use regex::Regex;
use std::collections::{HashMap, HashSet};
use crate::types::{AegisSeverity, AegisViolation, SqlAstConditionParams, ToolCall};

pub struct SqlChecker {
    default_sql_tools: HashSet<String>,
    search_tool_names: HashSet<String>,
    looks_like_sql_regex: Regex,
    explicit_sql_fields: HashSet<String>,
    homoglyphs: HashMap<char, char>,
}

impl SqlChecker {
    pub fn new() -> Self {
        let default_sql_tools = [
            "database_exec", "execute_sql", "exec_sql", "run_sql", "run_query",
            "sql_query", "query_database", "query_db", "db_query", "mysql_query",
            "postgres_query", "sqlite_query", "tsql_query", "database_query",
            "query_sql", "sql", "sql_exec", "execute_query", "exec_query",
            "db_exec", "sqlite_exec", "query", "database_command", "execute_raw_sql"
        ].iter().map(|s| s.to_string()).collect();

        let search_tool_names = [
            "search_kb", "kb_search", "web_search", "google_search", "docs_search",
            "doc_search", "search_docs", "wiki_search", "semantic_search", "search_wiki",
            "search_documentation", "search_articles", "help_search", "faq_search"
        ].iter().map(|s| s.to_string()).collect();

        let explicit_sql_fields = [
            "sql", "sql_query", "sqlquery", "sql_statement", "sqltext",
            "sql_text", "stmt", "sql_stmt", "database_query", "query_sql",
            "raw_sql", "db_query", "sql_cmd", "sql_script"
        ].iter().map(|s| s.to_string()).collect();

        let mut homoglyphs = HashMap::new();
        homoglyphs.insert('\u{0430}', 'a'); homoglyphs.insert('\u{0410}', 'A');
        homoglyphs.insert('\u{0432}', 'b'); homoglyphs.insert('\u{0412}', 'B');
        homoglyphs.insert('\u{0441}', 'c'); homoglyphs.insert('\u{0421}', 'C');
        homoglyphs.insert('\u{0435}', 'e'); homoglyphs.insert('\u{0415}', 'E');
        homoglyphs.insert('\u{0456}', 'i'); homoglyphs.insert('\u{0406}', 'I');
        homoglyphs.insert('\u{0458}', 'j'); homoglyphs.insert('\u{0408}', 'J');
        homoglyphs.insert('\u{043A}', 'k'); homoglyphs.insert('\u{041A}', 'K');
        homoglyphs.insert('\u{041C}', 'M'); homoglyphs.insert('\u{041D}', 'H');
        homoglyphs.insert('\u{043E}', 'o'); homoglyphs.insert('\u{041E}', 'O');
        homoglyphs.insert('\u{0440}', 'p'); homoglyphs.insert('\u{0420}', 'P');
        homoglyphs.insert('\u{0455}', 's'); homoglyphs.insert('\u{0405}', 'S');
        homoglyphs.insert('\u{0422}', 'T'); homoglyphs.insert('\u{0443}', 'y');
        homoglyphs.insert('\u{0445}', 'x'); homoglyphs.insert('\u{0425}', 'X');
        homoglyphs.insert('\u{0391}', 'A'); homoglyphs.insert('\u{03B1}', 'a');
        homoglyphs.insert('\u{0392}', 'B'); homoglyphs.insert('\u{0395}', 'E');
        homoglyphs.insert('\u{03B5}', 'e'); homoglyphs.insert('\u{039F}', 'O');
        homoglyphs.insert('\u{03BF}', 'o'); homoglyphs.insert('\u{03A1}', 'P');
        homoglyphs.insert('\u{03C1}', 'p'); homoglyphs.insert('\u{03A4}', 'T');
        homoglyphs.insert('\u{03A7}', 'X'); homoglyphs.insert('\u{03C7}', 'x');

        Self {
            default_sql_tools,
            search_tool_names,
            looks_like_sql_regex: Regex::new(r"(?i)^\s*(?:--[^\n]*\n|/\*[\s\S]*?\*/|\s*)*(?:SELECT|INSERT|UPDATE|DELETE|DROP|TRUNCATE|ALTER|CREATE|EXEC|EXECUTE|GRANT|REVOKE|WITH|MERGE|CALL|REPLACE|BEGIN|COMMIT|ROLLBACK)\b").unwrap(),
            explicit_sql_fields,
            homoglyphs,
        }
    }

    pub fn normalize_unicode(&self, sql: &str) -> String {
        let mut result = String::with_capacity(sql.len());
        for ch in sql.chars() {
            let u = ch as u32;
            if (0x200B..=0x200D).contains(&u) || u == 0x2060 || u == 0x2061 || u == 0x2062 || u == 0x2063 ||
               u == 0x2064 || u == 0x200E || u == 0x200F || (0x202A..=0x202E).contains(&u) || u == 0xFEFF || u == 0x00AD {
                continue;
            }
            if (0xFF01..=0xFF5E).contains(&u) {
                if let Some(ascii_ch) = char::from_u32(u - 0xFEE0) {
                    result.push(ascii_ch);
                    continue;
                }
            }
            if let Some(&mapped) = self.homoglyphs.get(&ch) {
                result.push(mapped);
                continue;
            }
            result.push(ch);
        }
        result
    }

    pub fn strip_sql_comments(&self, sql: &str) -> String {
        let mut result = String::with_capacity(sql.len());
        let chars: Vec<char> = sql.chars().collect();
        let len = chars.len();
        let mut in_single_quote = false;
        let mut in_double_quote = false;
        let mut in_backtick = false;

        let mut i = 0;
        while i < len {
            let ch = chars[i];
            let next_ch = if i + 1 < len { chars[i + 1] } else { '\0' };

            if ch == '\'' && !in_double_quote && !in_backtick {
                if in_single_quote && next_ch == '\'' {
                    result.push_str("''");
                    i += 2;
                    continue;
                }
                in_single_quote = !in_single_quote;
                result.push(ch);
                i += 1;
                continue;
            }

            if ch == '"' && !in_single_quote && !in_backtick {
                in_double_quote = !in_double_quote;
                result.push(ch);
                i += 1;
                continue;
            }

            if ch == '`' && !in_single_quote && !in_double_quote {
                in_backtick = !in_backtick;
                result.push(ch);
                i += 1;
                continue;
            }

            if in_single_quote || in_double_quote || in_backtick {
                result.push(ch);
                i += 1;
                continue;
            }

            // Block comment /* ... */
            if ch == '/' && next_ch == '*' {
                i += 2;
                while i + 1 < len && !(chars[i] == '*' && chars[i + 1] == '/') {
                    i += 1;
                }
                i += 2;
                result.push(' ');
                continue;
            }

            // Line comment -- ...
            if ch == '-' && next_ch == '-' {
                i += 2;
                while i < len && chars[i] != '\n' && chars[i] != '\r' {
                    i += 1;
                }
                result.push(' ');
                continue;
            }

            result.push(ch);
            i += 1;
        }

        let space_re = Regex::new(r"\s+").unwrap();
        let cleaned = space_re.replace_all(&result, " ").trim().to_string();

        // De-obfuscate split keywords
        let re_del = Regex::new(r"(?i)\bD\s*E\s*L\s*E\s*T\s*E\b").unwrap();
        let re_drop = Regex::new(r"(?i)\bD\s*R\s*O\s*P\b").unwrap();
        let re_trunc = Regex::new(r"(?i)\bT\s*R\s*U\s*N\s*C\s*A\s*T\s*E\b").unwrap();
        let re_upd = Regex::new(r"(?i)\bU\s*P\s*D\s*A\s*T\s*E\b").unwrap();
        let re_alt = Regex::new(r"(?i)\bA\s*L\s*T\s*E\s*R\b").unwrap();
        let re_ins = Regex::new(r"(?i)\bI\s*N\s*S\s*E\s*R\s*T\b").unwrap();
        let re_sel = Regex::new(r"(?i)\bS\s*E\s*L\s*E\s*C\s*T\b").unwrap();

        let s1 = re_del.replace_all(&cleaned, "DELETE");
        let s2 = re_drop.replace_all(&s1, "DROP");
        let s3 = re_trunc.replace_all(&s2, "TRUNCATE");
        let s4 = re_upd.replace_all(&s3, "UPDATE");
        let s5 = re_alt.replace_all(&s4, "ALTER");
        let s6 = re_ins.replace_all(&s5, "INSERT");
        re_sel.replace_all(&s6, "SELECT").to_string()
    }

    pub fn extract_sql_string(&self, call: &ToolCall, database_field: Option<&str>) -> Option<String> {
        if let Some(db_field) = database_field {
            if let Some(val) = call.arguments.get(db_field).and_then(|v| v.as_str()) {
                if !val.trim().is_empty() {
                    return Some(val.to_string());
                }
            }
        }

        self.find_sql_in_params(&call.arguments, &call.name, 0)
    }

    fn find_sql_in_params(&self, params: &HashMap<String, serde_json::Value>, tool: &str, depth: usize) -> Option<String> {
        if depth > 6 {
            return None;
        }

        let lower_tool = tool.to_lowercase();
        let is_db_tool = self.default_sql_tools.contains(&lower_tool) || lower_tool.contains("sql") || lower_tool.contains("db");
        let is_search = self.search_tool_names.contains(&lower_tool);

        let priority_fields = [
            "sql", "stmt", "sql_query", "sql_statement", "raw_sql", "sql_stmt", "query_sql", "db_query",
            "query", "statement", "command", "cmd", "body", "text", "script", "expression", "code", "q"
        ];

        for &field in &priority_fields {
            if let Some(serde_json::Value::String(val)) = params.get(field) {
                if !val.trim().is_empty() {
                    if self.explicit_sql_fields.contains(&field.to_lowercase()) {
                        return Some(val.clone());
                    }
                    if is_search && (field == "query" || field == "q") {
                        continue;
                    }
                    if self.looks_like_sql_regex.is_match(val) || (is_db_tool && !val.trim().is_empty()) {
                        return Some(val.clone());
                    }
                }
            }
        }

        // Search recursively
        for (k, v) in params {
            match v {
                serde_json::Value::String(val) => {
                    if is_search && (k == "query" || k == "q") {
                        continue;
                    }
                    if self.explicit_sql_fields.contains(&k.to_lowercase()) || self.looks_like_sql_regex.is_match(val) {
                        return Some(val.clone());
                    }
                }
                serde_json::Value::Object(map) => {
                    let map_conv: HashMap<String, serde_json::Value> = map.clone().into_iter().collect();
                    if let Some(found) = self.find_sql_in_params(&map_conv, tool, depth + 1) {
                        return Some(found);
                    }
                }
                serde_json::Value::Array(arr) => {
                    for item in arr {
                        if let serde_json::Value::String(str_item) = item {
                            if self.looks_like_sql_regex.is_match(str_item) {
                                return Some(str_item.clone());
                            }
                        } else if let serde_json::Value::Object(sub_map) = item {
                            let map_conv: HashMap<String, serde_json::Value> = sub_map.clone().into_iter().collect();
                            if let Some(found) = self.find_sql_in_params(&map_conv, tool, depth + 1) {
                                return Some(found);
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        None
    }

    pub fn unescape_payload(&self, sql: &str) -> String {
        let mut processed = sql.to_string();

        // Hex decoding: \xXX or %XX
        let hex_re = Regex::new(r"(?i)(?:\\x|%)([0-9a-f]{2})").unwrap();
        processed = hex_re.replace_all(&processed, |caps: &regex::Captures| {
            if let Ok(byte_val) = u8::from_str_radix(&caps[1], 16) {
                (byte_val as char).to_string()
            } else {
                caps[0].to_string()
            }
        }).to_string();

        // String concatenation unrolling: 'DEL' || 'ETE'
        let concat_re = Regex::new(r"'([^']*)'\s*\|\|\s*'([^']*)'").unwrap();
        while concat_re.is_match(&processed) {
            processed = concat_re.replace_all(&processed, "'$1$2'").to_string();
        }

        let concat_func_re = Regex::new(r"(?i)CONCAT\(\s*'([^']*)'\s*,\s*'([^']*)'\s*\)").unwrap();
        while concat_func_re.is_match(&processed) {
            processed = concat_func_re.replace_all(&processed, "'$1$2'").to_string();
        }

        // Unquote fully concatenated SQL keywords
        let kw_re = Regex::new(r"(?i)'(DROP|DELETE|UPDATE|TRUNCATE|ALTER|TABLE|DATABASE|SCHEMA|VIEW|GRANT|REVOKE)'").unwrap();
        processed = kw_re.replace_all(&processed, "$1").to_string();

        processed
    }

    pub fn evaluate(
        &self,
        rule_id: &str,
        pack_id: &str,
        params: &SqlAstConditionParams,
        call: &ToolCall,
        severity: AegisSeverity,
    ) -> Vec<AegisViolation> {
        let mut violations = Vec::new();
        let raw_sql = match self.extract_sql_string(call, params.database_field.as_deref()) {
            Some(s) if !s.trim().is_empty() => s,
            _ => return violations,
        };

        let normalized = self.normalize_unicode(&raw_sql);
        let cleaned = self.strip_sql_comments(&normalized);
        let unescaped = self.unescape_payload(&cleaned);

        let upper_sql = unescaped.to_uppercase();
        let tokens = self.tokenize_sql(&upper_sql);

        if tokens.is_empty() {
            return violations;
        }

        // 1. Prohibited Statement Types
        for blocked in &params.block_statements {
            let blocked_upper = blocked.to_uppercase();
            if tokens.contains(&blocked_upper) {
                violations.push(AegisViolation {
                    rule_id: rule_id.to_string(),
                    pack_id: pack_id.to_string(),
                    severity: severity.clone(),
                    message: format!("Statement type '{}' is prohibited by security policy.", blocked_upper),
                    suggested_fix: Some(format!("Avoid using '{}'. Use read-only queries or specific targeted updates instead.", blocked_upper)),
                    context: None,
                });
                return violations;
            }
        }

        // 2. Destructive DDL Detection (DROP, TRUNCATE, ALTER TABLE ... DROP, GRANT, REVOKE)
        for (i, token) in tokens.iter().enumerate() {
            if token == "DROP" && i + 1 < tokens.len() {
                let target = &tokens[i + 1];
                let ddl_targets = [
                    "TABLE", "DATABASE", "SCHEMA", "VIEW", "INDEX",
                    "PROCEDURE", "FUNCTION", "TRIGGER", "USER", "ROLE",
                    "EXTENSION", "MATERIALIZED"
                ];
                if ddl_targets.contains(&target.as_str()) {
                    violations.push(AegisViolation {
                        rule_id: rule_id.to_string(),
                        pack_id: pack_id.to_string(),
                        severity: severity.clone(),
                        message: format!("Destructive schema modification 'DROP {}' detected.", target),
                        suggested_fix: Some("Destructive schema alterations and DROP commands are prohibited in production agent workflows.".to_string()),
                        context: None,
                    });
                }
            }
        }

        if tokens.contains(&"TRUNCATE".to_string()) {
            violations.push(AegisViolation {
                rule_id: rule_id.to_string(),
                pack_id: pack_id.to_string(),
                severity: severity.clone(),
                message: "Destructive TRUNCATE statement detected.".to_string(),
                suggested_fix: Some("TRUNCATE is prohibited in production agent workflows.".to_string()),
                context: None,
            });
        }

        for (i, token) in tokens.iter().enumerate() {
            if token == "ALTER" && i + 1 < tokens.len() && tokens[i + 1] == "TABLE" {
                if tokens[i + 2..].contains(&"DROP".to_string()) {
                    violations.push(AegisViolation {
                        rule_id: rule_id.to_string(),
                        pack_id: pack_id.to_string(),
                        severity: severity.clone(),
                        message: "Destructive schema modification 'ALTER TABLE ... DROP' detected.".to_string(),
                        suggested_fix: Some("Destructive schema alterations are prohibited in production agent workflows.".to_string()),
                        context: None,
                    });
                    break;
                }
            }
        }

        for token in &tokens {
            if token == "GRANT" || token == "REVOKE" {
                violations.push(AegisViolation {
                    rule_id: rule_id.to_string(),
                    pack_id: pack_id.to_string(),
                    severity: severity.clone(),
                    message: "Privilege modification statement (GRANT/REVOKE) detected.".to_string(),
                    suggested_fix: Some("Database privilege modification commands are prohibited in production agent workflows.".to_string()),
                    context: None,
                });
                break;
            }
        }

        // CTE Mutations: WITH ... AS (DELETE/DROP/UPDATE/TRUNCATE)
        if tokens.contains(&"WITH".to_string()) {
            for mut_token in &["DELETE", "DROP", "TRUNCATE", "ALTER"] {
                if tokens.contains(&mut_token.to_string()) {
                    violations.push(AegisViolation {
                        rule_id: rule_id.to_string(),
                        pack_id: pack_id.to_string(),
                        severity: severity.clone(),
                        message: format!("Destructive mutation '{}' inside Common Table Expression (CTE) detected.", mut_token),
                        suggested_fix: Some("Destructive CTE mutations are prohibited in production agent workflows.".to_string()),
                        context: None,
                    });
                    break;
                }
            }
        }

        // 3. Prohibit DELETE without WHERE or with tautological WHERE
        if tokens.contains(&"DELETE".to_string()) {
            if params.require.as_deref() == Some("WHERE_CLAUSE") || params.require.is_none() {
                if let Some(where_idx) = tokens.iter().position(|t| t == "WHERE") {
                    let where_clause = tokens[where_idx + 1..].join(" ");
                    if self.is_tautology(&where_clause) {
                        violations.push(AegisViolation {
                            rule_id: rule_id.to_string(),
                            pack_id: pack_id.to_string(),
                            severity: severity.clone(),
                            message: "Mass DELETE statement detected with tautological WHERE clause (e.g. 1=1).".to_string(),
                            suggested_fix: Some("Specify target rows with authentic predicate conditions rather than tautologies.".to_string()),
                            context: None,
                        });
                    }
                } else {
                    violations.push(AegisViolation {
                        rule_id: rule_id.to_string(),
                        pack_id: pack_id.to_string(),
                        severity: severity.clone(),
                        message: "Mass DELETE statement detected without WHERE clause.".to_string(),
                        suggested_fix: Some("Specify target rows with specific predicate conditions (e.g. 'WHERE id = :id').".to_string()),
                        context: None,
                    });
                }
            }
        }

        // 4. Prohibit UPDATE without WHERE or with tautological WHERE
        if tokens.contains(&"UPDATE".to_string()) {
            if params.require.as_deref() == Some("WHERE_CLAUSE") || params.require.is_none() {
                if let Some(where_idx) = tokens.iter().position(|t| t == "WHERE") {
                    let where_clause = tokens[where_idx + 1..].join(" ");
                    if self.is_tautology(&where_clause) {
                        violations.push(AegisViolation {
                            rule_id: rule_id.to_string(),
                            pack_id: pack_id.to_string(),
                            severity: severity.clone(),
                            message: "Mass UPDATE statement detected with tautological WHERE clause (e.g. 1=1).".to_string(),
                            suggested_fix: Some("Specify target rows with authentic predicate conditions rather than tautologies.".to_string()),
                            context: None,
                        });
                    }
                } else {
                    violations.push(AegisViolation {
                        rule_id: rule_id.to_string(),
                        pack_id: pack_id.to_string(),
                        severity: severity.clone(),
                        message: "Mass UPDATE statement detected without WHERE clause.".to_string(),
                        suggested_fix: Some("Specify target rows with specific predicate conditions (e.g. 'WHERE id = :id').".to_string()),
                        context: None,
                    });
                }
            }
        }

        // 5. Enforce LIMIT ceiling
        if let Some(max_limit) = params.max_limit {
            if let Some(limit_idx) = tokens.iter().position(|t| t == "LIMIT") {
                if limit_idx + 1 < tokens.len() {
                    if let Ok(limit_val) = tokens[limit_idx + 1].parse::<i64>() {
                        if limit_val > max_limit {
                            violations.push(AegisViolation {
                                rule_id: rule_id.to_string(),
                                pack_id: pack_id.to_string(),
                                severity: severity.clone(),
                                message: format!("LIMIT {} exceeds maximum permitted ceiling of {}.", limit_val, max_limit),
                                suggested_fix: Some(format!("Reduce LIMIT clause to {} or less.", max_limit)),
                                context: None,
                            });
                        }
                    }
                }
            }
        }

        violations
    }

    fn tokenize_sql(&self, sql: &str) -> Vec<String> {
        let cleaned: String = sql.chars().map(|c| {
            if c == '(' || c == ')' || c == ';' || c == ',' {
                ' '
            } else {
                c
            }
        }).collect();

        cleaned.split_whitespace().map(|s| s.to_string()).collect()
    }

    pub fn is_tautology(&self, where_clause: &str) -> bool {
        let where_trim = where_clause.trim().to_uppercase();
        if where_trim.is_empty() {
            return true;
        }

        // Literal tautologies
        let literal_tautologies = [
            "1", "TRUE", "1=1", "1 = 1", "2=2", "2 = 2", "0=0", "0 = 0",
            "100=100", "100 = 100", "2>1", "2 > 1", "10>5", "10 > 5", "'A'='A'", "'A' = 'A'"
        ];
        for lit in &literal_tautologies {
            if where_trim == *lit || where_trim.starts_with(&format!("{} ", lit)) {
                return true;
            }
        }

        // Direct equality / identity checking: N=N, 'X'='X', id=id, users.id=users.id
        if let Some((left, right)) = where_trim.split_once('=') {
            let l_clean = left.trim().trim_matches('\'').trim_matches('"');
            let r_clean = right.trim().trim_matches('\'').trim_matches('"').trim_end_matches(';').trim();
            if !l_clean.is_empty() && l_clean == r_clean {
                return true;
            }
        }

        // Numeric compare N>M
        let num_comp_re = Regex::new(r"^(\d+)\s*>\s*(\d+)(?:\s|;|$)").unwrap();
        if let Some(caps) = num_comp_re.captures(&where_trim) {
            if let (Ok(n1), Ok(n2)) = (caps[1].parse::<i64>(), caps[2].parse::<i64>()) {
                if n1 > n2 {
                    return true;
                }
            }
        }

        // Unconditional IS NOT NULL
        let is_not_null_re = Regex::new(r"\bIS\s+NOT\s+NULL\b").unwrap();
        if is_not_null_re.is_match(&where_trim) {
            return true;
        }

        // Domain lower bounds: id > 0, id >= 0, id != -1, id <> -1, 0 < id, -1 != id
        let domain_re1 = Regex::new(r"\b[a-zA-Z_]\w*\s*>\s*0\b").unwrap();
        let domain_re2 = Regex::new(r"\b[a-zA-Z_]\w*\s*>=\s*0\b").unwrap();
        let domain_re3 = Regex::new(r"\b[a-zA-Z_]\w*\s*(?:<>|!=)\s*-\d+\b").unwrap();
        let domain_re4 = Regex::new(r"\b0\s*<\s*[a-zA-Z_]\w*\b").unwrap();
        let domain_re5 = Regex::new(r"\b-\d+\s*(?:<>|!=)\s*[a-zA-Z_]\w*\b").unwrap();

        if domain_re1.is_match(&where_trim) || domain_re2.is_match(&where_trim) ||
           domain_re3.is_match(&where_trim) || domain_re4.is_match(&where_trim) ||
           domain_re5.is_match(&where_trim) {
            return true;
        }

        // OR compound tautology: id = 123 OR 1=1, id = 'abc' OR TRUE
        let or_re = Regex::new(r"\bOR\s+(?:1\s*=\s*1|2\s*>\s*1|TRUE|1|\d+\s*=\s*\d+|'[^']+'\s*=\s*'[^']+')").unwrap();
        if or_re.is_match(&where_trim) {
            return true;
        }

        // Unconstrained subquery: WHERE id IN (SELECT id FROM users)
        if where_trim.contains("IN SELECT") {
            let select_part = &where_trim[where_trim.find("IN SELECT").unwrap() + 9..];
            if !select_part.contains("WHERE") {
                return true;
            }
        }
        if where_trim.contains("IN (SELECT") {
            let select_part = &where_trim[where_trim.find("IN (SELECT").unwrap()..];
            if !select_part.contains("WHERE") {
                return true;
            }
        }

        false
    }
}
