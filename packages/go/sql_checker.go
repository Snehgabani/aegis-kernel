package aegis

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Homoglyph map for Cyrillic and Greek lookalikes to Latin characters
var homoglyphDecodeMap = map[rune]rune{
	'\u0430': 'a', '\u0410': 'A',
	'\u0432': 'b', '\u0412': 'B',
	'\u0441': 'c', '\u0421': 'C',
	'\u0435': 'e', '\u0415': 'E',
	'\u0456': 'i', '\u0406': 'I',
	'\u0458': 'j', '\u0408': 'J',
	'\u043A': 'k', '\u041A': 'K',
	'\u041C': 'M',
	'\u041D': 'H',
	'\u043E': 'o', '\u041E': 'O',
	'\u0440': 'p', '\u0420': 'P',
	'\u0455': 's', '\u0405': 'S',
	'\u0422': 'T',
	'\u0443': 'y',
	'\u0445': 'x', '\u0425': 'X',
	'\u0391': 'A', '\u03B1': 'a',
	'\u0392': 'B',
	'\u0395': 'E', '\u03B5': 'e',
	'\u039F': 'O', '\u03BF': 'o',
	'\u03A1': 'P', '\u03C1': 'p',
	'\u03A4': 'T',
	'\u03A7': 'X', '\u03C7': 'x',
}

var defaultSqlTools = map[string]bool{
	"database_exec": true, "execute_sql": true, "exec_sql": true, "run_sql": true, "run_query": true,
	"sql_query": true, "query_database": true, "query_db": true, "db_query": true, "mysql_query": true,
	"postgres_query": true, "sqlite_query": true, "tsql_query": true, "database_query": true,
	"query_sql": true, "sql": true, "sql_exec": true, "execute_query": true, "exec_query": true,
	"db_exec": true, "sqlite_exec": true, "query": true, "database_command": true, "execute_raw_sql": true,
}

var searchToolNames = map[string]bool{
	"search_kb": true, "kb_search": true, "web_search": true, "google_search": true, "docs_search": true,
	"doc_search": true, "search_docs": true, "wiki_search": true, "semantic_search": true, "search_wiki": true,
	"search_documentation": true, "search_articles": true, "help_search": true, "faq_search": true,
}

var looksLikeSqlRegex = regexp.MustCompile(`(?i)^\s*(?:--[^\n]*\n|\/\*[\s\S]*?\*\/|\s*)*(?:SELECT|INSERT|UPDATE|DELETE|DROP|TRUNCATE|ALTER|CREATE|EXEC|EXECUTE|GRANT|REVOKE|WITH|MERGE|CALL|REPLACE|BEGIN|COMMIT|ROLLBACK)\b`)

var explicitSqlFields = map[string]bool{
	"sql": true, "sql_query": true, "sqlquery": true, "sql_statement": true, "sqltext": true,
	"sql_text": true, "stmt": true, "sql_stmt": true, "database_query": true, "query_sql": true,
	"raw_sql": true, "db_query": true, "sql_cmd": true, "sql_script": true,
}

var commonSqlParamNames = []string{
	"sql", "stmt", "sql_query", "sql_statement", "raw_sql", "sql_stmt", "query_sql", "db_query",
	"query", "statement", "command", "cmd", "body", "text", "script", "expression", "code", "q",
}

// SqlChecker performs token-level and invariant analysis on SQL queries
type SqlChecker struct{}

// NewSqlChecker creates a new SQL checker
func NewSqlChecker() *SqlChecker {
	return &SqlChecker{}
}

// NormalizeUnicode removes zero-width characters and replaces homoglyphs
func (sc *SqlChecker) NormalizeUnicode(sql string) string {
	var sb strings.Builder
	for _, r := range sql {
		// Zero-width characters, bidi overrides, soft hyphen
		if (r >= 0x200B && r <= 0x200D) || r == 0x2060 || r == 0x2061 || r == 0x2062 || r == 0x2063 ||
			r == 0x2064 || r == 0x200E || r == 0x200F || (r >= 0x202A && r <= 0x202E) || r == 0xFEFF || r == 0x00AD {
			continue
		}
		// Fullwidth ASCII conversion (0xFF01 - 0xFF5E -> 0x21 - 0x7E)
		if r >= 0xFF01 && r <= 0xFF5E {
			sb.WriteRune(r - 0xFEE0)
			continue
		}
		// Homoglyphs
		if mapped, ok := homoglyphDecodeMap[r]; ok {
			sb.WriteRune(mapped)
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

// StripSqlComments strips line and block comments while respecting string literals
func (sc *SqlChecker) StripSqlComments(sql string) string {
	var result strings.Builder
	runes := []rune(sql)
	n := len(runes)
	inSingleQuote := false
	inDoubleQuote := false
	inBacktick := false

	i := 0
	for i < n {
		char := runes[i]
		var nextChar rune
		if i+1 < n {
			nextChar = runes[i+1]
		}

		// Single quote handling
		if char == '\'' && !inDoubleQuote && !inBacktick {
			if inSingleQuote && nextChar == '\'' {
				result.WriteString("''")
				i += 2
				continue
			}
			inSingleQuote = !inSingleQuote
			result.WriteRune(char)
			i++
			continue
		}

		// Double quote handling
		if char == '"' && !inSingleQuote && !inBacktick {
			inDoubleQuote = !inDoubleQuote
			result.WriteRune(char)
			i++
			continue
		}

		// Backtick handling
		if char == '`' && !inSingleQuote && !inDoubleQuote {
			inBacktick = !inBacktick
			result.WriteRune(char)
			i++
			continue
		}

		// Inside string literals: preserve all characters
		if inSingleQuote || inDoubleQuote || inBacktick {
			result.WriteRune(char)
			i++
			continue
		}

		// Block comment /* ... */
		if char == '/' && nextChar == '*' {
			i += 2
			for i+1 < n && !(runes[i] == '*' && runes[i+1] == '/') {
				i++
			}
			i += 2 // Skip */
			result.WriteRune(' ')
			continue
		}

		// Line comment -- ...
		if char == '-' && nextChar == '-' {
			i += 2
			for i < n && runes[i] != '\n' && runes[i] != '\r' {
				i++
			}
			result.WriteRune(' ')
			continue
		}

		result.WriteRune(char)
		i++
	}

	cleaned := regexp.MustCompile(`\s+`).ReplaceAllString(result.String(), " ")
	cleaned = strings.TrimSpace(cleaned)

	// Reconstruct comment-split keywords (e.g. DEL/**/ETE -> DELETE, D R O P -> DROP)
	cleaned = regexp.MustCompile(`(?i)\bD\s*E\s*L\s*E\s*T\s*E\b`).ReplaceAllString(cleaned, "DELETE")
	cleaned = regexp.MustCompile(`(?i)\bD\s*R\s*O\s*P\b`).ReplaceAllString(cleaned, "DROP")
	cleaned = regexp.MustCompile(`(?i)\bT\s*R\s*U\s*N\s*C\s*A\s*T\s*E\b`).ReplaceAllString(cleaned, "TRUNCATE")
	cleaned = regexp.MustCompile(`(?i)\bU\s*P\s*D\s*A\s*T\s*E\b`).ReplaceAllString(cleaned, "UPDATE")
	cleaned = regexp.MustCompile(`(?i)\bA\s*L\s*T\s*E\s*R\b`).ReplaceAllString(cleaned, "ALTER")
	cleaned = regexp.MustCompile(`(?i)\bI\s*N\s*S\s*E\s*R\s*T\b`).ReplaceAllString(cleaned, "INSERT")
	cleaned = regexp.MustCompile(`(?i)\bS\s*E\s*L\s*E\s*C\s*T\b`).ReplaceAllString(cleaned, "SELECT")

	return cleaned
}

// ExtractSqlString extracts SQL from tool call parameters
func (sc *SqlChecker) ExtractSqlString(call ToolCall, databaseField string) string {
	params := call.GetParams()
	tool := call.GetToolName()

	if databaseField != "" {
		if val, ok := params[databaseField].(string); ok && strings.TrimSpace(val) != "" {
			return val
		}
	}

	return sc.findSqlInParams(params, tool, 0)
}

func (sc *SqlChecker) findSqlInParams(params map[string]interface{}, tool string, depth int) string {
	if depth > 6 || params == nil {
		return ""
	}

	isDbTool := defaultSqlTools[strings.ToLower(tool)] || strings.Contains(strings.ToLower(tool), "sql") || strings.Contains(strings.ToLower(tool), "db")
	isSearch := searchToolNames[strings.ToLower(tool)]

	// Check common high priority fields first
	for _, field := range commonSqlParamNames {
		if val, ok := params[field]; ok {
			if strVal, ok := val.(string); ok && strings.TrimSpace(strVal) != "" {
				if explicitSqlFields[strings.ToLower(field)] {
					return strVal
				}
				if isSearch && (field == "query" || field == "q") {
					continue
				}
				if looksLikeSqlRegex.MatchString(strVal) || (isDbTool && len(strings.TrimSpace(strVal)) > 0) {
					return strVal
				}
			}
		}
	}

	// Recursive search across all fields
	for k, v := range params {
		if strVal, ok := v.(string); ok && strings.TrimSpace(strVal) != "" {
			if isSearch && (k == "query" || k == "q") {
				continue
			}
			if explicitSqlFields[strings.ToLower(k)] || looksLikeSqlRegex.MatchString(strVal) {
				return strVal
			}
		} else if mapVal, ok := v.(map[string]interface{}); ok {
			found := sc.findSqlInParams(mapVal, tool, depth+1)
			if found != "" {
				return found
			}
		} else if sliceVal, ok := v.([]interface{}); ok {
			for _, item := range sliceVal {
				if strItem, ok := item.(string); ok && looksLikeSqlRegex.MatchString(strItem) {
					return strItem
				} else if mapItem, ok := item.(map[string]interface{}); ok {
					found := sc.findSqlInParams(mapItem, tool, depth+1)
					if found != "" {
						return found
					}
				}
			}
		}
	}

	return ""
}

// UnescapePayload handles hex, URL encoding, and Base64 payloads inside SQL strings
func (sc *SqlChecker) UnescapePayload(sql string) string {
	processed := sql

	// Hex decoding: 0xXX and \xXX
	hexRegex := regexp.MustCompile(`(?i)\\x([0-9a-f]{2})|%([0-9a-f]{2})`)
	processed = hexRegex.ReplaceAllStringFunc(processed, func(m string) string {
		var hexStr string
		if strings.HasPrefix(m, "\\x") || strings.HasPrefix(m, "\\X") {
			hexStr = m[2:]
		} else if strings.HasPrefix(m, "%") {
			hexStr = m[1:]
		}
		if b, err := strconv.ParseUint(hexStr, 16, 8); err == nil {
			return string([]byte{byte(b)})
		}
		return m
	})

	// Base64 payload detection
	b64Regex := regexp.MustCompile(`\b[A-Za-z0-9+/]{12,}={0,2}\b`)
	processed = b64Regex.ReplaceAllStringFunc(processed, func(m string) string {
		if data, err := base64.StdEncoding.DecodeString(m); err == nil {
			decoded := string(data)
			if regexp.MustCompile(`(?i)\b(DELETE|DROP|TRUNCATE|UPDATE|ALTER|SELECT|INSERT|GRANT|REVOKE)\b`).MatchString(decoded) {
				return decoded
			}
		}
		return m
	})

	// String concatenation unrolling: 'DEL' || 'ETE' -> 'DELETE'
	concatRegex := regexp.MustCompile(`'([^']*)'\s*\|\|\s*'([^']*)'`)
	for concatRegex.MatchString(processed) {
		processed = concatRegex.ReplaceAllString(processed, "'$1$2'")
	}
	concatFuncRegex := regexp.MustCompile(`(?i)CONCAT\(\s*'([^']*)'\s*,\s*'([^']*)'\s*\)`)
	for concatFuncRegex.MatchString(processed) {
		processed = concatFuncRegex.ReplaceAllString(processed, "'$1$2'")
	}

	// Unquote keywords that were fully concatenated
	kwRegex := regexp.MustCompile(`(?i)'(DROP|DELETE|UPDATE|TRUNCATE|ALTER|TABLE|DATABASE|SCHEMA|VIEW|GRANT|REVOKE)'`)
	processed = kwRegex.ReplaceAllString(processed, "$1")

	return processed
}

// Evaluate evaluates a tool call for SQL safety invariants
func (sc *SqlChecker) Evaluate(
	ruleID string,
	packID string,
	params SqlAstConditionParams,
	call ToolCall,
	severity AegisSeverity,
) []AegisViolation {
	var violations []AegisViolation

	rawSql := sc.ExtractSqlString(call, params.DatabaseField)
	if strings.TrimSpace(rawSql) == "" {
		return violations
	}

	normalized := sc.NormalizeUnicode(rawSql)
	cleaned := sc.StripSqlComments(normalized)
	unescaped := sc.UnescapePayload(cleaned)

	if severity == "" {
		severity = SeverityCritical
	}

	// Tokenize normalized SQL
	upperSql := strings.ToUpper(unescaped)
	tokens := sc.tokenizeSql(upperSql)

	if len(tokens) == 0 {
		return violations
	}

	// 1. Prohibited Statement Types (DROP, TRUNCATE, ALTER, GRANT, REVOKE)
	if len(params.BlockStatements) > 0 {
		for _, blocked := range params.BlockStatements {
			blockedUpper := strings.ToUpper(blocked)
			if sc.hasStatementType(tokens, blockedUpper) {
				violations = append(violations, AegisViolation{
					RuleID:       ruleID,
					PackID:       packID,
					Severity:     severity,
					Message:      fmt.Sprintf("Statement type '%s' is prohibited by security policy.", blockedUpper),
					SuggestedFix: fmt.Sprintf("Avoid using '%s'. Use read-only queries or specific targeted updates instead.", blockedUpper),
					Context: map[string]interface{}{
						"statementType": blockedUpper,
						"sql":           truncateString(rawSql, 120),
					},
				})
				return violations
			}
		}
	}

	// 2. Destructive DDL (DROP, TRUNCATE, ALTER TABLE ... DROP, GRANT, REVOKE)
	// Check for DROP
	for i, token := range tokens {
		if token == "DROP" && i+1 < len(tokens) {
			target := tokens[i+1]
			ddlTargets := map[string]bool{
				"TABLE": true, "DATABASE": true, "SCHEMA": true, "VIEW": true, "INDEX": true,
				"PROCEDURE": true, "FUNCTION": true, "TRIGGER": true, "USER": true, "ROLE": true,
				"EXTENSION": true, "MATERIALIZED": true,
			}
			if ddlTargets[target] {
				violations = append(violations, AegisViolation{
					RuleID:       ruleID,
					PackID:       packID,
					Severity:     severity,
					Message:      fmt.Sprintf("Destructive schema modification 'DROP %s' detected.", target),
					SuggestedFix: "Destructive schema alterations and DROP commands are prohibited in production agent workflows.",
					Context: map[string]interface{}{
						"statementType": "DROP",
						"target":        target,
						"sql":           truncateString(rawSql, 120),
					},
				})
			}
		}
	}

	// Check for TRUNCATE
	for _, token := range tokens {
		if token == "TRUNCATE" {
			violations = append(violations, AegisViolation{
				RuleID:       ruleID,
				PackID:       packID,
				Severity:     severity,
				Message:      "Destructive TRUNCATE statement detected.",
				SuggestedFix: "TRUNCATE is prohibited in production agent workflows.",
				Context: map[string]interface{}{
					"statementType": "TRUNCATE",
					"sql":           truncateString(rawSql, 120),
				},
			})
			break
		}
	}

	// Check for ALTER TABLE ... DROP
	for i, token := range tokens {
		if token == "ALTER" && i+1 < len(tokens) && tokens[i+1] == "TABLE" {
			remaining := tokens[i+2:]
			for _, rem := range remaining {
				if rem == "DROP" {
					violations = append(violations, AegisViolation{
						RuleID:       ruleID,
						PackID:       packID,
						Severity:     severity,
						Message:      "Destructive schema modification 'ALTER TABLE ... DROP' detected.",
						SuggestedFix: "Destructive schema alterations are prohibited in production agent workflows.",
						Context: map[string]interface{}{
							"statementType": "ALTER_DROP",
							"sql":           truncateString(rawSql, 120),
						},
					})
					break
				}
			}
		}
	}

	// Check for GRANT / REVOKE
	for _, token := range tokens {
		if token == "GRANT" || token == "REVOKE" {
			violations = append(violations, AegisViolation{
				RuleID:       ruleID,
				PackID:       packID,
				Severity:     severity,
				Message:      "Privilege modification statement (GRANT/REVOKE) detected.",
				SuggestedFix: "Database privilege modification commands are prohibited in production agent workflows.",
				Context: map[string]interface{}{
					"statementType": token,
					"sql":           truncateString(rawSql, 120),
				},
			})
			break
		}
	}

	// Check for CTE Mutations: WITH ... AS (DELETE/DROP/UPDATE/TRUNCATE)
	if tokens[0] == "WITH" || containsToken(tokens, "WITH") {
		for _, mutToken := range []string{"DELETE", "DROP", "TRUNCATE", "ALTER"} {
			if containsToken(tokens, mutToken) {
				violations = append(violations, AegisViolation{
					RuleID:       ruleID,
					PackID:       packID,
					Severity:     severity,
					Message:      fmt.Sprintf("Destructive mutation '%s' inside Common Table Expression (CTE) detected.", mutToken),
					SuggestedFix: "Destructive CTE mutations are prohibited in production agent workflows.",
					Context: map[string]interface{}{
						"statementType": "CTE_MUTATION",
						"sql":           truncateString(rawSql, 120),
					},
				})
				break
			}
		}
	}

	// 3. Prohibit DELETE without WHERE clause OR with tautological WHERE clause
	if containsToken(tokens, "DELETE") {
		if params.Require == "WHERE_CLAUSE" || params.Require == "" {
			whereIdx := indexOfToken(tokens, "WHERE")
			if whereIdx == -1 {
				violations = append(violations, AegisViolation{
					RuleID:       ruleID,
					PackID:       packID,
					Severity:     severity,
					Message:      "Mass DELETE statement detected without WHERE clause.",
					SuggestedFix: "Specify target rows with specific predicate conditions (e.g. 'WHERE id = :id').",
					Context: map[string]interface{}{
						"statementType": "DELETE",
						"missingWhere":  true,
					},
				})
			} else {
				whereClause := strings.Join(tokens[whereIdx+1:], " ")
				if sc.isTautology(whereClause) {
					violations = append(violations, AegisViolation{
						RuleID:       ruleID,
						PackID:       packID,
						Severity:     severity,
						Message:      "Mass DELETE statement detected with tautological WHERE clause (e.g. 1=1).",
						SuggestedFix: "Specify target rows with authentic predicate conditions rather than tautologies.",
						Context: map[string]interface{}{
							"statementType": "DELETE",
							"tautology":     true,
							"whereClause":   whereClause,
						},
					})
				}
			}
		}
	}

	// 4. Prohibit UPDATE without WHERE clause OR with tautological WHERE clause
	if containsToken(tokens, "UPDATE") {
		if params.Require == "WHERE_CLAUSE" || params.Require == "" {
			whereIdx := indexOfToken(tokens, "WHERE")
			if whereIdx == -1 {
				violations = append(violations, AegisViolation{
					RuleID:       ruleID,
					PackID:       packID,
					Severity:     severity,
					Message:      "Mass UPDATE statement detected without WHERE clause.",
					SuggestedFix: "Specify target rows with specific predicate conditions (e.g. 'WHERE id = :id').",
					Context: map[string]interface{}{
						"statementType": "UPDATE",
						"missingWhere":  true,
					},
				})
			} else {
				whereClause := strings.Join(tokens[whereIdx+1:], " ")
				if sc.isTautology(whereClause) {
					violations = append(violations, AegisViolation{
						RuleID:       ruleID,
						PackID:       packID,
						Severity:     severity,
						Message:      "Mass UPDATE statement detected with tautological WHERE clause (e.g. 1=1).",
						SuggestedFix: "Specify target rows with authentic predicate conditions rather than tautologies.",
						Context: map[string]interface{}{
							"statementType": "UPDATE",
							"tautology":     true,
							"whereClause":   whereClause,
						},
					})
				}
			}
		}
	}

	// 5. Enforce LIMIT ceilings on queries
	if params.MaxLimit != nil {
		limitIdx := indexOfToken(tokens, "LIMIT")
		if limitIdx != -1 && limitIdx+1 < len(tokens) {
			if limitVal, err := strconv.ParseInt(tokens[limitIdx+1], 10, 64); err == nil {
				if limitVal > *params.MaxLimit {
					violations = append(violations, AegisViolation{
						RuleID:       ruleID,
						PackID:       packID,
						Severity:     severity,
						Message:      fmt.Sprintf("LIMIT %d exceeds maximum permitted ceiling of %d.", limitVal, *params.MaxLimit),
						SuggestedFix: fmt.Sprintf("Reduce LIMIT clause to %d or less.", *params.MaxLimit),
						Context: map[string]interface{}{
							"requestedLimit": limitVal,
							"maxLimit":       *params.MaxLimit,
						},
					})
				}
			}
		}
	}

	return violations
}

func (sc *SqlChecker) tokenizeSql(sql string) []string {
	// Replace delimiters with spaces so tokens inside parens like (DELETE ...) are cleanly isolated
	cleaner := strings.Map(func(r rune) rune {
		if r == '(' || r == ')' || r == ';' || r == ',' {
			return ' '
		}
		return r
	}, sql)
	return strings.Fields(cleaner)
}

func (sc *SqlChecker) hasStatementType(tokens []string, stmtType string) bool {
	if len(tokens) == 0 {
		return false
	}
	if tokens[0] == stmtType {
		return true
	}
	for _, t := range tokens {
		if t == stmtType {
			return true
		}
	}
	return false
}

// isTautology checks for common SQL tautology patterns in WHERE clause
func (sc *SqlChecker) isTautology(whereClause string) bool {
	where := strings.TrimSpace(strings.ToUpper(whereClause))
	if where == "" {
		return true
	}

	// 1. Literal constant tautologies: WHERE 1, WHERE 1=1, WHERE 2=2, WHERE 0=0, WHERE 100=100, WHERE 2>1, WHERE TRUE
	literalTautologies := []string{
		"1", "TRUE", "1=1", "1 = 1", "2=2", "2 = 2", "0=0", "0 = 0",
		"100=100", "100 = 100", "2>1", "2 > 1", "10>5", "10 > 5", "'A'='A'", "'A' = 'A'",
	}
	for _, lit := range literalTautologies {
		if where == lit || strings.HasPrefix(where, lit+" ") || strings.HasPrefix(where, lit+";") {
			return true
		}
	}

	// 2. Numeric identity: N=N or N>M where N>M is statically true
	numIdentityRegex := regexp.MustCompile(`^(\d+)\s*=\s*\1(?:\s|;|$)`)
	if numIdentityRegex.MatchString(where) {
		return true
	}
	numCompareRegex := regexp.MustCompile(`^(\d+)\s*>\s*(\d+)(?:\s|;|$)`)
	if matches := numCompareRegex.FindStringSubmatch(where); len(matches) == 3 {
		n1, _ := strconv.Atoi(matches[1])
		n2, _ := strconv.Atoi(matches[2])
		if n1 > n2 {
			return true
		}
	}

	// 3. String identity: 'X' = 'X'
	strIdentityRegex := regexp.MustCompile(`^'([^']+)'\s*=\s*'\1'(?:\s|;|$)`)
	if strIdentityRegex.MatchString(where) {
		return true
	}

	// 4. Self column comparison: id = id, users.id = users.id
	selfColRegex := regexp.MustCompile(`^([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)?)\s*=\s*\1(?:\s|;|$)`)
	if selfColRegex.MatchString(where) {
		return true
	}

	// 5. Unconditional null test: WHERE id IS NOT NULL
	if regexp.MustCompile(`\bIS\s+NOT\s+NULL\b`).MatchString(where) {
		return true
	}

	// 6. Domain lower-bound tautologies: id > 0, id >= 0, id != -1, id <> -1, 0 < id, -1 != id
	if regexp.MustCompile(`\b[a-zA-Z_]\w*\s*>\s*0\b`).MatchString(where) ||
		regexp.MustCompile(`\b[a-zA-Z_]\w*\s*>=\s*0\b`).MatchString(where) ||
		regexp.MustCompile(`\b[a-zA-Z_]\w*\s*(?:<>|!=)\s*-\d+\b`).MatchString(where) ||
		regexp.MustCompile(`\b0\s*<\s*[a-zA-Z_]\w*\b`).MatchString(where) ||
		regexp.MustCompile(`\b-\d+\s*(?:<>|!=)\s*[a-zA-Z_]\w*\b`).MatchString(where) {
		return true
	}

	// 7. OR compound tautology: WHERE id = 123 OR 1=1, WHERE id = 'abc' OR TRUE
	if regexp.MustCompile(`\bOR\s+(?:1\s*=\s*1|2\s*>\s*1|TRUE|1|\d+\s*=\s*\d+|'[^']+'\s*=\s*'[^']+')`).MatchString(where) {
		return true
	}

	// 8. Unconstrained subquery: WHERE id IN (SELECT id FROM users) without WHERE in subquery
	if strings.Contains(where, "IN SELECT") {
		idx := strings.Index(where, "IN SELECT")
		subqueryPart := where[idx+9:]
		if !strings.Contains(subqueryPart, "WHERE") {
			return true
		}
	}
	if strings.Contains(where, "IN (SELECT") {
		idx := strings.Index(where, "IN (SELECT")
		subqueryPart := where[idx:]
		if !strings.Contains(subqueryPart, "WHERE") {
			return true
		}
	}

	return false
}

func containsToken(tokens []string, target string) bool {
	for _, t := range tokens {
		if t == target {
			return true
		}
	}
	return false
}

func indexOfToken(tokens []string, target string) int {
	for i, t := range tokens {
		if t == target {
			return i
		}
	}
	return -1
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
