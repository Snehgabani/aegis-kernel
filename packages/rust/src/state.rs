use crate::types::{AegisSeverity, AegisViolation, StateInvariantConditionParams, ToolCall};
use std::collections::HashMap;

pub struct StateChecker {}

impl Default for StateChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl StateChecker {
    pub fn new() -> Self {
        Self {}
    }

    pub fn evaluate(
        &self,
        rule_id: &str,
        pack_id: &str,
        params: &StateInvariantConditionParams,
        call: &ToolCall,
        state_context: Option<&HashMap<String, serde_json::Value>>,
        severity: AegisSeverity,
    ) -> Vec<AegisViolation> {
        let mut violations = Vec::new();

        // 1. Target field filtering
        if let Some(target_field) = &params.target_field {
            if !call.arguments.contains_key(target_field)
                && self
                    .find_nested_val(&call.arguments, target_field)
                    .is_none()
            {
                return violations;
            }
        }

        // 2. Tenant isolation
        if let Some(tenant_field) = &params.tenant_field {
            let tool_tenant = call
                .arguments
                .get(tenant_field)
                .or_else(|| self.find_nested_val(&call.arguments, tenant_field));
            if let Some(state) = state_context {
                let state_tenant = state.get(tenant_field);
                if let (Some(t_val), Some(s_val)) = (tool_tenant, state_tenant) {
                    if t_val != s_val {
                        violations.push(AegisViolation {
                            rule_id: rule_id.to_string(),
                            pack_id: pack_id.to_string(),
                            severity,
                            message: format!("Cross-tenant isolation violation: Tool requested tenant '{}' does not match authenticated session tenant '{}'.", t_val, s_val),
                            suggested_fix: Some(format!("Restrict tool call parameters to the caller's active tenant '{}'.", s_val)),
                            context: None,
                        });
                        return violations;
                    }
                }
            }
        }

        // 3. State required check
        let state = match state_context {
            Some(s) => s,
            None => {
                if params.require_state {
                    violations.push(AegisViolation {
                        rule_id: rule_id.to_string(),
                        pack_id: pack_id.to_string(),
                        severity,
                        message: format!("State invariant rule '{}' requires system state context, but no state was provided.", rule_id),
                        suggested_fix: Some("Pass current state context object to Aegis evaluate() to clear state invariant assertions.".to_string()),
                        context: None,
                    });
                }
                return violations;
            }
        };

        // Build evaluation context
        let mut ctx: HashMap<String, serde_json::Value> = HashMap::new();
        for (k, v) in &call.arguments {
            ctx.insert(k.clone(), v.clone());
        }
        for (k, v) in state {
            ctx.insert(k.clone(), v.clone());
        }
        ctx.insert(
            "params".to_string(),
            serde_json::to_value(&call.arguments).unwrap_or(serde_json::Value::Null),
        );
        ctx.insert(
            "state".to_string(),
            serde_json::to_value(state).unwrap_or(serde_json::Value::Null),
        );

        // 4. Precondition check
        if let Some(precond) = &params.precondition {
            if !self.eval_expression(precond, &ctx) {
                violations.push(AegisViolation {
                    rule_id: rule_id.to_string(),
                    pack_id: pack_id.to_string(),
                    severity: severity.clone(),
                    message: format!("State precondition failed: '{}' was not satisfied by current system state.", precond),
                    suggested_fix: Some(format!("Ensure system state satisfies precondition '{}' before invoking '{}'.", precond, call.name)),
                    context: None,
                });
            }
        }

        // 5. Assertion check
        if !self.eval_expression(&params.assertion, &ctx) {
            violations.push(AegisViolation {
                rule_id: rule_id.to_string(),
                pack_id: pack_id.to_string(),
                severity,
                message: format!(
                    "System state invariant violated: '{}' would be breached by this action.",
                    params.assertion
                ),
                suggested_fix: Some(format!(
                    "Action exceeds permitted state boundary. Invariant constraint: '{}'.",
                    params.assertion
                )),
                context: None,
            });
        }

        violations
    }

    fn find_nested_val<'a>(
        &self,
        params: &'a HashMap<String, serde_json::Value>,
        key: &str,
    ) -> Option<&'a serde_json::Value> {
        let lower = key.to_lowercase();
        for (k, v) in params {
            if k.to_lowercase() == lower {
                return Some(v);
            }
        }
        None
    }

    fn eval_expression(&self, expr: &str, ctx: &HashMap<String, serde_json::Value>) -> bool {
        let expr = expr.trim();
        if expr.is_empty() {
            return true;
        }

        // Logical OR: ||
        if let Some((left, right)) = self.split_top_level(expr, "||") {
            return self.eval_expression(left, ctx) || self.eval_expression(right, ctx);
        }

        // Logical AND: &&
        if let Some((left, right)) = self.split_top_level(expr, "&&") {
            return self.eval_expression(left, ctx) && self.eval_expression(right, ctx);
        }

        // Comparison operators: <=, >=, ==, !=, <, >
        let ops = ["<=", ">=", "==", "!=", "<", ">"];
        for op in ops {
            if let Some((left, right)) = self.split_operator(expr, op) {
                let left_val = self.eval_arithmetic(left, ctx);
                let right_val = self.eval_arithmetic(right, ctx);
                return self.compare_values(&left_val, op, &right_val);
            }
        }

        // Boolean value
        let val = self.eval_value(expr, ctx);
        match val {
            serde_json::Value::Bool(b) => b,
            serde_json::Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
            serde_json::Value::String(s) => s == "true" || s == "1",
            _ => !val.is_null(),
        }
    }

    fn split_top_level<'a>(&self, expr: &'a str, op: &str) -> Option<(&'a str, &'a str)> {
        let mut depth = 0;
        let mut in_quote = false;
        let mut quote_char = '\0';
        let chars: Vec<char> = expr.chars().collect();
        let op_chars: Vec<char> = op.chars().collect();

        for i in 0..chars.len() {
            let c = chars[i];
            if (c == '\'' || c == '"') && depth == 0 {
                if in_quote && c == quote_char {
                    in_quote = false;
                } else if !in_quote {
                    in_quote = true;
                    quote_char = c;
                }
            } else if !in_quote {
                if c == '(' {
                    depth += 1;
                } else if c == ')' {
                    depth -= 1;
                } else if depth == 0 && i + op_chars.len() <= chars.len() {
                    let mut match_op = true;
                    for j in 0..op_chars.len() {
                        if chars[i + j] != op_chars[j] {
                            match_op = false;
                            break;
                        }
                    }
                    if match_op {
                        let left = &expr[..i];
                        let right = &expr[i + op.len()..];
                        return Some((left, right));
                    }
                }
            }
        }
        None
    }

    fn split_operator<'a>(&self, expr: &'a str, op: &str) -> Option<(&'a str, &'a str)> {
        let mut depth = 0;
        let mut in_quote = false;
        let mut quote_char = '\0';
        let chars: Vec<char> = expr.chars().collect();
        let op_chars: Vec<char> = op.chars().collect();

        for i in 0..chars.len() {
            let c = chars[i];
            if (c == '\'' || c == '"') && depth == 0 {
                if in_quote && c == quote_char {
                    in_quote = false;
                } else if !in_quote {
                    in_quote = true;
                    quote_char = c;
                }
            } else if !in_quote {
                if c == '(' {
                    depth += 1;
                } else if c == ')' {
                    depth -= 1;
                } else if depth == 0 && i + op_chars.len() <= chars.len() {
                    let mut match_op = true;
                    for j in 0..op_chars.len() {
                        if chars[i + j] != op_chars[j] {
                            match_op = false;
                            break;
                        }
                    }
                    if match_op {
                        // Prevent matching '<' inside '<='
                        if op == "<" && i + 1 < chars.len() && chars[i + 1] == '=' {
                            continue;
                        }
                        if op == ">" && i + 1 < chars.len() && chars[i + 1] == '=' {
                            continue;
                        }
                        let left = &expr[..i];
                        let right = &expr[i + op.len()..];
                        return Some((left, right));
                    }
                }
            }
        }
        None
    }

    fn eval_arithmetic(
        &self,
        expr: &str,
        ctx: &HashMap<String, serde_json::Value>,
    ) -> serde_json::Value {
        let expr = expr.trim();

        // Addition: +
        if let Some((left, right)) = self.split_top_level(expr, "+") {
            let l_num = self.to_f64(&self.eval_arithmetic(left, ctx));
            let r_num = self.to_f64(&self.eval_arithmetic(right, ctx));
            if let (Some(l), Some(r)) = (l_num, r_num) {
                if let Some(num) = serde_json::Number::from_f64(l + r) {
                    return serde_json::Value::Number(num);
                }
            }
        }

        // Subtraction: -
        if let Some((left, right)) = self.split_top_level(expr, "-") {
            let l_num = self.to_f64(&self.eval_arithmetic(left, ctx));
            let r_num = self.to_f64(&self.eval_arithmetic(right, ctx));
            if let (Some(l), Some(r)) = (l_num, r_num) {
                if let Some(num) = serde_json::Number::from_f64(l - r) {
                    return serde_json::Value::Number(num);
                }
            }
        }

        self.eval_value(expr, ctx)
    }

    fn eval_value(
        &self,
        token: &str,
        ctx: &HashMap<String, serde_json::Value>,
    ) -> serde_json::Value {
        let token = token.trim();

        // String literals '...' or "..."
        if (token.starts_with('\'') && token.ends_with('\''))
            || (token.starts_with('"') && token.ends_with('"'))
        {
            if token.len() >= 2 {
                return serde_json::Value::String(token[1..token.len() - 1].to_string());
            }
            return serde_json::Value::String(String::new());
        }

        if token.eq_ignore_ascii_case("true") {
            return serde_json::Value::Bool(true);
        }
        if token.eq_ignore_ascii_case("false") {
            return serde_json::Value::Bool(false);
        }

        if let Ok(n) = token.parse::<f64>() {
            if let Some(num) = serde_json::Number::from_f64(n) {
                return serde_json::Value::Number(num);
            }
        }

        // Property traversal e.g. state.spent_today, params.amount
        let parts: Vec<&str> = token.split('.').collect();
        if let Some(first) = parts.first() {
            if let Some(mut current) = ctx.get(*first) {
                for &part in &parts[1..] {
                    if let serde_json::Value::Object(map) = current {
                        if let Some(next_val) = map.get(part) {
                            current = next_val;
                        } else {
                            return serde_json::Value::Null;
                        }
                    } else {
                        return serde_json::Value::Null;
                    }
                }
                return current.clone();
            }
        }

        serde_json::Value::Null
    }

    fn to_f64(&self, val: &serde_json::Value) -> Option<f64> {
        match val {
            serde_json::Value::Number(n) => n.as_f64(),
            serde_json::Value::String(s) => s.parse::<f64>().ok(),
            _ => None,
        }
    }

    fn compare_values(
        &self,
        left: &serde_json::Value,
        op: &str,
        right: &serde_json::Value,
    ) -> bool {
        if let (Some(l), Some(r)) = (self.to_f64(left), self.to_f64(right)) {
            return match op {
                "<=" => l <= r,
                ">=" => l >= r,
                "<" => l < r,
                ">" => l > r,
                "==" => (l - r).abs() < f64::EPSILON,
                "!=" => (l - r).abs() >= f64::EPSILON,
                _ => false,
            };
        }

        let l_str = match left {
            serde_json::Value::String(s) => s.clone(),
            _ => left.to_string(),
        };
        let r_str = match right {
            serde_json::Value::String(s) => s.clone(),
            _ => right.to_string(),
        };

        match op {
            "==" => l_str.eq_ignore_ascii_case(&r_str),
            "!=" => !l_str.eq_ignore_ascii_case(&r_str),
            _ => false,
        }
    }
}
