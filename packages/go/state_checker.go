package aegis

import (
	"fmt"
	"strconv"
	"strings"
)

// StateChecker evaluates state invariant rules and tenant isolation
type StateChecker struct{}

// NewStateChecker creates a new StateChecker
func NewStateChecker() *StateChecker {
	return &StateChecker{}
}

// Evaluate runs state invariants, preconditions, and tenant isolation checks
func (sc *StateChecker) Evaluate(
	ruleID string,
	packID string,
	params StateInvariantConditionParams,
	call ToolCall,
	stateContext map[string]interface{},
	severity AegisSeverity,
) []AegisViolation {
	var violations []AegisViolation
	toolParams := call.GetParams()

	if severity == "" {
		severity = SeverityCritical
	}

	// 1. Target field filter
	if params.TargetField != "" {
		_, exists := toolParams[params.TargetField]
		if !exists && sc.findNestedValue(toolParams, params.TargetField) == nil {
			return violations
		}
	}

	// 2. Tenant isolation check
	if params.TenantField != "" {
		toolTenant := toolParams[params.TenantField]
		if toolTenant == nil {
			toolTenant = sc.findNestedValue(toolParams, params.TenantField)
		}

		if stateContext != nil {
			stateTenant := stateContext[params.TenantField]
			if toolTenant != nil && stateTenant != nil {
				toolTenantStr := fmt.Sprintf("%v", toolTenant)
				stateTenantStr := fmt.Sprintf("%v", stateTenant)
				if toolTenantStr != stateTenantStr {
					violations = append(violations, AegisViolation{
						RuleID:       ruleID,
						PackID:       packID,
						Severity:     severity,
						Message:      fmt.Sprintf("Cross-tenant isolation violation: Tool requested tenant '%s' does not match authenticated session tenant '%s'.", toolTenantStr, stateTenantStr),
						SuggestedFix: fmt.Sprintf("Restrict tool call parameters to the caller's active tenant '%s'.", stateTenantStr),
						Context: map[string]interface{}{
							"toolTenant":  toolTenantStr,
							"stateTenant": stateTenantStr,
						},
					})
					return violations
				}
			}
		}
	}

	// 3. Require state check
	if stateContext == nil {
		if params.RequireState {
			violations = append(violations, AegisViolation{
				RuleID:       ruleID,
				PackID:       packID,
				Severity:     severity,
				Message:      fmt.Sprintf("State invariant rule '%s' requires system state context, but no state was provided.", ruleID),
				SuggestedFix: "Pass current state context object to Aegis Evaluate() to clear state invariant assertions.",
				Context: map[string]interface{}{
					"missingState": true,
				},
			})
		}
		return violations
	}

	evalCtx := make(map[string]interface{})
	for k, v := range toolParams {
		evalCtx[k] = v
	}
	for k, v := range stateContext {
		evalCtx[k] = v
	}
	evalCtx["params"] = toolParams
	evalCtx["state"] = stateContext

	// 4. Precondition check
	if params.Precondition != "" {
		passed := sc.evaluateExpression(params.Precondition, evalCtx)
		if !passed {
			violations = append(violations, AegisViolation{
				RuleID:       ruleID,
				PackID:       packID,
				Severity:     severity,
				Message:      fmt.Sprintf("State precondition failed: '%s' was not satisfied by current system state.", params.Precondition),
				SuggestedFix: fmt.Sprintf("Ensure system state satisfies precondition '%s' before invoking '%s'.", params.Precondition, call.GetToolName()),
				Context: map[string]interface{}{
					"precondition": params.Precondition,
					"state":        stateContext,
				},
			})
		}
	}

	// 5. Invariant assertion check
	if params.Assertion != "" {
		passed := sc.evaluateExpression(params.Assertion, evalCtx)
		if !passed {
			violations = append(violations, AegisViolation{
				RuleID:       ruleID,
				PackID:       packID,
				Severity:     severity,
				Message:      fmt.Sprintf("System state invariant violated: '%s' would be breached by this action.", params.Assertion),
				SuggestedFix: fmt.Sprintf("Action exceeds permitted state boundary. Invariant constraint: '%s'.", params.Assertion),
				Context: map[string]interface{}{
					"assertion": params.Assertion,
					"state":     stateContext,
					"params":    toolParams,
				},
			})
		}
	}

	return violations
}

func (sc *StateChecker) findNestedValue(obj map[string]interface{}, key string) interface{} {
	if obj == nil {
		return nil
	}
	if val, ok := obj[key]; ok {
		return val
	}
	for _, v := range obj {
		if subMap, ok := v.(map[string]interface{}); ok {
			if found := sc.findNestedValue(subMap, key); found != nil {
				return found
			}
		}
	}
	return nil
}

// evaluateExpression evaluates a logical/arithmetic DSL expression against the context
func (sc *StateChecker) evaluateExpression(expr string, ctx map[string]interface{}) bool {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return true
	}

	// Handle logical OR: ||
	if parts := splitTopLevel(expr, "||"); len(parts) > 1 {
		for _, part := range parts {
			if sc.evaluateExpression(part, ctx) {
				return true
			}
		}
		return false
	}

	// Handle logical AND: &&
	if parts := splitTopLevel(expr, "&&"); len(parts) > 1 {
		for _, part := range parts {
			if !sc.evaluateExpression(part, ctx) {
				return false
			}
		}
		return true
	}

	// Handle comparison operators: <=, >=, ==, !=, <, >
	operators := []string{"<=", ">=", "==", "!=", "<", ">"}
	for _, op := range operators {
		idx := findOperatorIndex(expr, op)
		if idx != -1 {
			leftStr := strings.TrimSpace(expr[:idx])
			rightStr := strings.TrimSpace(expr[idx+len(op):])

			leftVal := sc.evalArithmetic(leftStr, ctx)
			rightVal := sc.evalArithmetic(rightStr, ctx)

			return compareValues(leftVal, op, rightVal)
		}
	}

	// Single boolean expression or variable check
	val := sc.evalValue(expr, ctx)
	if b, ok := val.(bool); ok {
		return b
	}
	if str, ok := val.(string); ok {
		return str == "true" || str == "1"
	}
	if num, ok := toFloat(val); ok {
		return num != 0
	}
	return val != nil
}

func splitTopLevel(expr, op string) []string {
	var parts []string
	depth := 0
	inQuote := false
	var quoteChar rune
	start := 0
	runes := []rune(expr)
	opRunes := []rune(op)

	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if (r == '\'' || r == '"') && depth == 0 {
			if inQuote && r == quoteChar {
				inQuote = false
			} else if !inQuote {
				inQuote = true
				quoteChar = r
			}
		} else if !inQuote {
			if r == '(' {
				depth++
			} else if r == ')' {
				depth--
			} else if depth == 0 && i+len(opRunes) <= len(runes) {
				match := true
				for j := 0; j < len(opRunes); j++ {
					if runes[i+j] != opRunes[j] {
						match = false
						break
					}
				}
				if match {
					parts = append(parts, string(runes[start:i]))
					start = i + len(opRunes)
					i += len(opRunes) - 1
				}
			}
		}
	}
	if start < len(runes) {
		parts = append(parts, string(runes[start:]))
	}
	return parts
}

func findOperatorIndex(expr, op string) int {
	depth := 0
	inQuote := false
	var quoteChar rune
	runes := []rune(expr)
	opRunes := []rune(op)

	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if r == '\'' || r == '"' {
			if inQuote && r == quoteChar {
				inQuote = false
			} else if !inQuote {
				inQuote = true
				quoteChar = r
			}
		} else if !inQuote {
			if r == '(' {
				depth++
			} else if r == ')' {
				depth--
			} else if depth == 0 && i+len(opRunes) <= len(runes) {
				match := true
				for j := 0; j < len(opRunes); j++ {
					if runes[i+j] != opRunes[j] {
						match = false
						break
					}
				}
				if match {
					// Check it's not part of longer operator (e.g. < in <=)
					if op == "<" && i+1 < len(runes) && runes[i+1] == '=' {
						continue
					}
					if op == ">" && i+1 < len(runes) && runes[i+1] == '=' {
						continue
					}
					return i
				}
			}
		}
	}
	return -1
}

func (sc *StateChecker) evalArithmetic(expr string, ctx map[string]interface{}) interface{} {
	expr = strings.TrimSpace(expr)

	// Handle addition: +
	if parts := splitTopLevel(expr, "+"); len(parts) > 1 {
		var sum float64
		for _, part := range parts {
			val := sc.evalArithmetic(part, ctx)
			if f, ok := toFloat(val); ok {
				sum += f
			}
		}
		return sum
	}

	// Handle subtraction: -
	if parts := splitTopLevel(expr, "-"); len(parts) > 1 {
		var res float64
		for i, part := range parts {
			val := sc.evalArithmetic(part, ctx)
			if f, ok := toFloat(val); ok {
				if i == 0 {
					res = f
				} else {
					res -= f
				}
			}
		}
		return res
	}

	// Handle multiplication: *
	if parts := splitTopLevel(expr, "*"); len(parts) > 1 {
		var prod float64 = 1
		for _, part := range parts {
			val := sc.evalArithmetic(part, ctx)
			if f, ok := toFloat(val); ok {
				prod *= f
			}
		}
		return prod
	}

	// Handle division: /
	if parts := splitTopLevel(expr, "/"); len(parts) > 1 {
		var res float64
		for i, part := range parts {
			val := sc.evalArithmetic(part, ctx)
			if f, ok := toFloat(val); ok {
				if i == 0 {
					res = f
				} else if f != 0 {
					res /= f
				}
			}
		}
		return res
	}

	return sc.evalValue(expr, ctx)
}

func (sc *StateChecker) evalValue(token string, ctx map[string]interface{}) interface{} {
	token = strings.TrimSpace(token)

	// String literal
	if (strings.HasPrefix(token, "'") && strings.HasSuffix(token, "'")) ||
		(strings.HasPrefix(token, "\"") && strings.HasSuffix(token, "\"")) {
		if len(token) >= 2 {
			return token[1 : len(token)-1]
		}
		return ""
	}

	// Boolean literal
	if strings.EqualFold(token, "true") {
		return true
	}
	if strings.EqualFold(token, "false") {
		return false
	}

	// Number literal
	if f, err := strconv.ParseFloat(token, 64); err == nil {
		return f
	}

	// Property path traversal: e.g. state.spent_today, params.amount, daily_budget
	parts := strings.Split(token, ".")
	var current interface{} = ctx

	for _, part := range parts {
		if curMap, ok := current.(map[string]interface{}); ok {
			if val, exists := curMap[part]; exists {
				current = val
			} else {
				return nil
			}
		} else {
			return nil
		}
	}

	return current
}

func compareValues(left interface{}, op string, right interface{}) bool {
	// Numeric comparison
	leftNum, leftIsNum := toFloat(left)
	rightNum, rightIsNum := toFloat(right)

	if leftIsNum && rightIsNum {
		switch op {
		case "<=":
			return leftNum <= rightNum
		case ">=":
			return leftNum >= rightNum
		case "<":
			return leftNum < rightNum
		case ">":
			return leftNum > rightNum
		case "==":
			return leftNum == rightNum
		case "!=":
			return leftNum != rightNum
		}
	}

	// String / generic comparison
	leftStr := fmt.Sprintf("%v", left)
	rightStr := fmt.Sprintf("%v", right)

	switch op {
	case "==":
		return strings.EqualFold(leftStr, rightStr)
	case "!=":
		return !strings.EqualFold(leftStr, rightStr)
	default:
		return false
	}
}

func toFloat(val interface{}) (float64, bool) {
	if val == nil {
		return 0, false
	}
	switch v := val.(type) {
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case string:
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f, true
		}
	}
	return 0, false
}
