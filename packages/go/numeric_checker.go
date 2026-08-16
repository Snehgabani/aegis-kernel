package aegis

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var financialAliases = []string{
	"amount", "total", "value", "sum", "price", "cost", "payout", "payment",
	"transfer", "balance", "limit", "fee", "debit", "credit", "charge", "subtotal",
}

// NumericChecker performs boundary and rate limit checks on numeric parameters
type NumericChecker struct {
	mu               sync.Mutex
	rateLimitWindows map[string][]int64
}

// NewNumericChecker creates a new numeric checker
func NewNumericChecker() *NumericChecker {
	return &NumericChecker{
		rateLimitWindows: make(map[string][]int64),
	}
}

type extractionResult struct {
	status   string // "valid", "invalid", "absent"
	value    float64
	rawValue interface{}
}

// ParseNumericValue converts various types to float64, stripping currency formatting
func (nc *NumericChecker) ParseNumericValue(val interface{}) (float64, bool) {
	if val == nil {
		return 0, false
	}

	switch v := val.(type) {
	case int:
		return float64(v), true
	case int8:
		return float64(v), true
	case int16:
		return float64(v), true
	case int32:
		return float64(v), true
	case int64:
		return float64(v), true
	case uint:
		return float64(v), true
	case uint8:
		return float64(v), true
	case uint16:
		return float64(v), true
	case uint32:
		return float64(v), true
	case uint64:
		return float64(v), true
	case float32:
		f := float64(v)
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return 0, false
		}
		return f, true
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return 0, false
		}
		return v, true
	case json.Number:
		if f, err := v.Float64(); err == nil {
			return f, true
		}
		return 0, false
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed == "" || strings.EqualFold(trimmed, "nan") || strings.EqualFold(trimmed, "infinity") {
			return 0, false
		}

		// Strip currency symbols and ISO currency codes
		cleaned := trimmed
		cleaned = regexp.MustCompile(`[$€£¥₹]`).ReplaceAllString(cleaned, "")
		cleaned = regexp.MustCompile(`(?i)\b(USD|EUR|GBP|CAD|AUD|INR|JPY|CHF|CNY)\b`).ReplaceAllString(cleaned, "")
		cleaned = strings.ReplaceAll(cleaned, ",", "")
		cleaned = strings.TrimSpace(cleaned)

		if parsed, err := strconv.ParseFloat(cleaned, 64); err == nil {
			if !math.IsNaN(parsed) && !math.IsInf(parsed, 0) {
				return parsed, true
			}
		}
		return 0, false
	default:
		return 0, false
	}
}

func (nc *NumericChecker) extractNestedNumber(params map[string]interface{}, pathStr string) extractionResult {
	if params == nil {
		return extractionResult{status: "absent"}
	}

	cleanPath := strings.TrimPrefix(pathStr, "params.")
	parts := strings.Split(cleanPath, ".")
	var current interface{} = params
	directFound := true

	for _, part := range parts {
		if currentMap, ok := current.(map[string]interface{}); ok {
			if val, exists := currentMap[part]; exists {
				current = val
			} else {
				directFound = false
				break
			}
		} else {
			directFound = false
			break
		}
	}

	if directFound {
		if num, ok := nc.ParseNumericValue(current); ok {
			return extractionResult{status: "valid", value: num}
		}
		return extractionResult{status: "invalid", rawValue: current}
	}

	// Recursive search for target field name in nested objects
	targetField := parts[len(parts)-1]
	res := nc.findNestedNumber(params, targetField, make(map[string]bool))
	if res.status != "absent" {
		return res
	}

	// Semantic alias search for financial fields
	lowerTarget := strings.ToLower(targetField)
	isFinancial := false
	for _, alias := range financialAliases {
		if lowerTarget == alias {
			isFinancial = true
			break
		}
	}

	if isFinancial {
		for _, alias := range financialAliases {
			if alias == lowerTarget {
				continue
			}
			aliasRes := nc.findNestedNumber(params, alias, make(map[string]bool))
			if aliasRes.status != "absent" {
				return aliasRes
			}
		}
	}

	return extractionResult{status: "absent"}
}

func (nc *NumericChecker) findNestedNumber(obj interface{}, fieldName string, visited map[string]bool) extractionResult {
	if obj == nil {
		return extractionResult{status: "absent"}
	}

	record, ok := obj.(map[string]interface{})
	if !ok {
		return extractionResult{status: "absent"}
	}

	lowerTarget := strings.ToLower(fieldName)

	// Case-insensitive direct lookup
	for k, v := range record {
		if strings.ToLower(k) == lowerTarget {
			if num, ok := nc.ParseNumericValue(v); ok {
				return extractionResult{status: "valid", value: num}
			}
			return extractionResult{status: "invalid", rawValue: v}
		}
	}

	// Recurse into nested objects
	for _, v := range record {
		if subMap, ok := v.(map[string]interface{}); ok {
			res := nc.findNestedNumber(subMap, fieldName, visited)
			if res.status != "absent" {
				return res
			}
		}
	}

	return extractionResult{status: "absent"}
}

// Evaluate checks numeric bounds and sliding-window rate limits
func (nc *NumericChecker) Evaluate(
	ruleID string,
	packID string,
	params NumericConditionParams,
	call ToolCall,
	severity AegisSeverity,
) []AegisViolation {
	var violations []AegisViolation
	extraction := nc.extractNestedNumber(call.GetParams(), params.Field)

	if extraction.status == "absent" {
		return violations
	}

	if severity == "" {
		severity = SeverityCritical
	}

	if extraction.status == "invalid" {
		violations = append(violations, AegisViolation{
			RuleID:       ruleID,
			PackID:       packID,
			Severity:     severity,
			Message:      fmt.Sprintf("Numeric parameter '%s' contains invalid or unparseable non-numeric value: %v.", params.Field, extraction.rawValue),
			SuggestedFix: fmt.Sprintf("Ensure '%s' is a valid finite numeric value or formatted currency string.", params.Field),
			Context: map[string]interface{}{
				"field":    params.Field,
				"rawValue": extraction.rawValue,
			},
		})
		return violations
	}

	val := extraction.value

	// Automatic default min: 0 for financial aliases if min is omitted
	var effectiveMin *float64 = params.Min
	if effectiveMin == nil {
		lowerField := strings.ToLower(params.Field)
		for _, alias := range financialAliases {
			if strings.Contains(lowerField, alias) {
				zero := 0.0
				effectiveMin = &zero
				break
			}
		}
	}

	if effectiveMin != nil && val < *effectiveMin {
		violations = append(violations, AegisViolation{
			RuleID:       ruleID,
			PackID:       packID,
			Severity:     severity,
			Message:      fmt.Sprintf("Numeric parameter '%s' (%v) is below minimum allowed value of %v.", params.Field, val, *effectiveMin),
			SuggestedFix: fmt.Sprintf("Increase value of '%s' to at least %v.", params.Field, *effectiveMin),
			Context: map[string]interface{}{
				"field":   params.Field,
				"actual":  val,
				"minimum": *effectiveMin,
			},
		})
	}

	if params.Max != nil && val > *params.Max {
		violations = append(violations, AegisViolation{
			RuleID:       ruleID,
			PackID:       packID,
			Severity:     severity,
			Message:      fmt.Sprintf("Numeric parameter '%s' (%v) exceeds maximum allowed limit of %v.", params.Field, val, *params.Max),
			SuggestedFix: fmt.Sprintf("Reduce value of '%s' to %v or less.", params.Field, *params.Max),
			Context: map[string]interface{}{
				"field":   params.Field,
				"actual":  val,
				"maximum": *params.Max,
			},
		})
	}

	// Rate Limiting Check (Sliding 60-second window)
	if params.RateLimit != nil && params.RateLimit.MaxPerMinute > 0 {
		now := time.Now().UnixMilli()
		windowMs := int64(60 * 1000)
		key := fmt.Sprintf("%s:%s:%s", packID, ruleID, call.GetToolName())

		nc.mu.Lock()
		timestamps := nc.rateLimitWindows[key]
		var activeTimestamps []int64
		for _, t := range timestamps {
			if now-t < windowMs {
				activeTimestamps = append(activeTimestamps, t)
			}
		}
		activeTimestamps = append(activeTimestamps, now)
		nc.rateLimitWindows[key] = activeTimestamps
		count := len(activeTimestamps)
		nc.mu.Unlock()

		if count > params.RateLimit.MaxPerMinute {
			violations = append(violations, AegisViolation{
				RuleID:       ruleID,
				PackID:       packID,
				Severity:     severity,
				Message:      fmt.Sprintf("Rate limit ceiling reached: Tool '%s' invoked %d times in past minute (max: %d).", call.GetToolName(), count, params.RateLimit.MaxPerMinute),
				SuggestedFix: "Throttle tool invocation frequency or batch operations.",
				Context: map[string]interface{}{
					"currentCount": count,
					"maxPerMinute": params.RateLimit.MaxPerMinute,
				},
			})
		}
	}

	return violations
}
