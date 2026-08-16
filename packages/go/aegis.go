package aegis

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

type ToolCall struct {
	Name      string
	Arguments map[string]interface{}
}

type AegisVerdict struct {
	Allowed    bool
	Violations []string
	LatencyMs  int64
}

type AegisEngine struct {
	config Config
}

type Config struct {
	EnableSQLValidation bool
	EnablePIIScanning   bool
	NumericLimits       map[string]NumericLimit
}

type NumericLimit struct {
	Min float64
	Max float64
}

var piiRegex = regexp.MustCompile(`(?i)(ssn|social security|credit card|cc)[\s\-:]*\d{4}|\b\d{3}-\d{2}-\d{4}\b`)

func NewEngine(cfg Config) *AegisEngine {
	return &AegisEngine{config: cfg}
}

func (e *AegisEngine) Evaluate(call ToolCall) AegisVerdict {
	start := time.Now()
	verdict := AegisVerdict{Allowed: true}

	if e.config.EnableSQLValidation {
		if query, ok := call.Arguments["query"].(string); ok {
			upperQuery := strings.ToUpper(query)
			if strings.Contains(upperQuery, "DROP ") || strings.Contains(upperQuery, "TRUNCATE ") {
				verdict.Violations = append(verdict.Violations, "destructive SQL operation not allowed")
				verdict.Allowed = false
			}
			if strings.Contains(upperQuery, "DELETE FROM ") && !strings.Contains(upperQuery, " WHERE ") {
				verdict.Violations = append(verdict.Violations, "DELETE without WHERE clause not allowed")
				verdict.Allowed = false
			}
		}
	}

	if e.config.EnablePIIScanning {
		for _, v := range call.Arguments {
			if strVal, ok := v.(string); ok {
				if piiRegex.MatchString(strVal) {
					verdict.Violations = append(verdict.Violations, "PII detected")
					verdict.Allowed = false
				}
			}
		}
	}

	for argName, limit := range e.config.NumericLimits {
		if val, ok := call.Arguments[argName]; ok {
			var num float64
			switch v := val.(type) {
			case int:
				num = float64(v)
			case float64:
				num = v
			}
			if num < limit.Min || num > limit.Max {
				verdict.Violations = append(verdict.Violations, fmt.Sprintf("argument %s out of bounds", argName))
				verdict.Allowed = false
			}
		}
	}

	verdict.LatencyMs = time.Since(start).Milliseconds()
	return verdict
}

type AgentFunc func(call ToolCall) (interface{}, error)

func (e *AegisEngine) Guard(fn AgentFunc) AgentFunc {
	return func(call ToolCall) (interface{}, error) {
		verdict := e.Evaluate(call)
		if !verdict.Allowed {
			return nil, fmt.Errorf("aegis violation: %s", strings.Join(verdict.Violations, ", "))
		}
		return fn(call)
	}
}
