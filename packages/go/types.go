package aegis

import (
	"encoding/json"
)

// AegisMode defines the enforcement mode
type AegisMode string

const (
	ModeEnforce AegisMode = "enforce"
	ModeShadow  AegisMode = "shadow"
)

// AegisSeverity defines the violation severity
type AegisSeverity string

const (
	SeverityCritical AegisSeverity = "critical"
	SeverityWarning  AegisSeverity = "warning"
	SeverityInfo     AegisSeverity = "info"
)

// AegisFailPolicy defines how the engine behaves on evaluation errors
type AegisFailPolicy string

const (
	FailClosed AegisFailPolicy = "fail-closed"
	FailOpen   AegisFailPolicy = "fail-open"
)

// ToolCall represents a tool invocation to be validated
type ToolCall struct {
	Tool      string                 `json:"tool"`
	Name      string                 `json:"name,omitempty"` // Alias for Tool
	Params    map[string]interface{} `json:"params"`
	Arguments map[string]interface{} `json:"arguments,omitempty"` // Alias for Params
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// GetToolName returns the canonical tool name
func (tc ToolCall) GetToolName() string {
	if tc.Tool != "" {
		return tc.Tool
	}
	return tc.Name
}

// GetParams returns the canonical tool parameters map
func (tc ToolCall) GetParams() map[string]interface{} {
	if tc.Params != nil {
		return tc.Params
	}
	if tc.Arguments != nil {
		return tc.Arguments
	}
	return make(map[string]interface{})
}

// AegisViolation details a specific invariant breach
type AegisViolation struct {
	RuleID       string                 `json:"ruleId"`
	PackID       string                 `json:"packId"`
	Severity     AegisSeverity          `json:"severity"`
	Message      string                 `json:"message"`
	SuggestedFix string                 `json:"suggestedFix,omitempty"`
	Context      map[string]interface{} `json:"context,omitempty"`
}

// AegisVerdict is the outcome of policy evaluation
type AegisVerdict struct {
	Allowed      bool             `json:"allowed"`
	Violations   []AegisViolation `json:"violations"`
	ProofHash    string           `json:"proofHash"`
	LatencyMs    int64            `json:"latencyMs"`
	LatencyUs    int64            `json:"latencyUs"`
	Mode         AegisMode        `json:"mode"`
	SuggestedFix string           `json:"suggestedFix,omitempty"`
	Warning      string           `json:"warning,omitempty"`
}

// ViolationMessages returns all violation messages as a string slice for backward compatibility
func (v AegisVerdict) ViolationMessages() []string {
	res := make([]string, len(v.Violations))
	for i, viol := range v.Violations {
		res[i] = viol.Message
	}
	return res
}

// Legacy Config for backward compatibility
type Config struct {
	EnableSQLValidation bool
	EnablePIIScanning   bool
	NumericLimits       map[string]NumericLimit
	Mode                AegisMode
	FailPolicy          AegisFailPolicy
	RulePacks           []RulePack
}

// NumericLimit specifies boundary constraints on a parameter
type NumericLimit struct {
	Min *float64 `json:"min,omitempty"`
	Max *float64 `json:"max,omitempty"`
}

// RuleCondition specifies the invariant rule configuration
type RuleCondition struct {
	Type   string                 `json:"type" yaml:"type"` // "sql_ast", "numeric", "regex", "state_invariant", "custom"
	Params map[string]interface{} `json:"params" yaml:"params"`
}

// Rule represents a discrete invariant check
type Rule struct {
	ID           string        `json:"id" yaml:"id"`
	Severity     AegisSeverity `json:"severity" yaml:"severity"`
	Description  string        `json:"description" yaml:"description"`
	SuggestedFix string        `json:"suggestedFix,omitempty" yaml:"suggestedFix,omitempty"`
	Condition    RuleCondition `json:"condition" yaml:"condition"`
}

// RulePack groups related invariant rules
type RulePack struct {
	ID          string `json:"id" yaml:"id"`
	Name        string `json:"name" yaml:"name"`
	Version     string `json:"version" yaml:"version"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	Rules       []Rule `json:"rules" yaml:"rules"`
}

// SqlAstConditionParams defines params for SQL AST checks
type SqlAstConditionParams struct {
	Statements      []string `json:"statements,omitempty" yaml:"statements,omitempty"`
	BlockStatements []string `json:"block_statements,omitempty" yaml:"block_statements,omitempty"`
	Require         string   `json:"require,omitempty" yaml:"require,omitempty"` // e.g. "WHERE_CLAUSE"
	MaxLimit        *int64   `json:"max_limit,omitempty" yaml:"max_limit,omitempty"`
	DatabaseField   string   `json:"database_field,omitempty" yaml:"database_field,omitempty"`
}

// NumericConditionParams defines params for numeric boundary checks
type NumericConditionParams struct {
	Field     string      `json:"field" yaml:"field"`
	Min       *float64    `json:"min,omitempty" yaml:"min,omitempty"`
	Max       *float64    `json:"max,omitempty" yaml:"max,omitempty"`
	RateLimit *RateLimit  `json:"rate_limit,omitempty" yaml:"rate_limit,omitempty"`
}

// RateLimit defines sliding-window execution frequency limits
type RateLimit struct {
	MaxPerMinute int `json:"max_per_minute" yaml:"max_per_minute"`
}

// RegexConditionParams defines params for regex and PII scans
type RegexConditionParams struct {
	Patterns    []string `json:"patterns" yaml:"patterns"`
	MatchAction string   `json:"match_action,omitempty" yaml:"match_action,omitempty"` // "block" or "warn"
}

// StateInvariantConditionParams defines params for state invariant checks
type StateInvariantConditionParams struct {
	TargetField  string `json:"target_field,omitempty" yaml:"target_field,omitempty"`
	TenantField  string `json:"tenant_field,omitempty" yaml:"tenant_field,omitempty"`
	RequireState bool   `json:"require_state,omitempty" yaml:"require_state,omitempty"`
	Precondition string `json:"precondition,omitempty" yaml:"precondition,omitempty"`
	Assertion    string `json:"assertion" yaml:"assertion"`
}

// EvaluateOptions provides runtime evaluation configuration
type EvaluateOptions struct {
	State        map[string]interface{}
	Mode         *AegisMode
	FailPolicy   *AegisFailPolicy
	CallerID     string
	OnViolation  func(verdict AegisVerdict, toolCall ToolCall)
}

// EvaluateOption is a functional option for Evaluate
type EvaluateOption func(*EvaluateOptions)

// WithState provides system state context to Evaluate
func WithState(state map[string]interface{}) EvaluateOption {
	return func(o *EvaluateOptions) {
		o.State = state
	}
}

// WithMode sets evaluation mode (enforce/shadow)
func WithMode(mode AegisMode) EvaluateOption {
	return func(o *EvaluateOptions) {
		o.Mode = &mode
	}
}

// WithFailPolicy sets fail policy (fail-closed/fail-open)
func WithFailPolicy(policy AegisFailPolicy) EvaluateOption {
	return func(o *EvaluateOptions) {
		o.FailPolicy = &policy
	}
}

// AegisEvent defines structured telemetry log event
type AegisEvent struct {
	ID                   string           `json:"id"`
	Timestamp            string           `json:"timestamp"`
	Version              string           `json:"version"`
	ToolName             string           `json:"toolName"`
	ToolCallFingerprint  string           `json:"toolCallFingerprint"`
	Mode                 AegisMode        `json:"mode"`
	Verdict              string           `json:"verdict"` // "ALLOWED" | "BLOCKED"
	RulesEvaluated       int              `json:"rulesEvaluated"`
	RulesFired           []AegisViolation `json:"rulesFired"`
	LatencyMs            int64            `json:"latencyMs"`
	ProofHash            string           `json:"proofHash"`
	PolicyCommitmentHash string           `json:"policyCommitmentHash"`
	UserOverride         bool             `json:"userOverride"`
}

// AgentFunc represents a tool execution function wrapped by Guard
type AgentFunc func(call ToolCall) (interface{}, error)

// MarshalJSON helper for ToolCall to ensure clean JSON serialization
func (tc ToolCall) MarshalJSON() ([]byte, error) {
	type Alias ToolCall
	t := tc.GetToolName()
	p := tc.GetParams()
	return json.Marshal(&struct {
		Tool   string                 `json:"tool"`
		Params map[string]interface{} `json:"params"`
		Alias
	}{
		Tool:   t,
		Params: p,
		Alias:  (Alias)(tc),
	})
}
