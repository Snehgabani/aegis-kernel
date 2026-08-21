package aegis

import (
	"fmt"
	"strings"
	"time"
)

// AegisEngine is the core deterministic invariant enforcement engine
type AegisEngine struct {
	config           Config
	packs            []RulePack
	compiledRules    []compiledRule
	sqlChecker       *SqlChecker
	numericChecker   *NumericChecker
	piiChecker       *PiiChecker
	stateChecker     *StateChecker
	tokenVault       *PiiTokenVault
	merkleLogger     *MerkleLogger
	policyCommitment string
	mode             AegisMode
	failPolicy       AegisFailPolicy
}

// compiledRule is a rule whose condition params have been parsed into typed
// structs ONCE at engine construction. The historical implementation re-parsed
// the map[string]interface{} params (with per-rule slice reallocations) on
// EVERY Evaluate() call; pre-compilation moves that work out of the hot path.
type compiledRule struct {
	ruleID   string
	packID   string
	severity AegisSeverity
	kind     compiledRuleKind
}

type compiledRuleKind struct {
	ruleType string
	sql      *SqlAstConditionParams
	numeric  *NumericConditionParams
	regex    *RegexConditionParams
	state    *StateInvariantConditionParams
}

func compileRules(packs []RulePack) []compiledRule {
	var out []compiledRule
	for _, pack := range packs {
		for _, rule := range pack.Rules {
			cr := compiledRule{
				ruleID:   rule.ID,
				packID:   pack.ID,
				severity: rule.Severity,
				kind:     compiledRuleKind{ruleType: rule.Condition.Type},
			}
			switch rule.Condition.Type {
			case "sql_ast":
				var params SqlAstConditionParams
				if p, ok := rule.Condition.Params["require"].(string); ok {
					params.Require = p
				}
				if dbf, ok := rule.Condition.Params["database_field"].(string); ok {
					params.DatabaseField = dbf
				}
				if maxLimitVal, ok := rule.Condition.Params["max_limit"]; ok {
					if ml, ok := maxLimitVal.(int); ok {
						val := int64(ml)
						params.MaxLimit = &val
					} else if ml, ok := maxLimitVal.(int64); ok {
						params.MaxLimit = &ml
					} else if ml, ok := maxLimitVal.(float64); ok {
						val := int64(ml)
						params.MaxLimit = &val
					}
				}
				if stmts, ok := rule.Condition.Params["statements"].([]interface{}); ok {
					for _, s := range stmts {
						if str, ok := s.(string); ok {
							params.Statements = append(params.Statements, str)
						}
					}
				} else if stmts, ok := rule.Condition.Params["statements"].([]string); ok {
					params.Statements = stmts
				}
				if bstmts, ok := rule.Condition.Params["block_statements"].([]interface{}); ok {
					for _, s := range bstmts {
						if str, ok := s.(string); ok {
							params.BlockStatements = append(params.BlockStatements, str)
						}
					}
				} else if bstmts, ok := rule.Condition.Params["block_statements"].([]string); ok {
					params.BlockStatements = bstmts
				}
				cr.kind.sql = &params
			case "numeric":
				var params NumericConditionParams
				if f, ok := rule.Condition.Params["field"].(string); ok {
					params.Field = f
				}
				if minVal, ok := rule.Condition.Params["min"]; ok && minVal != nil {
					if f, ok := toFloat(minVal); ok {
						params.Min = &f
					}
				}
				if maxVal, ok := rule.Condition.Params["max"]; ok && maxVal != nil {
					if f, ok := toFloat(maxVal); ok {
						params.Max = &f
					}
				}
				if rlVal, ok := rule.Condition.Params["rate_limit"].(map[string]interface{}); ok {
					if mpm, ok := rlVal["max_per_minute"].(int); ok {
						params.RateLimit = &RateLimit{MaxPerMinute: mpm}
					} else if mpm, ok := rlVal["max_per_minute"].(float64); ok {
						params.RateLimit = &RateLimit{MaxPerMinute: int(mpm)}
					}
				}
				cr.kind.numeric = &params
			case "regex":
				var params RegexConditionParams
				if pats, ok := rule.Condition.Params["patterns"].([]interface{}); ok {
					for _, p := range pats {
						if str, ok := p.(string); ok {
							params.Patterns = append(params.Patterns, str)
						}
					}
				} else if pats, ok := rule.Condition.Params["patterns"].([]string); ok {
					params.Patterns = pats
				}
				if ma, ok := rule.Condition.Params["match_action"].(string); ok {
					params.MatchAction = ma
				}
				cr.kind.regex = &params
			case "state_invariant":
				var params StateInvariantConditionParams
				if tf, ok := rule.Condition.Params["target_field"].(string); ok {
					params.TargetField = tf
				}
				if tf, ok := rule.Condition.Params["tenant_field"].(string); ok {
					params.TenantField = tf
				}
				if req, ok := rule.Condition.Params["require_state"].(bool); ok {
					params.RequireState = req
				}
				if prec, ok := rule.Condition.Params["precondition"].(string); ok {
					params.Precondition = prec
				}
				if ass, ok := rule.Condition.Params["assertion"].(string); ok {
					params.Assertion = ass
				}
				cr.kind.state = &params
			}
			out = append(out, cr)
		}
	}
	return out
}

// NewEngine creates an AegisEngine with the provided configuration
func NewEngine(cfg Config) *AegisEngine {
	mode := cfg.Mode
	if mode == "" {
		mode = ModeEnforce
	}
	failPolicy := cfg.FailPolicy
	if failPolicy == "" {
		failPolicy = FailClosed
	}

	packs := cfg.RulePacks
	if len(packs) == 0 && (cfg.EnableSQLValidation || cfg.EnablePIIScanning || len(cfg.NumericLimits) > 0) {
		// Synthesize rule pack from legacy configuration flags
		var rules []Rule
		if cfg.EnableSQLValidation {
			rules = append(rules, BuiltinPacks["sql-guard"].Rules...)
		}
		if cfg.EnablePIIScanning {
			rules = append(rules, BuiltinPacks["data-guard"].Rules...)
		}
		for argName, limit := range cfg.NumericLimits {
			rules = append(rules, Rule{
				ID:          fmt.Sprintf("NUMERIC-%s", argName),
				Severity:    SeverityCritical,
				Description: fmt.Sprintf("Numeric limit constraint on %s", argName),
				Condition: RuleCondition{
					Type: "numeric",
					Params: map[string]interface{}{
						"field": argName,
						"min":   limit.Min,
						"max":   limit.Max,
					},
				},
			})
		}
		if len(rules) > 0 {
			packs = []RulePack{{
				ID:      "custom-config-pack",
				Name:    "Synthesized Config Rulepack",
				Version: "1.0.0",
				Rules:   rules,
			}}
		}
	} else if len(packs) == 0 {
		// Load standard default guard packs
		packs = []RulePack{
			BuiltinPacks["sql-guard"],
			BuiltinPacks["finance-guard"],
			BuiltinPacks["data-guard"],
		}
	}

	return &AegisEngine{
		config:           cfg,
		packs:            packs,
		compiledRules:    compileRules(packs),
		sqlChecker:       NewSqlChecker(),
		numericChecker:   NewNumericChecker(),
		piiChecker:       NewPiiChecker(),
		stateChecker:     NewStateChecker(),
		tokenVault:       NewPiiTokenVault(nil),
		merkleLogger:     NewMerkleLogger(),
		policyCommitment: ComputePolicyCommitmentHash(packs),
		mode:             mode,
		failPolicy:       failPolicy,
	}
}

// NewDefaultEngine creates an AegisEngine with standard launch rule packs
func NewDefaultEngine() *AegisEngine {
	return NewEngine(Config{
		Mode:       ModeEnforce,
		FailPolicy: FailClosed,
		RulePacks: []RulePack{
			BuiltinPacks["sql-guard"],
			BuiltinPacks["finance-guard"],
			BuiltinPacks["data-guard"],
		},
	})
}

// NewEngineWithPacks creates an AegisEngine with specific rule packs
func NewEngineWithPacks(packs ...RulePack) *AegisEngine {
	return NewEngine(Config{
		Mode:       ModeEnforce,
		FailPolicy: FailClosed,
		RulePacks:  packs,
	})
}

// GetTokenVault returns the active PII token vault
func (e *AegisEngine) GetTokenVault() *PiiTokenVault {
	return e.tokenVault
}

// GetMerkleLogger returns the audit logger
func (e *AegisEngine) GetMerkleLogger() *MerkleLogger {
	return e.merkleLogger
}

// GetPolicyCommitment returns the cryptographic commitment of all active rules
func (e *AegisEngine) GetPolicyCommitment() string {
	return e.policyCommitment
}

// Evaluate evaluates a tool call against all active safety invariants
func (e *AegisEngine) Evaluate(call ToolCall, opts ...EvaluateOption) (verdict AegisVerdict) {
	start := time.Now()
	timestamp := start.UnixMilli()

	options := EvaluateOptions{
		Mode:       &e.mode,
		FailPolicy: &e.failPolicy,
	}
	for _, opt := range opts {
		opt(&options)
	}

	effectiveMode := e.mode
	if options.Mode != nil {
		effectiveMode = *options.Mode
	}
	effectiveFailPolicy := e.failPolicy
	if options.FailPolicy != nil {
		effectiveFailPolicy = *options.FailPolicy
	}

	// Fail-closed panic recovery handler
	defer func() {
		if r := recover(); r != nil {
			latencyMs := time.Since(start).Milliseconds()
			latencyUs := time.Since(start).Microseconds()
			toolFingerprint := ComputeToolCallFingerprint(call)

			if effectiveFailPolicy == FailClosed {
				v := AegisViolation{
					RuleID:   "ENGINE-PANIC",
					PackID:   "aegis-core",
					Severity: SeverityCritical,
					Message:  fmt.Sprintf("Engine evaluation error (fail-closed triggered): %v", r),
				}
				proof := GenerateProofHash(toolFingerprint, false, e.policyCommitment, 1, timestamp)
				verdict = AegisVerdict{
					Allowed:    false,
					Violations: []AegisViolation{v},
					ProofHash:  proof,
					LatencyMs:  latencyMs,
					LatencyUs:  latencyUs,
					Mode:       effectiveMode,
				}
			} else {
				proof := GenerateProofHash(toolFingerprint, true, e.policyCommitment, 0, timestamp)
				verdict = AegisVerdict{
					Allowed:   true,
					Warning:   fmt.Sprintf("Engine panic occurred under fail-open policy: %v", r),
					ProofHash: proof,
					LatencyMs: latencyMs,
					LatencyUs: latencyUs,
					Mode:      effectiveMode,
				}
			}
		}
	}()

	var violations []AegisViolation
	rulesEvaluated := 0

	// 1. Evaluate all compiled rules (typed params pre-parsed at construction —
	//    the hot path performs zero per-rule map[string]interface{} re-parsing).
	for i := range e.compiledRules {
		rule := &e.compiledRules[i]
		rulesEvaluated++
		switch rule.kind.ruleType {
		case "sql_ast":
			vList := e.sqlChecker.Evaluate(rule.ruleID, rule.packID, *rule.kind.sql, call, rule.severity)
			violations = append(violations, vList...)
		case "numeric":
			vList := e.numericChecker.Evaluate(rule.ruleID, rule.packID, *rule.kind.numeric, call, rule.severity)
			violations = append(violations, vList...)
		case "regex":
			vList := e.piiChecker.Evaluate(rule.ruleID, rule.packID, *rule.kind.regex, call, rule.severity)
			violations = append(violations, vList...)
		case "state_invariant":
			vList := e.stateChecker.Evaluate(rule.ruleID, rule.packID, *rule.kind.state, call, options.State, rule.severity)
			violations = append(violations, vList...)
		}
	}

	// Determine verdict
	hasCriticalViolation := false
	for _, v := range violations {
		if v.Severity == SeverityCritical {
			hasCriticalViolation = true
			break
		}
	}

	allowed := !hasCriticalViolation
	if effectiveMode == ModeShadow {
		allowed = true // Shadow mode permits execution while recording violations
	}

	latencyMs := time.Since(start).Milliseconds()
	latencyUs := time.Since(start).Microseconds()
	toolFingerprint := ComputeToolCallFingerprint(call)
	proofHash := GenerateProofHash(toolFingerprint, allowed, e.policyCommitment, len(violations), timestamp)

	var suggestedFix string
	if len(violations) > 0 {
		for _, v := range violations {
			if v.SuggestedFix != "" {
				suggestedFix = v.SuggestedFix
				break
			}
		}
	}

	verdict = AegisVerdict{
		Allowed:      allowed,
		Violations:   violations,
		ProofHash:    proofHash,
		LatencyMs:    latencyMs,
		LatencyUs:    latencyUs,
		Mode:         effectiveMode,
		SuggestedFix: suggestedFix,
	}

	// Telemetry logging
	verdictStr := "ALLOWED"
	if !verdict.Allowed {
		verdictStr = "BLOCKED"
	}
	e.merkleLogger.LogEvent(AegisEvent{
		ID:                   fmt.Sprintf("evt_%d", timestamp),
		Timestamp:            time.Now().UTC().Format(time.RFC3339),
		Version:              "1.0.0",
		ToolName:             call.GetToolName(),
		ToolCallFingerprint:  toolFingerprint,
		Mode:                 effectiveMode,
		Verdict:              verdictStr,
		RulesEvaluated:       rulesEvaluated,
		RulesFired:           violations,
		LatencyMs:            latencyMs,
		ProofHash:            proofHash,
		PolicyCommitmentHash: e.policyCommitment,
	})

	if options.OnViolation != nil && len(violations) > 0 {
		options.OnViolation(verdict, call)
	}

	return verdict
}

// Guard wraps an AgentFunc tool call handler with fail-closed safety enforcement
func (e *AegisEngine) Guard(fn AgentFunc) AgentFunc {
	return func(call ToolCall) (interface{}, error) {
		verdict := e.Evaluate(call)
		if !verdict.Allowed {
			var msgs []string
			for _, v := range verdict.Violations {
				msgs = append(msgs, v.Message)
			}
			return nil, fmt.Errorf("aegis policy violation: %s", strings.Join(msgs, " | "))
		}
		return fn(call)
	}
}
