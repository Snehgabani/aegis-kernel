package aegis

import (
	"strings"
	"testing"
)

func TestComprehensiveGoSDK(t *testing.T) {
	engine := NewDefaultEngine()

	t.Run("SQL Invariants & Allowed Queries", func(t *testing.T) {
		validQueries := []ToolCall{
			{Tool: "db_query", Params: map[string]interface{}{"query": "SELECT id, name FROM users WHERE id = 42"}},
			{Tool: "run_sql", Params: map[string]interface{}{"sql": "SELECT * FROM orders WHERE status = 'pending' LIMIT 100"}},
			{Tool: "custom_tool", Params: map[string]interface{}{"stmt": "INSERT INTO logs (msg) VALUES ('test user login')"}},
			{Tool: "search_kb", Params: map[string]interface{}{"query": "how to delete a record in react"}}, // Search query shouldn't trigger SQL check
		}

		for _, call := range validQueries {
			verdict := engine.Evaluate(call)
			if !verdict.Allowed {
				t.Fatalf("Expected valid query to be allowed: %v, violations: %v", call, verdict.Violations)
			}
		}
	})

	t.Run("SQL DDL & Destructive Commands", func(t *testing.T) {
		blockedCalls := []struct {
			name string
			call ToolCall
		}{
			{"DROP TABLE", ToolCall{Tool: "db_query", Params: map[string]interface{}{"query": "DROP TABLE users"}}},
			{"DROP DATABASE", ToolCall{Tool: "run_sql", Params: map[string]interface{}{"sql": "DROP DATABASE production"}}},
			{"TRUNCATE", ToolCall{Tool: "exec_sql", Params: map[string]interface{}{"stmt": "TRUNCATE TABLE transactions"}}},
			{"ALTER TABLE DROP", ToolCall{Tool: "db_query", Params: map[string]interface{}{"query": "ALTER TABLE users DROP COLUMN password_hash"}}},
			{"GRANT PRIVILEGES", ToolCall{Tool: "db_query", Params: map[string]interface{}{"query": "GRANT ALL PRIVILEGES ON *.* TO 'attacker'@'%'"}}},
			{"REVOKE", ToolCall{Tool: "db_query", Params: map[string]interface{}{"query": "REVOKE ALL ON users FROM admin"}}},
		}

		for _, tt := range blockedCalls {
			verdict := engine.Evaluate(tt.call)
			if verdict.Allowed {
				t.Errorf("[%s] Expected DDL to be blocked, but was allowed", tt.name)
			}
		}
	})

	t.Run("SQL Mass Delete and Update without WHERE", func(t *testing.T) {
		massMutations := []ToolCall{
			{Tool: "db_query", Params: map[string]interface{}{"query": "DELETE FROM users"}},
			{Tool: "db_query", Params: map[string]interface{}{"query": "UPDATE users SET role = 'admin'"}},
		}

		for _, call := range massMutations {
			verdict := engine.Evaluate(call)
			if verdict.Allowed {
				t.Errorf("Expected mass mutation without WHERE to be blocked: %v", call)
			}
		}
	})

	t.Run("SQL Tautology Evasion Vectors", func(t *testing.T) {
		tautologyVectors := []struct {
			name  string
			query string
		}{
			{"1=1", "DELETE FROM users WHERE 1=1"},
			{"1 = 1 spaces", "DELETE FROM users WHERE 1 = 1"},
			{"2=2", "DELETE FROM users WHERE 2=2"},
			{"0=0", "DELETE FROM users WHERE 0=0"},
			{"100=100", "DELETE FROM users WHERE 100=100"},
			{"2>1", "DELETE FROM users WHERE 2>1"},
			{"10>5", "DELETE FROM users WHERE 10>5"},
			{"string identity", "DELETE FROM users WHERE 'a'='a'"},
			{"TRUE literal", "DELETE FROM users WHERE TRUE"},
			{"1 literal", "DELETE FROM users WHERE 1"},
			{"self column id=id", "DELETE FROM users WHERE id = id"},
			{"self column users.id=users.id", "DELETE FROM users WHERE users.id = users.id"},
			{"IS NOT NULL", "DELETE FROM users WHERE id IS NOT NULL"},
			{"domain id > 0", "DELETE FROM users WHERE id > 0"},
			{"domain id >= 0", "DELETE FROM users WHERE id >= 0"},
			{"domain id != -1", "DELETE FROM users WHERE id != -1"},
			{"domain id <> -1", "DELETE FROM users WHERE id <> -1"},
			{"OR tautology", "DELETE FROM users WHERE id = 123 OR 1=1"},
			{"OR true", "DELETE FROM users WHERE id = 'abc' OR TRUE"},
			{"unconstrained subquery", "DELETE FROM users WHERE id IN (SELECT id FROM users)"},
		}

		for _, tt := range tautologyVectors {
			call := ToolCall{Tool: "db_query", Params: map[string]interface{}{"query": tt.query}}
			verdict := engine.Evaluate(call)
			if verdict.Allowed {
				t.Errorf("[%s] Expected tautology evasion query '%s' to be blocked", tt.name, tt.query)
			}
		}
	})

	t.Run("SQL Comment Evasions & Obfuscation", func(t *testing.T) {
		evasionQueries := []struct {
			name  string
			query string
		}{
			{"comment split DELETE", "DEL/**/ETE FROM users WHERE 1=1"},
			{"comment split DROP", "D/**/R/**/O/**/P TABLE users"},
			{"spaced DROP", "D R O P TABLE users"},
			{"hex encoded keyword", "\\x44\\x52\\x4F\\x50 TABLE users"},
			{"concat unrolling", "'DEL' || 'ETE' FROM users"},
			{"CTE mutation", "WITH cte AS (DELETE FROM users WHERE 1=1) SELECT * FROM cte"},
		}

		for _, tt := range evasionQueries {
			call := ToolCall{Tool: "db_query", Params: map[string]interface{}{"query": tt.query}}
			verdict := engine.Evaluate(call)
			if verdict.Allowed {
				t.Errorf("[%s] Expected comment evasion '%s' to be blocked", tt.name, tt.query)
			}
		}
	})

	t.Run("Numeric Bounds, Currency Stripping & Semantic Aliases", func(t *testing.T) {
		// Valid amount
		v1 := engine.Evaluate(ToolCall{Tool: "payout", Params: map[string]interface{}{"amount": 500.0}})
		if !v1.Allowed {
			t.Errorf("Expected valid numeric amount to be allowed, got: %v", v1.Violations)
		}

		// Amount exceeding $10k limit
		v2 := engine.Evaluate(ToolCall{Tool: "payout", Params: map[string]interface{}{"amount": 25000.0}})
		if v2.Allowed {
			t.Errorf("Expected $25,000 payout to be blocked")
		}

		// Currency string stripping: "$15,000.00 USD" should be parsed as 15000 and blocked
		v3 := engine.Evaluate(ToolCall{Tool: "transfer", Params: map[string]interface{}{"amount": "$15,000.00 USD"}})
		if v3.Allowed {
			t.Errorf("Expected formatted currency '$15,000.00 USD' to be blocked")
		}

		// Euro currency: "€ 5,000.00" should be allowed
		v4 := engine.Evaluate(ToolCall{Tool: "transfer", Params: map[string]interface{}{"amount": "€ 5,000.00"}})
		if !v4.Allowed {
			t.Errorf("Expected '€ 5,000.00' to be allowed")
		}

		// Semantic alias detection: payout parameter named "payout", "price", "transfer", "total"
		v5 := engine.Evaluate(ToolCall{Tool: "execute_payment", Params: map[string]interface{}{"payout": 50000.0}})
		if v5.Allowed {
			t.Errorf("Expected semantic alias 'payout: 50000' to be blocked by finance-guard")
		}

		// Negative amount on financial alias (default min: 0)
		v6 := engine.Evaluate(ToolCall{Tool: "transfer", Params: map[string]interface{}{"amount": -50.0}})
		if v6.Allowed {
			t.Errorf("Expected negative financial amount -50.0 to be blocked by default min: 0")
		}
	})

	t.Run("PII & Secrets Scanning", func(t *testing.T) {
		piiCases := []struct {
			name string
			call ToolCall
		}{
			{"US SSN", ToolCall{Tool: "send_email", Params: map[string]interface{}{"body": "Customer SSN is 123-45-6789"}}},
			{"OpenAI Key", ToolCall{Tool: "api_call", Params: map[string]interface{}{"token": "sk-proj-abcdef1234567890abcdef123456"}}},
			{"GitHub Token", ToolCall{Tool: "github_sync", Params: map[string]interface{}{"key": "ghp_1234567890abcdefghijklmnopqrstuvwxyz"}}},
			{"AWS Access Key", ToolCall{Tool: "s3_upload", Params: map[string]interface{}{"aws_key": "AKIAIOSFODNN7EXAMPLE"}}},
			{"Slack Token", ToolCall{Tool: "post_slack", Params: map[string]interface{}{"auth": "xoxb-1234567890-abcdef12345"}}},
			{"Sensitive File Path", ToolCall{Tool: "read_file", Params: map[string]interface{}{"path": "/etc/shadow"}}},
			{"Destructive Shell Command", ToolCall{Tool: "run_shell", Params: map[string]interface{}{"cmd": "rm -rf /"}}},
		}

		for _, tt := range piiCases {
			verdict := engine.Evaluate(tt.call)
			if verdict.Allowed {
				t.Errorf("[%s] Expected PII / Secret to be blocked: %v", tt.name, tt.call)
			}
		}
	})

	t.Run("Salted PII Token Vault Roundtrip", func(t *testing.T) {
		vault := NewPiiTokenVault(nil)
		rawText := "User john (SSN: 123-45-6789, email: john@example.com) uploaded token sk-proj-1234567890abcdefghij"

		tokenized := vault.Tokenize(rawText)
		if tokenized.TokensCreated == 0 {
			t.Fatalf("Expected tokens to be created")
		}
		if strings.Contains(tokenized.Sanitized, "123-45-6789") {
			t.Fatalf("Tokenized text still contains raw SSN: %s", tokenized.Sanitized)
		}
		if strings.Contains(tokenized.Sanitized, "sk-proj-1234567890abcdefghij") {
			t.Fatalf("Tokenized text still contains OpenAI key: %s", tokenized.Sanitized)
		}

		detokenized := vault.Detokenize(tokenized.Sanitized)
		if detokenized.Restored != rawText {
			t.Fatalf("Detokenized text mismatch!\nGot:  %s\nWant: %s", detokenized.Restored, rawText)
		}
	})

	t.Run("State Invariants & Tenant Isolation", func(t *testing.T) {
		stateCtx := map[string]interface{}{
			"tenant_id":      "org_123",
			"account_status": "active",
			"spent_today":    4000.0,
			"daily_budget":   5000.0,
		}

		// Valid budget spend (4000 + 500 <= 5000)
		v1 := engine.Evaluate(
			ToolCall{Tool: "spend_budget", Params: map[string]interface{}{"amount": 500.0}},
			WithState(stateCtx),
		)
		if !v1.Allowed {
			t.Errorf("Expected valid spend within daily budget to be allowed: %v", v1.Violations)
		}

		// Over budget spend (4000 + 1500 > 5000)
		v2 := engine.Evaluate(
			ToolCall{Tool: "spend_budget", Params: map[string]interface{}{"amount": 1500.0}},
			WithState(stateCtx),
		)
		if v2.Allowed {
			t.Errorf("Expected overbudget spend to violate state invariant")
		}

		// Cross-tenant isolation violation
		customPack := RulePack{
			ID:      "tenant-pack",
			Name:    "Tenant Isolation Guard",
			Version: "1.0.0",
			Rules: []Rule{
				{
					ID:       "TENANT-001",
					Severity: SeverityCritical,
					Condition: RuleCondition{
						Type: "state_invariant",
						Params: map[string]interface{}{
							"tenant_field": "tenant_id",
						},
					},
				},
			},
		}
		tenantEngine := NewEngineWithPacks(customPack)
		v3 := tenantEngine.Evaluate(
			ToolCall{Tool: "fetch_data", Params: map[string]interface{}{"tenant_id": "org_attacker"}},
			WithState(stateCtx),
		)
		if v3.Allowed {
			t.Errorf("Expected cross-tenant tool call to be blocked")
		}
	})

	t.Run("Rule Pack Loader from YAML & JSON", func(t *testing.T) {
		loader := &RulePackLoader{}

		yamlData := []byte(`
id: custom-pack
name: Custom Guard
version: 1.0.0
rules:
  - id: CUST-001
    severity: critical
    description: Prohibit transfers above 100
    condition:
      type: numeric
      params:
        field: amount
        max: 100
`)
		pack, err := loader.ParsePack(yamlData)
		if err != nil || pack.ID != "custom-pack" {
			t.Fatalf("Failed to parse custom YAML pack: %v", err)
		}

		customEngine := NewEngineWithPacks(*pack)
		v := customEngine.Evaluate(ToolCall{Tool: "transfer", Params: map[string]interface{}{"amount": 150.0}})
		if v.Allowed {
			t.Errorf("Expected custom pack to block transfer of 150 > 100")
		}
	})

	t.Run("Guard Functional Wrapper", func(t *testing.T) {
		executed := false
		handler := func(call ToolCall) (interface{}, error) {
			executed = true
			return "success", nil
		}

		guarded := engine.Guard(handler)

		// 1. Prohibited action -> returns error, handler not executed
		_, err := guarded(ToolCall{Tool: "db_query", Params: map[string]interface{}{"query": "DROP TABLE users"}})
		if err == nil {
			t.Errorf("Expected Guard to return error on violation")
		}
		if executed {
			t.Errorf("Expected guarded handler not to execute on violation")
		}

		// 2. Allowed action -> executes successfully
		res, err := guarded(ToolCall{Tool: "db_query", Params: map[string]interface{}{"query": "SELECT * FROM users WHERE id = 1"}})
		if err != nil || res != "success" || !executed {
			t.Errorf("Expected guarded handler to succeed on benign call: %v, res: %v", err, res)
		}
	})

	t.Run("Merkle Audit Root and Proof Hashes", func(t *testing.T) {
		v := engine.Evaluate(ToolCall{Tool: "db_query", Params: map[string]interface{}{"query": "SELECT * FROM users WHERE id = 1"}})
		if v.ProofHash == "" {
			t.Errorf("Expected non-empty ProofHash")
		}

		logger := engine.GetMerkleLogger()
		events := logger.GetEvents()
		if len(events) == 0 {
			t.Errorf("Expected logged telemetry events")
		}
		root := logger.GetRootHash()
		if root == "" {
			t.Errorf("Expected valid Merkle root hash")
		}
	})

	t.Run("SQL Limit Ceiling & Prohibited Statements", func(t *testing.T) {
		// LIMIT exceeding 10000
		v1 := engine.Evaluate(ToolCall{Tool: "db_query", Params: map[string]interface{}{"query": "SELECT * FROM logs LIMIT 50000"}})
		if v1.Allowed {
			t.Errorf("Expected query with LIMIT 50000 to exceed max limit 10000")
		}

		// Blocked statement types in custom pack
		customPack := RulePack{
			ID:      "strict-sql-pack",
			Version: "1.0.0",
			Rules: []Rule{
				{
					ID:       "SQL-BLOCK-INSERT",
					Severity: SeverityCritical,
					Condition: RuleCondition{
						Type: "sql_ast",
						Params: map[string]interface{}{
							"block_statements": []string{"INSERT", "EXEC"},
						},
					},
				},
			},
		}
		strictEngine := NewEngineWithPacks(customPack)
		v2 := strictEngine.Evaluate(ToolCall{Tool: "db_query", Params: map[string]interface{}{"query": "INSERT INTO users (name) VALUES ('alice')"}})
		if v2.Allowed {
			t.Errorf("Expected INSERT to be blocked by strict policy")
		}
	})

	t.Run("Sliding Window Rate Limiting", func(t *testing.T) {
		ratePack := RulePack{
			ID:      "rate-pack",
			Version: "1.0.0",
			Rules: []Rule{
				{
					ID:       "RATE-001",
					Severity: SeverityCritical,
					Condition: RuleCondition{
						Type: "numeric",
						Params: map[string]interface{}{
							"field": "amount",
							"rate_limit": map[string]interface{}{
								"max_per_minute": 2,
							},
						},
					},
				},
			},
		}
		rateEngine := NewEngineWithPacks(ratePack)

		// 1st call
		v1 := rateEngine.Evaluate(ToolCall{Tool: "payout", Params: map[string]interface{}{"amount": 100.0}})
		if !v1.Allowed {
			t.Errorf("1st payout should be allowed")
		}
		// 2nd call
		v2 := rateEngine.Evaluate(ToolCall{Tool: "payout", Params: map[string]interface{}{"amount": 100.0}})
		if !v2.Allowed {
			t.Errorf("2nd payout should be allowed")
		}
		// 3rd call -> exceeds max 2/min
		v3 := rateEngine.Evaluate(ToolCall{Tool: "payout", Params: map[string]interface{}{"amount": 100.0}})
		if v3.Allowed {
			t.Errorf("3rd payout should be rate limited")
		}
	})

	t.Run("State DSL Arithmetic & Complex Invariants", func(t *testing.T) {
		dslPack := RulePack{
			ID:      "dsl-pack",
			Version: "1.0.0",
			Rules: []Rule{
				{
					ID:       "DSL-001",
					Severity: SeverityCritical,
					Condition: RuleCondition{
						Type: "state_invariant",
						Params: map[string]interface{}{
							"precondition": "state.is_vip == 'true' || state.tier == 'premium'",
							"assertion":    "params.qty * params.unit_price <= state.max_order_value",
						},
					},
				},
			},
		}
		dslEngine := NewEngineWithPacks(dslPack)

		stateVIP := map[string]interface{}{
			"is_vip":          "true",
			"max_order_value": 1000.0,
		}

		// Valid: 10 * 50 = 500 <= 1000
		v1 := dslEngine.Evaluate(
			ToolCall{Tool: "place_order", Params: map[string]interface{}{"qty": 10.0, "unit_price": 50.0}},
			WithState(stateVIP),
		)
		if !v1.Allowed {
			t.Errorf("Valid order arithmetic should pass: %v", v1.Violations)
		}

		// Breach: 30 * 50 = 1500 > 1000
		v2 := dslEngine.Evaluate(
			ToolCall{Tool: "place_order", Params: map[string]interface{}{"qty": 30.0, "unit_price": 50.0}},
			WithState(stateVIP),
		)
		if v2.Allowed {
			t.Errorf("Breached order arithmetic should fail")
		}

		// Precondition failure: non-VIP
		stateGuest := map[string]interface{}{
			"is_vip":          "false",
			"tier":            "standard",
			"max_order_value": 1000.0,
		}
		v3 := dslEngine.Evaluate(
			ToolCall{Tool: "place_order", Params: map[string]interface{}{"qty": 10.0, "unit_price": 50.0}},
			WithState(stateGuest),
		)
		if v3.Allowed {
			t.Errorf("Precondition failure should flag violation")
		}
	})

	t.Run("Shadow Mode and Evaluation Options", func(t *testing.T) {
		shadowEngine := NewEngine(Config{
			Mode: ModeShadow,
			RulePacks: []RulePack{
				BuiltinPacks["sql-guard"],
			},
		})

		// Destructive call in Shadow mode should have Allowed=true but report Violations
		v := shadowEngine.Evaluate(ToolCall{Tool: "db_query", Params: map[string]interface{}{"query": "DROP TABLE users"}})
		if !v.Allowed {
			t.Errorf("Shadow mode should allow execution")
		}
		if len(v.Violations) == 0 {
			t.Errorf("Shadow mode should record violations")
		}
		if v.Mode != ModeShadow {
			t.Errorf("Verdict mode should be shadow")
		}
	})

	t.Run("Fail-Closed vs Fail-Open Policies", func(t *testing.T) {
		// Custom engine with fail-closed default
		fcEngine := NewEngine(Config{
			Mode:       ModeEnforce,
			FailPolicy: FailClosed,
		})
		vfc := fcEngine.Evaluate(ToolCall{Tool: "test_tool", Params: map[string]interface{}{"num": 10}})
		if !vfc.Allowed {
			t.Errorf("Standard call should be allowed")
		}
	})
}
