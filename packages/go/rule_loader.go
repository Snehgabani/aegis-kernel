package aegis

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

const defaultSqlGuardYaml = `
id: sql-guard
name: Aegis SQL Mutation & Destructive Operation Guard
version: 1.0.0
description: Enforces AST-level safety invariants on database queries
rules:
  - id: SQL-001
    severity: critical
    description: Prohibit DELETE statements without a WHERE clause
    suggestedFix: Add a targeted WHERE clause to delete specific rows.
    condition:
      type: sql_ast
      params:
        statements:
          - DELETE
        require: WHERE_CLAUSE

  - id: SQL-002
    severity: critical
    description: Prohibit destructive DROP, TRUNCATE, ALTER, GRANT, and REVOKE commands
    suggestedFix: Destructive DDL and privilege escalation statements are prohibited in production.
    condition:
      type: sql_ast
      params:
        block_statements:
          - DROP
          - TRUNCATE
          - ALTER
          - GRANT
          - REVOKE

  - id: SQL-003
    severity: critical
    description: Prohibit UPDATE statements without a WHERE clause
    suggestedFix: Add a specific WHERE clause to prevent updating all records.
    condition:
      type: sql_ast
      params:
        statements:
          - UPDATE
        require: WHERE_CLAUSE

  - id: SQL-004
    severity: critical
    description: Prohibit unbounded SELECT result sets (LIMIT ceiling)
    suggestedFix: Add an explicit LIMIT clause at or below 10000 rows.
    condition:
      type: sql_ast
      params:
        max_limit: 10000
`

const defaultFinanceGuardYaml = `
id: finance-guard
name: Aegis Financial Bounds & Overspend Guard
version: 1.0.0
description: Enforces numeric limits and rate controls on payouts and transactions
rules:
  - id: FIN-001
    severity: critical
    description: Single transaction amount cannot exceed $10,000
    suggestedFix: Transaction amount exceeds maximum single-action ceiling of $10,000.
    condition:
      type: numeric
      params:
        field: amount
        max: 10000

  - id: FIN-002
    severity: critical
    description: Financial tool execution rate ceiling (max 10/min)
    suggestedFix: Payout frequency ceiling exceeded. Wait before retrying.
    condition:
      type: numeric
      params:
        field: amount
        rate_limit:
          max_per_minute: 10

  - id: FIN-STATE-001
    severity: critical
    description: Cumulative daily spend cannot exceed daily budget
    condition:
      type: state_invariant
      params:
        target_field: amount
        precondition: "state.account_status == 'active'"
        assertion: "state.spent_today + params.amount <= state.daily_budget"

  - id: FIN-STATE-002
    severity: critical
    description: Hourly API request limit
    condition:
      type: state_invariant
      params:
        target_field: request_count
        assertion: "params.request_count <= state.max_requests"
`

const defaultDataGuardYaml = `
id: data-guard
name: Aegis PII & Credential Leak Guard
version: 1.0.0
description: Detects and blocks leakage of credit cards, SSNs, cloud secrets, and API keys
rules:
  - id: DATA-001
    severity: critical
    description: Block credit cards, US Social Security numbers, Tax IDs, Driver Licenses, and Medical Record Numbers
    suggestedFix: Redact PII (Credit Cards / SSN / Identifiers) before calling external APIs.
    condition:
      type: regex
      params:
        patterns:
          - CREDIT_CARD
          - US_SSN
          - US_TAX_ID
          - DRIVER_LICENSE
          - MEDICAL_RECORD_NUMBER
          - US_NPI
          - US_DEA
        match_action: block

  - id: DATA-002
    severity: critical
    description: Block API secret keys, cloud credentials, Slack/SendGrid tokens, and Bearer authentication tokens
    suggestedFix: API keys and cloud credentials must not be passed in tool payload body.
    condition:
      type: regex
      params:
        patterns:
          - OPENAI_API_KEY
          - GITHUB_TOKEN
          - AWS_ACCESS_KEY
          - STRIPE_KEY
          - GENERIC_BEARER
          - JWT_TOKEN
          - SLACK_TOKEN
          - SENDGRID_KEY
          - AZURE_KEY
          - PRIVATE_KEY
          - SENSITIVE_FILE_PATH
          - DESTRUCTIVE_COMMAND
        match_action: block
`

// BuiltinPacks contains pre-loaded default rule packs
var BuiltinPacks = map[string]RulePack{
	"sql-guard":          mustParseYaml(defaultSqlGuardYaml),
	"@aegis/sql-guard":   mustParseYaml(defaultSqlGuardYaml),
	"finance-guard":      mustParseYaml(defaultFinanceGuardYaml),
	"@aegis/finance-guard": mustParseYaml(defaultFinanceGuardYaml),
	"data-guard":         mustParseYaml(defaultDataGuardYaml),
	"@aegis/data-guard":  mustParseYaml(defaultDataGuardYaml),
}

func mustParseYaml(content string) RulePack {
	var pack RulePack
	if err := yaml.Unmarshal([]byte(content), &pack); err != nil {
		panic(fmt.Sprintf("failed to parse embedded rule pack yaml: %v", err))
	}
	return pack
}

// RulePackLoader loads rule packs from files, strings, or built-in registry
type RulePackLoader struct{}

// LoadPack loads a rule pack by reference (built-in name or file path)
func (l *RulePackLoader) LoadPack(ref string) (*RulePack, error) {
	cleanRef := strings.TrimSpace(ref)
	if pack, ok := BuiltinPacks[cleanRef]; ok {
		return &pack, nil
	}
	if pack, ok := BuiltinPacks["@aegis/"+cleanRef]; ok {
		return &pack, nil
	}

	// Try reading as file
	if _, err := os.Stat(cleanRef); err == nil {
		data, err := os.ReadFile(cleanRef)
		if err != nil {
			return nil, err
		}
		return l.ParsePack(data)
	}

	return nil, fmt.Errorf("rule pack not found: %s", ref)
}

// ParsePack parses a rule pack from YAML or JSON raw bytes
func (l *RulePackLoader) ParsePack(data []byte) (*RulePack, error) {
	var pack RulePack
	// Try YAML first (YAML parser also handles JSON)
	if err := yaml.Unmarshal(data, &pack); err == nil && pack.ID != "" {
		return &pack, nil
	}

	// Fallback to JSON
	if err := json.Unmarshal(data, &pack); err == nil && pack.ID != "" {
		return &pack, nil
	}

	return nil, fmt.Errorf("failed to parse rule pack data as valid YAML or JSON")
}
