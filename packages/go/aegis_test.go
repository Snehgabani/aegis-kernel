package aegis

import (
	"testing"
)

func TestEvaluate(t *testing.T) {
	engine := NewEngine(Config{
		EnableSQLValidation: true,
		EnablePIIScanning:   true,
		NumericLimits: map[string]NumericLimit{
			"amount": {Min: 0, Max: 1000},
		},
	})

	tests := []struct {
		name     string
		call     ToolCall
		allowed  bool
	}{
		{
			name: "allowed call",
			call: ToolCall{Name: "get_data", Arguments: map[string]interface{}{"query": "SELECT * FROM users WHERE id = 1"}},
			allowed: true,
		},
		{
			name: "blocked sql drop",
			call: ToolCall{Name: "execute_sql", Arguments: map[string]interface{}{"query": "DROP TABLE users"}},
			allowed: false,
		},
		{
			name: "blocked sql delete without where",
			call: ToolCall{Name: "execute_sql", Arguments: map[string]interface{}{"query": "DELETE FROM users"}},
			allowed: false,
		},
		{
			name: "blocked pii",
			call: ToolCall{Name: "send_message", Arguments: map[string]interface{}{"msg": "my ssn is 123-45-6789"}},
			allowed: false,
		},
		{
			name: "blocked numeric out of bounds",
			call: ToolCall{Name: "transfer", Arguments: map[string]interface{}{"amount": 2000.0}},
			allowed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verdict := engine.Evaluate(tt.call)
			if verdict.Allowed != tt.allowed {
				t.Errorf("expected allowed: %v, got %v (violations: %v)", tt.allowed, verdict.Allowed, verdict.Violations)
			}
		})
	}
}
