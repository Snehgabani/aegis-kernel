package aegis

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sync"
)

// TokenizeResult holds the result of a tokenization operation
type TokenizeResult struct {
	Sanitized     string         `json:"sanitized"`
	TokensCreated int            `json:"tokensCreated"`
	TokenTypes    map[string]int `json:"tokenTypes"`
}

// DetokenizeResult holds the result of a detokenization operation
type DetokenizeResult struct {
	Restored       string `json:"restored"`
	TokensRestored int    `json:"tokensRestored"`
}

// PiiTokenVaultConfig configures the salted token vault
type PiiTokenVaultConfig struct {
	Patterns    map[string]*regexp.Regexp
	TokenPrefix string
	HashLength  int
	Salt        []byte
}

// PiiTokenVault provides a secure, deterministic, salted tokenization store
type PiiTokenVault struct {
	mu              sync.RWMutex
	patterns        map[string]*regexp.Regexp
	vault           map[string]string // Token -> original value
	valueToTokenMap map[string]string // Original value -> token
	tokenPrefix     string
	hashLength      int
	sessionSalt     []byte
}

// NewPiiTokenVault creates a new token vault with randomized session salt
func NewPiiTokenVault(config *PiiTokenVaultConfig) *PiiTokenVault {
	patterns := DefaultPiiPatterns
	tokenPrefix := ""
	hashLength := 16
	var salt []byte

	if config != nil {
		if config.Patterns != nil {
			patterns = config.Patterns
		}
		if config.TokenPrefix != "" {
			tokenPrefix = config.TokenPrefix
		}
		if config.HashLength > 0 {
			hashLength = config.HashLength
		}
		if len(config.Salt) > 0 {
			salt = config.Salt
		}
	}

	if len(salt) == 0 {
		salt = make([]byte, 16)
		_, _ = rand.Read(salt)
	}

	return &PiiTokenVault{
		patterns:        patterns,
		vault:           make(map[string]string),
		valueToTokenMap: make(map[string]string),
		tokenPrefix:     tokenPrefix,
		hashLength:      hashLength,
		sessionSalt:     salt,
	}
}

// Tokenize masks all matching PII patterns with salted deterministic tokens
func (v *PiiTokenVault) Tokenize(text string) TokenizeResult {
	if text == "" {
		return TokenizeResult{Sanitized: text, TokensCreated: 0, TokenTypes: make(map[string]int)}
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	sanitized := text
	tokensCreated := 0
	tokenTypes := make(map[string]int)

	for pName, regex := range v.patterns {
		sanitized = regex.ReplaceAllStringFunc(sanitized, func(match string) string {
			if existing, ok := v.valueToTokenMap[match]; ok {
				return existing
			}

			mac := hmac.New(sha256.New, v.sessionSalt)
			mac.Write([]byte(match))
			tokenHash := hex.EncodeToString(mac.Sum(nil))
			if len(tokenHash) > v.hashLength {
				tokenHash = tokenHash[:v.hashLength]
			}

			prefix := pName
			if v.tokenPrefix != "" {
				prefix = v.tokenPrefix
			}
			token := fmt.Sprintf("<%s_%s>", prefix, tokenHash)

			v.vault[token] = match
			v.valueToTokenMap[match] = token
			tokensCreated++
			tokenTypes[pName]++

			return token
		})
	}

	return TokenizeResult{
		Sanitized:     sanitized,
		TokensCreated: tokensCreated,
		TokenTypes:    tokenTypes,
	}
}

// Detokenize restores masked tokens back to their original PII values
func (v *PiiTokenVault) Detokenize(text string) DetokenizeResult {
	if text == "" {
		return DetokenizeResult{Restored: text, TokensRestored: 0}
	}

	v.mu.RLock()
	defer v.mu.RUnlock()

	tokenRegex := regexp.MustCompile(`<[A-Za-z0-9_]+>`)
	tokensRestored := 0

	restored := tokenRegex.ReplaceAllStringFunc(text, func(match string) string {
		if original, ok := v.vault[match]; ok {
			tokensRestored++
			return original
		}
		return match
	})

	return DetokenizeResult{
		Restored:       restored,
		TokensRestored: tokensRestored,
	}
}

// Clear clears all stored tokens
func (v *PiiTokenVault) Clear() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.vault = make(map[string]string)
	v.valueToTokenMap = make(map[string]string)
}

// GetVaultSize returns current count of vaulted tokens
func (v *PiiTokenVault) GetVaultSize() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.vault)
}
