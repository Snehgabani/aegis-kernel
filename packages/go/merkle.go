package aegis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
)

// ComputePolicyCommitmentHash creates a deterministic SHA-256 fingerprint for active rule packs
func ComputePolicyCommitmentHash(packs []RulePack) string {
	hasher := sha256.New()
	var ruleKeys []string

	for _, p := range packs {
		for _, r := range p.Rules {
			ruleKeys = append(ruleKeys, fmt.Sprintf("%s:%s:%s", p.ID, r.ID, r.Severity))
		}
	}
	sort.Strings(ruleKeys)

	for _, k := range ruleKeys {
		hasher.Write([]byte(k))
		hasher.Write([]byte{0})
	}

	return hex.EncodeToString(hasher.Sum(nil))
}

// ComputeToolCallFingerprint calculates a deterministic hash of tool name and parameters
func ComputeToolCallFingerprint(call ToolCall) string {
	hasher := sha256.New()
	hasher.Write([]byte(call.GetToolName()))
	hasher.Write([]byte{0})

	paramsBytes, err := json.Marshal(call.GetParams())
	if err == nil {
		hasher.Write(paramsBytes)
	}

	return hex.EncodeToString(hasher.Sum(nil))
}

// GenerateProofHash creates a cryptographic commitment binding tool call, verdict, policy commitment, and timestamp
func GenerateProofHash(toolFingerprint string, allowed bool, policyCommitment string, violationCount int, timestamp int64) string {
	hasher := sha256.New()
	hasher.Write([]byte(toolFingerprint))
	hasher.Write([]byte(fmt.Sprintf(":%v:%s:%d:%d", allowed, policyCommitment, violationCount, timestamp)))
	return hex.EncodeToString(hasher.Sum(nil))
}

// MerkleLogger stores in-memory or persists event logs
type MerkleLogger struct {
	mu     sync.RWMutex
	events []AegisEvent
}

// NewMerkleLogger creates a new Merkle event logger
func NewMerkleLogger() *MerkleLogger {
	return &MerkleLogger{
		events: make([]AegisEvent, 0),
	}
}

// LogEvent records an audit event in thread-safe storage
func (ml *MerkleLogger) LogEvent(event AegisEvent) {
	ml.mu.Lock()
	defer ml.mu.Unlock()
	ml.events = append(ml.events, event)
}

// GetEvents returns a copy of all recorded events
func (ml *MerkleLogger) GetEvents() []AegisEvent {
	ml.mu.RLock()
	defer ml.mu.RUnlock()
	copied := make([]AegisEvent, len(ml.events))
	copy(copied, ml.events)
	return copied
}

// GetRootHash computes a Merkle root over all recorded events
func (ml *MerkleLogger) GetRootHash() string {
	ml.mu.RLock()
	defer ml.mu.RUnlock()

	if len(ml.events) == 0 {
		h := sha256.Sum256([]byte("AEGIS_EMPTY_LEDGER"))
		return hex.EncodeToString(h[:])
	}

	var hashes [][]byte
	for _, evt := range ml.events {
		h := sha256.Sum256([]byte(evt.ProofHash))
		hashes = append(hashes, h[:])
	}

	for len(hashes) > 1 {
		var nextLevel [][]byte
		for i := 0; i < len(hashes); i += 2 {
			if i+1 < len(hashes) {
				combined := append(hashes[i], hashes[i+1]...)
				h := sha256.Sum256(combined)
				nextLevel = append(nextLevel, h[:])
			} else {
				nextLevel = append(nextLevel, hashes[i])
			}
		}
		hashes = nextLevel
	}

	return hex.EncodeToString(hashes[0])
}
