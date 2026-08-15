import { describe, it, expect, beforeEach } from 'vitest';
import { RAGGroundingValidator } from '../src/grounding/rag-grounding-validator';

describe('RAGGroundingValidator', () => {
  let validator: RAGGroundingValidator;

  beforeEach(() => {
    validator = new RAGGroundingValidator();
  });

  it('should pass grounded output', () => {
    const output = 'The capital of France is Paris.';
    const context = [
      'France is a country in Europe.',
      'Paris is the capital of France.'
    ];
    
    const result = validator.checkGrounding(output, context);
    expect(result.isGrounded).toBe(true);
    expect(result.hallucinatedFacts).toHaveLength(0);
  });

  it('should fail ungrounded output due to hallucinated entities', () => {
    const output = 'The capital of France is Paris. The president is Macron.';
    const context = [
      'France is a country in Europe.',
      'Paris is the capital of France.'
    ];
    
    const result = validator.checkGrounding(output, context);
    // 'Macron' is an entity not in context
    expect(result.isGrounded).toBe(false);
    expect(result.hallucinatedFacts).toContain("Entity 'Macron' not found in context");
  });

  it('should calculate low lexical overlap when output is unrelated', () => {
    const output = 'Dogs are great pets.';
    const context = [
      'The cat is a small carnivorous mammal.'
    ];
    
    const result = validator.checkGrounding(output, context);
    expect(result.lexicalOverlapScore).toBe(0);
    expect(result.isGrounded).toBe(false);
  });

  it('should respect requireExactMatch option', () => {
    const output = 'Cats are mammals.';
    const context = ['The cat is a small carnivorous mammal.'];
    
    // Partially matched
    const result = validator.checkGrounding(output, context, { requireExactMatch: true, entityCheckEnabled: false });
    // Due to requireExactMatch, containmentScore needs to be > 0.8
    expect(result.isGrounded).toBe(false);
  });
});
