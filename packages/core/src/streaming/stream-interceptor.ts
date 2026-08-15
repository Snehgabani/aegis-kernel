import type { AegisEngine } from '../engine.js';

export interface StreamChunk {
  text: string;
  index?: number;
  finishReason?: string | null;
  action?: 'ABORT' | 'PASS' | 'REDACT';
  reason?: string;
}

export interface StreamVerdictAction {
  action: 'PASS' | 'ABORT' | 'REDACT';
  reason?: string;
  matchedPattern?: string;
  position?: number;
}

export interface StreamInterceptorConfig {
  maxPatternLength?: number;  // Default: 256 characters
  piiPatterns?: RegExp[];     // Additional PII patterns to scan
  secretPatterns?: RegExp[];  // Secret/API key patterns
  abortOnMatch?: boolean;     // Default: true (abort stream on match)
  redactOnMatch?: boolean;    // Default: false (redact instead of abort)
}

// Simple Aho-Corasick node
class TrieNode {
  children: Map<string, TrieNode> = new Map();
  fail: TrieNode | null = null;
  output: string[] = [];
}

class AhoCorasick {
  root: TrieNode = new TrieNode();

  constructor(patterns: string[]) {
    for (const p of patterns) {
      this.insert(p);
    }
    this.buildFailureLinks();
  }

  private insert(pattern: string) {
    let node = this.root;
    for (const char of pattern) {
      if (!node.children.has(char)) {
        node.children.set(char, new TrieNode());
      }
      node = node.children.get(char)!;
    }
    node.output.push(pattern);
  }

  private buildFailureLinks() {
    const queue: TrieNode[] = [];
    for (const child of this.root.children.values()) {
      child.fail = this.root;
      queue.push(child);
    }

    while (queue.length > 0) {
      const current = queue.shift()!;
      for (const [char, child] of current.children.entries()) {
        let failNode = current.fail;
        while (failNode !== null && !failNode.children.has(char)) {
          failNode = failNode.fail;
        }
        child.fail = failNode ? failNode.children.get(char)! : this.root;
        child.output.push(...child.fail.output);
        queue.push(child);
      }
    }
  }

  search(text: string): { matchedPattern: string; position: number } | null {
    let node: TrieNode | null = this.root;
    for (let i = 0; i < text.length; i++) {
      const char = text[i];
      while (node !== null && !node.children.has(char)) {
        node = node.fail;
      }
      if (!node) {
        node = this.root;
      } else {
        node = node.children.get(char) ?? this.root;
      }
      if (node.output.length > 0) {
        return { matchedPattern: node.output[0], position: i - node.output[0].length + 1 };
      }
    }
    return null;
  }
}

export class AegisStreamInterceptor {
  private config: Required<StreamInterceptorConfig>;
  private engine: AegisEngine;
  private ac: AhoCorasick;

  constructor(engine: AegisEngine, config: StreamInterceptorConfig = {}) {
    this.engine = engine;
    this.config = {
      maxPatternLength: config.maxPatternLength ?? 256,
      piiPatterns: config.piiPatterns ?? [],
      secretPatterns: config.secretPatterns ?? [],
      abortOnMatch: config.abortOnMatch ?? true,
      redactOnMatch: config.redactOnMatch ?? false,
    };
    
    // We'll extract strings from regex for AC, or just use AC for a set of known secrets
    const patterns = ['password123', 'API_KEY_SECRET', 'SSN_MOCK_123']; 
    this.ac = new AhoCorasick(patterns);
  }

  public getEngine(): AegisEngine {
    return this.engine;
  }

  async *intercept(stream: AsyncIterable<StreamChunk>): AsyncGenerator<StreamChunk> {
    let buffer = '';
    
    for await (let chunk of stream) {
      if (!chunk) continue;
      
      const token = chunk.text || '';
      buffer += token;
      
      let matched = false;
      let matchReason = '';
      
      // Check Aho-Corasick
      const acMatch = this.ac.search(buffer);
      if (acMatch) {
        matched = true;
        matchReason = `Matched pattern: ${acMatch.matchedPattern}`;
      }

      // Check regex patterns
      if (!matched) {
        for (const pattern of [...this.config.piiPatterns, ...this.config.secretPatterns]) {
          if (pattern.test(buffer)) {
            matched = true;
            matchReason = `Matched regex pattern: ${pattern.source}`;
            break;
          }
        }
      }
      
      if (matched) {
        if (this.config.abortOnMatch) {
          yield { text: '', action: 'ABORT', reason: matchReason, index: chunk.index };
          return;
        } else if (this.config.redactOnMatch) {
          chunk = { ...chunk, text: '[REDACTED]', action: 'REDACT' };
        }
      }

      // Keep the last maxPatternLength characters in a sliding buffer
      if (buffer.length > this.config.maxPatternLength) {
        buffer = buffer.slice(-this.config.maxPatternLength);
      }
      
      // Clear the buffer when a natural sentence/paragraph boundary is detected
      if (/[.!?](?:\s|$)|(?:\n\n)/.test(token)) {
        buffer = '';
      }

      yield chunk;
    }
  }
}
