import { describe, it, expect, beforeEach } from 'vitest';
import { AegisStreamInterceptor, StreamChunk } from '../src/streaming/stream-interceptor';

describe('AegisStreamInterceptor', () => {
  let interceptor: AegisStreamInterceptor;

  beforeEach(() => {
    interceptor = new AegisStreamInterceptor({}, {
      windowSize: 4,
      piiPatterns: [/\b\d{3}-\d{2}-\d{4}\b/], // SSN regex
      secretPatterns: [/super_secret_key/],
      abortOnMatch: true
    });
  });

  async function collectChunks(interceptor: AegisStreamInterceptor, chunks: StreamChunk[]) {
    async function* generate() {
      for (const chunk of chunks) yield chunk;
    }
    const result = [];
    for await (const chunk of interceptor.intercept(generate())) {
      result.push(chunk);
    }
    return result;
  }

  it('should pass through safe chunks', async () => {
    const chunks: StreamChunk[] = [
      { text: 'Hello ' },
      { text: 'world!' }
    ];
    const result = await collectChunks(interceptor, chunks);
    expect(result).toHaveLength(2);
    expect(result[0].text).toBe('Hello ');
    expect(result[1].text).toBe('world!');
  });

  it('should handle empty streams', async () => {
    const result = await collectChunks(interceptor, []);
    expect(result).toHaveLength(0);
  });

  it('should handle single token stream', async () => {
    const chunks: StreamChunk[] = [{ text: 'Hello' }];
    const result = await collectChunks(interceptor, chunks);
    expect(result).toHaveLength(1);
    expect(result[0].text).toBe('Hello');
  });

  it('should handle very long streams (sliding window logic)', async () => {
    const chunks: StreamChunk[] = Array(100).fill({ text: 'a ' });
    const result = await collectChunks(interceptor, chunks);
    expect(result).toHaveLength(100);
  });

  it('should detect and abort on Aho-Corasick match', async () => {
    const chunks: StreamChunk[] = [
      { text: 'Here is ' },
      { text: 'my pass' },
      { text: 'word12' },
      { text: '3!' }
    ];
    const result = await collectChunks(interceptor, chunks);
    expect(result.length).toBeLessThan(5);
    expect(result[result.length - 1].action).toBe('ABORT');
    expect(result[result.length - 1].reason).toContain('password123');
  });

  it('should detect PII split across chunk boundaries', async () => {
    const chunks: StreamChunk[] = [
      { text: 'My SSN is ' },
      { text: '123' },
      { text: '-45' },
      { text: '-6789.' }
    ];
    const result = await collectChunks(interceptor, chunks);
    expect(result[result.length - 1].action).toBe('ABORT');
    expect(result[result.length - 1].reason).toContain('regex pattern');
  });

  it('should redact when redactOnMatch is true', async () => {
    const redactInterceptor = new AegisStreamInterceptor({}, {
      windowSize: 4,
      secretPatterns: [/super_secret_key/],
      abortOnMatch: false,
      redactOnMatch: true
    });
    
    const chunks: StreamChunk[] = [
      { text: 'The key is ' },
      { text: 'super_' },
      { text: 'secret_' },
      { text: 'key and ' },
      { text: 'that is it.' }
    ];
    const result = await collectChunks(redactInterceptor, chunks);
    
    // It should redact the chunk that triggered the match
    const redactedChunk = result.find(c => c.action === 'REDACT');
    expect(redactedChunk).toBeDefined();
    expect(redactedChunk?.text).toBe('[REDACTED]');
  });
});
