import { describe, it, expect } from 'vitest';
import { 
  LiteLLMMiddleware, 
  PortkeyGuardrailPlugin, 
  LangfuseObservabilityBridge 
} from '../src/adapters/gateway-ecosystem.js';

describe('Gateway Ecosystem Adapters', () => {
  describe('LiteLLMMiddleware', () => {
    it('should validate tool call data', async () => {
      const middleware = new LiteLLMMiddleware();
      await expect(middleware.preToolCallValidation({ name: 'myTool' })).resolves.toBe(true);
      await expect(middleware.preToolCallValidation(null)).rejects.toThrow("Invalid tool call data");
    });

    it('should validate tool call result', async () => {
      const middleware = new LiteLLMMiddleware();
      await expect(middleware.postToolCallValidation({ result: 'ok' })).resolves.toBe(true);
      await expect(middleware.postToolCallValidation(null)).rejects.toThrow("Invalid tool call result");
    });

    it('should validate streaming chunks', () => {
      const middleware = new LiteLLMMiddleware();
      expect(middleware.streamValidationHook("safe data")).toBe(true);
      expect(middleware.streamValidationHook("this contains BLOCK_THIS string")).toBe(false);
    });
  });

  describe('PortkeyGuardrailPlugin', () => {
    it('should integrate with Portkey pipeline', () => {
      const plugin = new PortkeyGuardrailPlugin({ someConfig: true });
      const pipelineData = { steps: [] };
      const integrated = plugin.integratePipeline(pipelineData);
      
      expect(integrated.steps).toEqual([]);
      expect(integrated._aegis_guardrail_attached).toBe(true);
      expect(integrated.timestamp).toBeDefined();
    });
  });

  describe('LangfuseObservabilityBridge', () => {
    it('should sync trace data', () => {
      const bridge = new LangfuseObservabilityBridge();
      bridge.syncTrace({ id: 'trace123', type: 'info' });
      
      const traces = bridge.getTraces();
      expect(traces).toHaveLength(1);
      expect(traces[0].id).toBe('trace123');
    });

    it('should reject trace without ID', () => {
      const bridge = new LangfuseObservabilityBridge();
      expect(() => bridge.syncTrace({ type: 'info' })).toThrow("Trace data requires an ID");
    });

    it('should log violations', () => {
      const bridge = new LangfuseObservabilityBridge();
      bridge.logViolation({ reason: 'policy breach' });
      
      const traces = bridge.getTraces();
      expect(traces).toHaveLength(1);
      expect(traces[0].id).toContain('violation_');
      expect(traces[0].type).toBe('violation');
      expect(traces[0].data.reason).toBe('policy breach');
    });
  });
});
