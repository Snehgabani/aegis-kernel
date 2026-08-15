import type { AegisEvent } from './types.js';

export interface CloudTelemetryConfig {
  apiKey: string;
  endpoint?: string;
  batchSize?: number;
  flushIntervalMs?: number;
  maxQueueSize?: number;
  enabled?: boolean;
}

export class AegisCloudTelemetryClient {
  private apiKey: string;
  private endpoint: string;
  private batchSize: number;
  private flushIntervalMs: number;
  private maxQueueSize: number;
  private enabled: boolean;

  private queue: AegisEvent[] = [];
  private timer: NodeJS.Timeout | null = null;
  private isFlushing: boolean = false;

  constructor(config: CloudTelemetryConfig) {
    this.apiKey = config.apiKey;
    this.endpoint = config.endpoint || 'https://gateway.aegis-kernel.dev/api/telemetry';
    this.batchSize = config.batchSize || 50;
    this.flushIntervalMs = config.flushIntervalMs || 2000;
    this.maxQueueSize = config.maxQueueSize || 5000;
    this.enabled = config.enabled ?? Boolean(config.apiKey);

    if (this.enabled && this.flushIntervalMs > 0) {
      this.startTimer();
    }
  }

  /**
   * Enqueues an event for background asynchronous transmission.
   * Completely non-blocking on the evaluation hot-path.
   */
  public enqueue(event: AegisEvent): void {
    if (!this.enabled) return;

    if (this.queue.length >= this.maxQueueSize) {
      // Drop oldest event if buffer is completely saturated to prevent memory unbounded growth
      this.queue.shift();
    }

    this.queue.push(event);

    if (this.queue.length >= this.batchSize) {
      // Trigger async flush without awaiting
      this.flush().catch(() => {});
    }
  }

  public async flush(): Promise<number> {
    if (this.isFlushing || this.queue.length === 0 || !this.apiKey) {
      return 0;
    }

    this.isFlushing = true;
    const batch = this.queue.splice(0, this.batchSize);

    try {
      if (typeof fetch !== 'undefined') {
        await fetch(this.endpoint, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${this.apiKey}`,
            'X-Aegis-Client-Version': '1.0.0',
          },
          body: JSON.stringify({ events: batch }),
        });
      }
      return batch.length;
    } catch {
      // In case of transient network failure, re-prepend batch if space permits
      if (this.queue.length + batch.length <= this.maxQueueSize) {
        this.queue.unshift(...batch);
      }
      return 0;
    } finally {
      this.isFlushing = false;
    }
  }

  public getQueueLength(): number {
    return this.queue.length;
  }

  public close(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  private startTimer(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = setInterval(() => {
      this.flush().catch(() => {});
    }, this.flushIntervalMs);

    // Prevent unref error in edge runtimes
    if (this.timer && typeof this.timer.unref === 'function') {
      this.timer.unref();
    }
  }
}
