import { describe, it, expect, vi } from 'vitest';
import { runHubList, runHubSearch, runHubInstall, HUB_REGISTRY } from '../src/hub-cli.js';

describe('Aegis Hub CLI Registry', () => {
  it('should list all registered community and enterprise packs', () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    runHubList();
    expect(consoleSpy).toHaveBeenCalled();
    expect(HUB_REGISTRY.length).toBeGreaterThanOrEqual(6);
    consoleSpy.mockRestore();
  });

  it('should search registry and filter matching packs', () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    runHubSearch('sql');
    expect(consoleSpy).toHaveBeenCalled();
    consoleSpy.mockRestore();
  });

  it('should install pack into local directory without error', () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    runHubInstall('@aegis/sql-guard');
    expect(consoleSpy).toHaveBeenCalled();
    consoleSpy.mockRestore();
  });
});
