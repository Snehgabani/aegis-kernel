/**
 * @file packages/vscode-extension/src/extension.ts
 * @description VS Code extension for Aegis AI Agent Security Linter.
 * Provides real-time in-editor AST linting of SQL queries and MCP tool parameter invariants.
 */

export interface ExtensionContext {
  subscriptions: { dispose(): any }[];
}

export function activate(context: ExtensionContext) {
  // eslint-disable-next-line no-console
  console.log('🛡️ Aegis AI Agent Security Linter extension is active!');
}

export function deactivate() {
  // eslint-disable-next-line no-console
  console.log('🛡️ Aegis AI Agent Security Linter extension deactivated.');
}
