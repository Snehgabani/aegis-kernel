import * as fs from 'node:fs';
import yaml from 'js-yaml';
import AjvModule from 'ajv';
import type { RulePack } from './types.js';

const AjvClass: typeof import('ajv').default = (AjvModule as any).default ?? AjvModule;
const ajv = new (AjvClass as any)();

const RULE_PACK_SCHEMA = {
  type: 'object',
  required: ['id', 'name', 'version', 'rules'],
  properties: {
    id: { type: 'string', pattern: '^[a-zA-Z0-9_-]+$' },
    name: { type: 'string' },
    version: { type: 'string' },
    description: { type: 'string' },
    rules: {
      type: 'array',
      items: {
        type: 'object',
        required: ['id', 'severity', 'description', 'condition'],
        properties: {
          id: { type: 'string' },
          severity: { enum: ['critical', 'warning', 'info'] },
          description: { type: 'string' },
          suggestedFix: { type: 'string' },
          condition: {
            type: 'object',
            required: ['type', 'params'],
            properties: {
              type: {
                enum: ['sql_ast', 'json_schema', 'regex', 'numeric', 'custom', 'state_invariant'],
              },
              params: { type: 'object' },
            },
          },
        },
      },
    },
  },
};

const validatePackSchema = ajv.compile(RULE_PACK_SCHEMA);

// Inlined Built-in Launch Packs (Available with zero file-system dependencies)
export const BUILTIN_PACKS: Record<string, RulePack> = {
  '@aegis/sql-guard': {
    id: 'sql-guard',
    name: 'Aegis SQL Mutation & Destructive Operation Guard',
    version: '1.0.0',
    description: 'Enforces AST-level safety invariants on database queries',
    rules: [
      {
        id: 'SQL-001',
        severity: 'critical',
        description: 'Prohibit DELETE statements without a WHERE clause',
        suggestedFix: 'Add a targeted WHERE clause to delete specific rows.',
        condition: {
          type: 'sql_ast',
          params: {
            statements: ['DELETE'],
            require: 'WHERE_CLAUSE',
          },
        },
      },
      {
        id: 'SQL-002',
        severity: 'critical',
        description: 'Prohibit destructive DROP and TRUNCATE commands',
        suggestedFix: 'Destructive DDL statements are prohibited in production.',
        condition: {
          type: 'sql_ast',
          params: {
            block_statements: ['DROP', 'TRUNCATE'],
          },
        },
      },
      {
        id: 'SQL-003',
        severity: 'critical',
        description: 'Prohibit UPDATE statements without a WHERE clause',
        suggestedFix: 'Add a specific WHERE clause to prevent updating all records.',
        condition: {
          type: 'sql_ast',
          params: {
            statements: ['UPDATE'],
            require: 'WHERE_CLAUSE',
          },
        },
      },
    ],
  },
  '@aegis/finance-guard': {
    id: 'finance-guard',
    name: 'Aegis Financial Bounds & Overspend Guard',
    version: '1.0.0',
    description: 'Enforces numeric limits and rate controls on payouts and transactions',
    rules: [
      {
        id: 'FIN-001',
        severity: 'critical',
        description: 'Single transaction amount cannot exceed $10,000',
        suggestedFix: 'Transaction amount exceeds maximum single-action ceiling of $10,000.',
        condition: {
          type: 'numeric',
          params: {
            field: 'amount',
            max: 10000,
          },
        },
      },
      {
        id: 'FIN-002',
        severity: 'critical',
        description: 'Financial tool execution rate ceiling (max 10/min)',
        suggestedFix: 'Payout frequency ceiling exceeded. Wait before retrying.',
        condition: {
          type: 'numeric',
          params: {
            field: 'amount',
            rate_limit: {
              max_per_minute: 10,
            },
          },
        },
      },
      {
        id: 'FIN-STATE-001',
        severity: 'critical',
        description: 'Daily cumulative spending invariant: current_daily_spent + amount <= daily_budget',
        suggestedFix: 'Cumulative daily spending limit exceeded.',
        condition: {
          type: 'state_invariant',
          params: {
            target_field: 'amount',
            precondition: "state.account_status == 'active'",
            assertion: 'state.spent_today + params.amount <= state.daily_budget',
          },
        },
      },
    ],
  },
  '@aegis/data-guard': {
    id: 'data-guard',
    name: 'Aegis PII & Credential Leak Guard',
    version: '1.0.0',
    description: 'Detects and blocks leakage of credit cards, SSNs, and API keys',
    rules: [
      {
        id: 'DATA-001',
        severity: 'critical',
        description: 'Block credit cards and US Social Security numbers',
        suggestedFix: 'Redact PII (Credit Cards / SSN) before calling external APIs.',
        condition: {
          type: 'regex',
          params: {
            patterns: ['CREDIT_CARD', 'US_SSN'],
            match_action: 'block',
          },
        },
      },
      {
        id: 'DATA-002',
        severity: 'critical',
        description: 'Block API secret keys and Bearer authentication tokens',
        suggestedFix: 'API keys must not be passed in tool payload body.',
        condition: {
          type: 'regex',
          params: {
            patterns: ['OPENAI_API_KEY', 'GITHUB_TOKEN', 'AWS_ACCESS_KEY', 'STRIPE_KEY', 'GENERIC_BEARER'],
            match_action: 'block',
          },
        },
      },
    ],
  },
  // Enterprise & Compliance Packs (Pro / Enterprise Tiers)
  '@aegis/hipaa-guard': {
    id: 'hipaa-guard',
    name: 'Aegis HIPAA Healthcare & Protected Health Information Invariant Guard',
    version: '1.0.0',
    description: 'Technical safeguards enforcing HIPAA 164.312(a)(1) against PHI exfiltration',
    rules: [
      {
        id: 'HIPAA-001',
        severity: 'critical',
        description: 'Prohibit unmasked National Provider Identifier (NPI) and Social Security Numbers in outbound agent tools',
        suggestedFix: 'Redact patient SSN and physician NPI numbers before tool dispatch.',
        condition: {
          type: 'regex',
          params: {
            patterns: ['US_SSN', 'US_NPI'],
            match_action: 'block',
          },
        },
      },
      {
        id: 'HIPAA-002',
        severity: 'critical',
        description: 'Block DEA registration numbers and prescription identifiers from unauthorized external transmission',
        suggestedFix: 'DEA registration numbers are restricted under HIPAA safeguards.',
        condition: {
          type: 'regex',
          params: {
            patterns: ['US_DEA'],
            match_action: 'block',
          },
        },
      },
      {
        id: 'HIPAA-003',
        severity: 'warning',
        description: 'Detect and flag clinical diagnostic ICD-10 codes in unstructured tool arguments',
        suggestedFix: 'Clinical diagnostic codes (ICD-10) should be sanitized or tokenized.',
        condition: {
          type: 'regex',
          params: {
            patterns: ['ICD10_CODE'],
            match_action: 'warn',
          },
        },
      },
    ],
  },
  '@aegis/pci-dss-guard': {
    id: 'pci-dss-guard',
    name: 'Aegis PCI-DSS v4.0 Payment Card Industry Invariant Guard',
    version: '1.0.0',
    description: 'Enforces technical standards for cardholder data environments under PCI-DSS Requirement 3 & 6',
    rules: [
      {
        id: 'PCI-001',
        severity: 'critical',
        description: 'Prohibit Primary Account Numbers (PAN / credit cards) in plain text tool calls',
        suggestedFix: 'Payment card numbers must be tokenized before transmission.',
        condition: {
          type: 'regex',
          params: {
            patterns: ['CREDIT_CARD'],
            match_action: 'block',
          },
        },
      },
      {
        id: 'PCI-002',
        severity: 'critical',
        description: 'Strict prohibition of Card Verification Value (CVV/CVC) in any agent storage or transmission',
        suggestedFix: 'Card verification values (CVV/CVC) must NEVER be processed or retained by agents.',
        condition: {
          type: 'regex',
          params: {
            patterns: ['CREDIT_CARD_CVV'],
            match_action: 'block',
          },
        },
      },
      {
        id: 'PCI-003',
        severity: 'critical',
        description: 'Block payment gateway live secret tokens from leaking into agent execution logs',
        suggestedFix: 'Stripe / payment gateway live keys must be stored in secret managers.',
        condition: {
          type: 'regex',
          params: {
            patterns: ['STRIPE_KEY'],
            match_action: 'block',
          },
        },
      },
    ],
  },
  '@aegis/soc2-guard': {
    id: 'soc2-guard',
    name: 'Aegis SOC 2 Trust Services Criteria & System Invariant Guard',
    version: '1.0.0',
    description: 'Enforces access control and system integrity invariants for SOC 2 Type II compliance (CC6.1, CC6.6)',
    rules: [
      {
        id: 'SOC2-001',
        severity: 'critical',
        description: 'Block system file path traversal and credential access (/etc/shadow, ~/.ssh, .env)',
        suggestedFix: 'Access to system credentials and environment files is restricted under SOC 2 policies.',
        condition: {
          type: 'regex',
          params: {
            patterns: ['SENSITIVE_FILE_PATH'],
            match_action: 'block',
          },
        },
      },
      {
        id: 'SOC2-002',
        severity: 'critical',
        description: 'Prohibit destructive schema DDL alterations in production agent workflows',
        suggestedFix: 'Destructive DDL operations (DROP/TRUNCATE/ALTER) require an approved change management ticket.',
        condition: {
          type: 'sql_ast',
          params: {
            block_statements: ['DROP', 'TRUNCATE'],
          },
        },
      },
      {
        id: 'SOC2-003',
        severity: 'critical',
        description: 'Block production database mass mutations lacking row-level WHERE constraints',
        suggestedFix: 'All mutation queries in production must specify targeted WHERE clauses.',
        condition: {
          type: 'sql_ast',
          params: {
            statements: ['DELETE', 'UPDATE'],
            require: 'WHERE_CLAUSE',
          },
        },
      },
    ],
  },
};

export class RulePackLoader {
  public static loadPack(packRef: string | RulePack): RulePack | null {
    if (typeof packRef !== 'string') {
      if (this.validatePack(packRef)) {
        return packRef;
      }
      return null;
    }

    if (packRef in BUILTIN_PACKS) {
      return BUILTIN_PACKS[packRef];
    }
    const withPrefix = `@aegis/${packRef}`;
    if (withPrefix in BUILTIN_PACKS) {
      return BUILTIN_PACKS[withPrefix];
    }

    try {
      if (fs.existsSync(packRef)) {
        const fileContent = fs.readFileSync(packRef, 'utf8');
        const parsed = yaml.load(fileContent) as RulePack;
        if (this.validatePack(parsed)) {
          return parsed;
        }
      }
    } catch {
      // Return null on failure
    }

    return null;
  }

  public static validatePack(pack: unknown): pack is RulePack {
    if (!pack || typeof pack !== 'object') return false;
    const isValid = validatePackSchema(pack);
    return Boolean(isValid);
  }
}
