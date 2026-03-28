/**
 * SARIF (Static Analysis Results Interchange Format) Output Generator
 * Generates SARIF format output for compatibility with GitHub Code Scanning,
 * Azure DevOps, and other security tools.
 * 
 * SARIF specification: https://sarifweb.azurewebsites.net/
 */

import { Vulnerability, Severity } from './types.js';

/**
 * SARIF Log structure
 */
export interface SarifLog {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

export interface SarifRun {
  tool: SarifTool;
  results: SarifResult[];
  columnKind: string;
}

export interface SarifTool {
  driver: SarifDriver;
}

export interface SarifDriver {
  name: string;
  version: string;
  informationUri: string;
  rules: SarifRule[];
}

export interface SarifRule {
  id: string;
  name: string;
  shortDescription: {
    text: string;
  };
  fullDescription?: {
    text: string;
  };
  helpUri?: string;
  help?: {
    text: string;
  };
  defaultConfiguration?: {
    level: string;
  };
  properties?: {
    tags?: string[];
    cwe?: string[];
    owasp?: string[];
    severity: string;
  };
}

export interface SarifResult {
  ruleId: string;
  ruleIndex?: number;
  level: string;
  message: {
    text: string;
  };
  locations: SarifLocation[];
  partialFingerprints?: {
    'primaryLocationLineHash'?: string;
  };
  properties?: {
    confidence: number;
  };
}

export interface SarifLocation {
  physicalLocation: {
    artifactLocation: {
      uri: string;
      uriBaseId?: string;
    };
    region: {
      startLine: number;
      startColumn?: number;
      endLine?: number;
      endColumn?: number;
      snippet?: {
        text: string;
      };
    };
  };
}

/**
 * Map severity to SARIF level
 */
function severityToSarifLevel(severity: Severity): string {
  const levelMap: Record<Severity, string> = {
    'critical': 'error',
    'high': 'error',
    'medium': 'warning',
    'low': 'note',
    'info': 'note',
  };
  return levelMap[severity] || 'warning';
}

/**
 * Generate a simple hash for the fingerprint
 */
function generateLineHash(file: string, line: number, ruleId: string): string {
  const str = `${file}:${line}:${ruleId}`;
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return Math.abs(hash).toString(16);
}

/**
 * Convert vulnerabilities to SARIF format
 */
export function generateSarif(
  vulnerabilities: Vulnerability[],
  toolName: string = 'code-audit-mcp-server',
  toolVersion: string = '2.0.0'
): SarifLog {
  // Collect unique rules
  const ruleMap = new Map<string, SarifRule>();
  
  for (const vuln of vulnerabilities) {
    if (!ruleMap.has(vuln.ruleId)) {
      const rule: SarifRule = {
        id: vuln.ruleId,
        name: vuln.name,
        shortDescription: {
          text: vuln.description,
        },
        defaultConfiguration: {
          level: severityToSarifLevel(vuln.severity),
        },
        properties: {
          severity: vuln.severity,
        },
      };
      
      if (vuln.cwe) {
        rule.properties!.cwe = [vuln.cwe];
        rule.helpUri = `https://cwe.mitre.org/data/definitions/${vuln.cwe.replace('CWE-', '')}.html`;
      }
      
      if (vuln.owasp) {
        rule.properties!.owasp = [vuln.owasp];
      }
      
      if (vuln.tags && vuln.tags.length > 0) {
        rule.properties!.tags = vuln.tags;
      }
      
      if (vuln.fixSuggestion) {
        rule.help = {
          text: vuln.fixSuggestion,
        };
      }
      
      ruleMap.set(vuln.ruleId, rule);
    }
  }
  
  const rules = Array.from(ruleMap.values());
  
  // Create rule index map
  const ruleIndexMap = new Map<string, number>();
  rules.forEach((rule, index) => {
    ruleIndexMap.set(rule.id, index);
  });
  
  // Generate results
  const results: SarifResult[] = vulnerabilities.map((vuln) => ({
    ruleId: vuln.ruleId,
    ruleIndex: ruleIndexMap.get(vuln.ruleId),
    level: severityToSarifLevel(vuln.severity),
    message: {
      text: vuln.description,
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: vuln.location.file.replace(/\\/g, '/'),
          },
          region: {
            startLine: vuln.location.line,
            startColumn: vuln.location.column || 1,
            endLine: vuln.location.endLine || vuln.location.line,
            endColumn: vuln.location.endColumn || 1,
            ...(vuln.snippet?.code ? {
              snippet: {
                text: vuln.snippet.code,
              },
            } : {}),
          },
        },
      },
    ],
    partialFingerprints: {
      primaryLocationLineHash: generateLineHash(vuln.location.file, vuln.location.line, vuln.ruleId),
    },
    properties: {
      confidence: vuln.confidence,
    },
  }));
  
  // Create SARIF log
  const sarifLog: SarifLog = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: toolName,
            version: toolVersion,
            informationUri: 'https://github.com/example/code-audit-mcp-server',
            rules,
          },
        },
        results,
        columnKind: 'utf16CodeUnits',
      },
    ],
  };
  
  return sarifLog;
}

/**
 * Generate SARIF JSON string
 */
export function generateSarifJson(
  vulnerabilities: Vulnerability[],
  toolName?: string,
  toolVersion?: string
): string {
  const sarif = generateSarif(vulnerabilities, toolName, toolVersion);
  return JSON.stringify(sarif, null, 2);
}
