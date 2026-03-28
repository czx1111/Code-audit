/**
 * Dynamic Security Rules Loader
 * Loads custom security rules from YAML configuration files
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import * as yaml from 'yaml';
import { Vulnerability, Severity } from './types.js';

export interface SecurityRule {
  id: string;
  name: string;
  description: string;
  category: string;
  severity: Severity;
  languages: string[];
  cwe: string;
  owasp: string;
  enabled: boolean;
  tags: string[];
  patterns: RulePattern[];
  fixSuggestion?: string;
}

export interface RulePattern {
  pattern: string;
  message: string;
}

export interface RuleConfig {
  minSeverity?: Severity;
  exclude?: string[];
}

export interface RulesFile {
  rules: SecurityRule[];
  config?: RuleConfig;
}

export class RulesLoader {
  private rules: Map<string, SecurityRule> = new Map();
  private config: RuleConfig = {};
  private rulesPath: string;

  constructor(rulesPath?: string) {
    this.rulesPath = rulesPath || path.join(__dirname, '../rules');
  }

  /**
   * Load all rules from the rules directory
   */
  async loadRules(): Promise<void> {
    try {
      const files = await fs.readdir(this.rulesPath);
      const yamlFiles = files.filter(f => f.endsWith('.yaml') || f.endsWith('.yml'));

      for (const file of yamlFiles) {
        await this.loadRulesFile(path.join(this.rulesPath, file));
      }

      console.error(`Loaded ${this.rules.size} security rules from ${yamlFiles.length} files`);
    } catch (error) {
      console.error(`Warning: Could not load rules from ${this.rulesPath}:`, error);
    }
  }

  /**
   * Load rules from a single file
   */
  private async loadRulesFile(filePath: string): Promise<void> {
    try {
      const content = await fs.readFile(filePath, 'utf-8');
      const data: RulesFile = yaml.parse(content);

      if (data.config) {
        this.config = { ...this.config, ...data.config };
      }

      if (data.rules) {
        for (const rule of data.rules) {
          if (rule.enabled) {
            this.rules.set(rule.id, rule);
          }
        }
      }
    } catch (error) {
      console.error(`Error loading rules from ${filePath}:`, error);
    }
  }

  /**
   * Get all loaded rules
   */
  getRules(): SecurityRule[] {
    return Array.from(this.rules.values());
  }

  /**
   * Get rules for a specific language
   */
  getRulesForLanguage(language: string): SecurityRule[] {
    return this.getRules().filter(rule => 
      rule.languages.includes(language) || rule.languages.includes('*')
    );
  }

  /**
   * Get rules by category
   */
  getRulesByCategory(category: string): SecurityRule[] {
    return this.getRules().filter(rule => rule.category === category);
  }

  /**
   * Get rules by severity
   */
  getRulesBySeverity(severity: Severity): SecurityRule[] {
    return this.getRules().filter(rule => rule.severity === severity);
  }

  /**
   * Get a specific rule by ID
   */
  getRule(id: string): SecurityRule | undefined {
    return this.rules.get(id);
  }

  /**
   * Get configuration
   */
  getConfig(): RuleConfig {
    return this.config;
  }

  /**
   * Check if a file should be excluded based on config
   */
  shouldExclude(filePath: string): boolean {
    if (!this.config.exclude) return false;

    const relativePath = filePath.replace(/\\/g, '/');
    return this.config.exclude.some(pattern => {
      const regex = new RegExp(
        pattern
          .replace(/\*\*/g, '.*')
          .replace(/\*/g, '[^/]*')
          .replace(/\./g, '\\.')
      );
      return regex.test(relativePath);
    });
  }

  /**
   * Convert rule severity to Vulnerability severity
   */
  private mapSeverity(severity: string): Severity {
    const severityMap: Record<string, Severity> = {
      'critical': 'critical',
      'high': 'high',
      'medium': 'medium',
      'low': 'low',
      'info': 'info'
    };
    return severityMap[severity.toLowerCase()] || 'medium';
  }

  /**
   * Map category to vulnerability name prefix
   */
  private mapCategoryToName(category: string): string {
    const nameMap: Record<string, string> = {
      'injection': '注入漏洞',
      'xss': '跨站脚本攻击',
      'secrets': '敏感信息泄露',
      'crypto': '弱加密',
      'auth': '认证问题',
      'ssrf': '服务端请求伪造',
      'rce': '远程代码执行',
      'path-traversal': '路径遍历',
      'xxe': 'XML外部实体注入',
      'deserialization': '不安全的反序列化'
    };
    return nameMap[category.toLowerCase()] || '代码质量问题';
  }

  /**
   * Create a Vulnerability from a rule match
   */
  createVulnerability(
    rule: SecurityRule,
    filePath: string,
    line: number,
    codeSnippet: string,
    matchPattern?: string
  ): Vulnerability {
    const pattern = matchPattern 
      ? rule.patterns.find(p => {
          try {
            return new RegExp(p.pattern, 'gi').test(matchPattern);
          } catch {
            return false;
          }
        })
      : rule.patterns[0];

    return {
      id: `${rule.id}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      name: rule.name,
      description: rule.description,
      severity: this.mapSeverity(rule.severity),
      location: {
        file: filePath,
        line,
        column: 1,
        endLine: line,
        endColumn: 1
      },
      ruleId: rule.id,
      fixSuggestion: rule.fixSuggestion || '',
      cwe: rule.cwe,
      owasp: rule.owasp,
      confidence: 0.8,
      references: [
        `https://cwe.mitre.org/data/definitions/${rule.cwe.replace('CWE-', '')}.html`,
        `https://owasp.org/Top10/${rule.owasp}/`
      ],
      tags: rule.tags
    };
  }

  /**
   * Match code against all patterns in a rule
   */
  matchRule(code: string, rule: SecurityRule): { matched: boolean; pattern?: RulePattern; line?: number } {
    for (const rulePattern of rule.patterns) {
      try {
        const regex = new RegExp(rulePattern.pattern, 'gm');
        const match = regex.exec(code);
        
        if (match) {
          // Find line number
          const beforeMatch = code.substring(0, match.index);
          const line = (beforeMatch.match(/\n/g) || []).length + 1;
          
          return { matched: true, pattern: rulePattern, line };
        }
      } catch (error) {
        console.error(`Invalid regex pattern in rule ${rule.id}:`, rulePattern.pattern);
      }
    }
    
    return { matched: false };
  }

  /**
   * Scan code content against all rules for a language
   */
  scanWithRules(code: string, filePath: string, language: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const rules = this.getRulesForLanguage(language);
    const lines = code.split('\n');

    for (const rule of rules) {
      const result = this.matchRule(code, rule);
      
      if (result.matched && result.pattern && result.line) {
        const codeSnippet = lines[result.line - 1]?.trim() || '';
        
        vulnerabilities.push(
          this.createVulnerability(rule, filePath, result.line, codeSnippet, result.pattern.pattern)
        );
      }
    }

    return vulnerabilities;
  }
}

// Singleton instance
let rulesLoaderInstance: RulesLoader | null = null;

/**
 * Get the global rules loader instance
 */
export function getRulesLoader(rulesPath?: string): RulesLoader {
  if (!rulesLoaderInstance) {
    rulesLoaderInstance = new RulesLoader(rulesPath);
  }
  return rulesLoaderInstance;
}

/**
 * Initialize rules loader
 */
export async function initializeRules(rulesPath?: string): Promise<RulesLoader> {
  const loader = getRulesLoader(rulesPath);
  await loader.loadRules();
  return loader;
}
