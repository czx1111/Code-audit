/**
 * Code Audit MCP Server - Utility Functions
 */

import * as crypto from 'crypto';
import * as path from 'path';
import { glob } from 'glob';
import { readFile, stat } from 'fs/promises';
import {
  FILE_EXTENSIONS,
  DEFAULT_EXCLUDE_PATTERNS,
} from '../constants';
import type {
  SupportedLanguage,
  Severity,
  Vulnerability,
  CodeSnippet,
} from '../types';

// ============================================================================
// Language Detection
// ============================================================================
export function detectLanguage(filePath: string): SupportedLanguage {
  const ext = path.extname(filePath).toLowerCase();
  for (const [lang, extensions] of Object.entries(FILE_EXTENSIONS)) {
    if (extensions.includes(ext)) {
      return lang as SupportedLanguage;
    }
  }
  return 'python'; // Default fallback
}

export function getLanguageFromFile(filePath: string): SupportedLanguage {
  return detectLanguage(filePath);
}

export function isLanguageSupported(filePath: string): boolean {
  const ext = path.extname(filePath).toLowerCase();
  for (const extensions of Object.values(FILE_EXTENSIONS)) {
    if (extensions.includes(ext)) {
      return true;
    }
  }
  return false;
}

// ============================================================================
// File Operations
// ============================================================================
export async function findSourceFiles(
  targetPath: string,
  language: SupportedLanguage | 'auto' = 'auto',
  excludePatterns: string[] = DEFAULT_EXCLUDE_PATTERNS,
  maxFiles: number = 1000
): Promise<string[]> {
  const patterns: string[] = [];
  
  // Normalize path to use forward slashes for glob compatibility
  const normalizedPath = targetPath.replace(/\\/g, '/');

  if (language === 'auto') {
    // All supported extensions
    for (const extensions of Object.values(FILE_EXTENSIONS)) {
      for (const ext of extensions) {
        patterns.push(`${normalizedPath}/**/*${ext}`);
      }
    }
  } else {
    // Specific language
    const extensions = FILE_EXTENSIONS[language] || [];
    for (const ext of extensions) {
      patterns.push(`${normalizedPath}/**/*${ext}`);
    }
  }

  const files: string[] = [];
  for (const pattern of patterns) {
    if (files.length >= maxFiles) break;
    try {
      const matches = await glob(pattern, {
        ignore: excludePatterns,
        nodir: true,
        absolute: true,
        follow: false,
      });
      files.push(...matches.slice(0, maxFiles - files.length));
    } catch {
      // Ignore glob errors
    }
  }

  return [...new Set(files)]; // Remove duplicates
}

export async function readFileContent(filePath: string): Promise<string> {
  try {
    const content = await readFile(filePath, 'utf-8');
    return content;
  } catch (error) {
    throw new Error(`Failed to read file ${filePath}: ${error}`);
  }
}

export async function getFileStats(
  filePath: string
): Promise<{ size: number; created: Date; modified: Date } | null> {
  try {
    const stats = await stat(filePath);
    return {
      size: stats.size,
      created: stats.birthtime,
      modified: stats.mtime,
    };
  } catch {
    return null;
  }
}

// ============================================================================
// Code Helpers
// ============================================================================
export function extractCodeSnippet(
  content: string,
  line: number,
  contextLines: number = 3
): CodeSnippet {
  const lines = content.split('\n');
  const startLine = Math.max(1, line - contextLines);
  const endLine = Math.min(lines.length, line + contextLines);
  const code = lines.slice(startLine - 1, endLine).join('\n');

  return {
    code,
    language: 'text',
    startLine,
    highlightedLines: [line],
  };
}

export function extractCodeSnippetWithLanguage(
  content: string,
  line: number,
  language: string,
  contextLines: number = 3
): CodeSnippet {
  const snippet = extractCodeSnippet(content, line, contextLines);
  snippet.language = language;
  return snippet;
}

export function getLineContent(content: string, line: number): string {
  const lines = content.split('\n');
  return lines[line - 1] || '';
}

export function countLines(content: string): number {
  return content.split('\n').length;
}

// ============================================================================
// ID Generation
// ============================================================================
export function generateId(): string {
  return crypto
    .createHash('sha256')
    .update(Date.now().toString() + Math.random().toString())
    .digest('hex')
    .slice(0, 16);
}

export function generateVulnerabilityId(
  ruleId: string,
  location: { file: string; line: number }
): string {
  const data = `${ruleId}:${location.file}:${location.line}`;
  return crypto.createHash('md5').update(data).digest('hex').slice(0, 12);
}

// ============================================================================
// Severity Helpers
// ============================================================================
export function severityToNumber(severity: Severity): number {
  const map: Record<Severity, number> = {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    info: 1,
  };
  return map[severity];
}

export function compareSeverity(a: Severity, b: Severity): number {
  return severityToNumber(b) - severityToNumber(a);
}

export function severityToEmoji(severity: Severity): string {
  const map: Record<Severity, string> = {
    critical: '🔴',
    high: '🟠',
    medium: '🟡',
    low: '🟢',
    info: '🔵',
  };
  return map[severity];
}

// ============================================================================
// Path Helpers
// ============================================================================
export function normalizePath(p: string): string {
  return p.replace(/\\/g, '/');
}

export function getRelativePath(basePath: string, filePath: string): string {
  const absBase = path.isAbsolute(basePath) ? basePath : path.resolve(basePath);
  const absFile = path.isAbsolute(filePath) ? filePath : path.resolve(filePath);
  return normalizePath(path.relative(absBase, absFile));
}

export function isPathExcluded(filePath: string, excludePatterns: string[]): boolean {
  const normalizedPath = normalizePath(filePath);
  for (const pattern of excludePatterns) {
    const normalizedPattern = pattern.replace(/\\/g, '/');
    // Simple pattern matching
    if (normalizedPattern.includes('**')) {
      const regexPattern = normalizedPattern
        .replace(/\*\*/g, '.*')
        .replace(/\*/g, '[^/]*');
      const regex = new RegExp(regexPattern, 'i');
      if (regex.test(normalizedPath)) {
        return true;
      }
    } else if (normalizedPath.includes(normalizedPattern.replace('*', ''))) {
      return true;
    }
  }
  return false;
}

// ============================================================================
// String Helpers
// ============================================================================
export function truncateString(str: string, maxLength: number): string {
  if (str.length <= maxLength) return str;
  return str.slice(0, maxLength - 3) + '...';
}

export function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

export function escapeMarkdown(str: string): string {
  return str.replace(/([*_`\[\]])/g, '\\$1');
}

// ============================================================================
// Timing Helpers
// ============================================================================
export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(2)}s`;
  const minutes = Math.floor(ms / 60000);
  const seconds = Math.floor((ms % 60000) / 1000);
  return `${minutes}m ${seconds}s`;
}

// ============================================================================
// Validation Helpers
// ============================================================================
export function isValidPath(p: string): boolean {
  try {
    // Check for path traversal attempts
    if (p.includes('..')) return false;
    if (p.includes('\0')) return false;
    return true;
  } catch {
    return false;
  }
}

export function validateTargetPath(
  p: string
): { valid: boolean; error?: string } {
  if (!p) {
    return { valid: false, error: 'Target path is required' };
  }
  if (!isValidPath(p)) {
    return { valid: false, error: 'Invalid path format' };
  }
  return { valid: true };
}

// ============================================================================
// Array Helpers
// ============================================================================
export function chunkArray<T>(array: T[], size: number): T[][] {
  const chunks: T[][] = [];
  for (let i = 0; i < array.length; i += size) {
    chunks.push(array.slice(i, i + size));
  }
  return chunks;
}

export function uniqueArray<T>(array: T[]): T[] {
  return [...new Set(array)];
}

// ============================================================================
// Vulnerability Helpers
// ============================================================================
export function sortVulnerabilities(vulnerabilities: Vulnerability[]): Vulnerability[] {
  return [...vulnerabilities].sort((a, b) => compareSeverity(a.severity, b.severity));
}

export function filterVulnerabilitiesBySeverity(
  vulnerabilities: Vulnerability[],
  minSeverity: Severity
): Vulnerability[] {
  const minLevel = severityToNumber(minSeverity);
  return vulnerabilities.filter(
    (v) => severityToNumber(v.severity) >= minLevel
  );
}

export function groupVulnerabilitiesByFile(
  vulnerabilities: Vulnerability[]
): Map<string, Vulnerability[]> {
  const groups = new Map<string, Vulnerability[]>();
  for (const vuln of vulnerabilities) {
    const file = vuln.location.file;
    if (!groups.has(file)) {
      groups.set(file, []);
    }
    groups.get(file)!.push(vuln);
  }
  return groups;
}

// ============================================================================
// Error Handling
// ============================================================================
export function formatError(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  if (typeof error === 'string') {
    return error;
  }
  return String(error);
}

export function createErrorResponse(error: unknown, context?: string): string {
  const message = formatError(error);
  return context ? `${context}: ${message}` : message;
}

// ============================================================================
// Report Generation
// ============================================================================
export function generateReport(
  result: {
    targetPath: string;
    timestamp: string;
    mode: string;
    totalFiles: number;
    vulnerabilities: Vulnerability[];
  },
  format: 'markdown' | 'json' = 'markdown'
): string {
  const summary = {
    critical: result.vulnerabilities.filter((v) => v.severity === 'critical').length,
    high: result.vulnerabilities.filter((v) => v.severity === 'high').length,
    medium: result.vulnerabilities.filter((v) => v.severity === 'medium').length,
    low: result.vulnerabilities.filter((v) => v.severity === 'low').length,
    info: result.vulnerabilities.filter((v) => v.severity === 'info').length,
  };

  if (format === 'json') {
    return JSON.stringify({ ...result, summary }, null, 2);
  }

  // Markdown format
  let report = `# 代码安全审计报告

## 概要
- **扫描路径**: ${result.targetPath}
- **扫描时间**: ${result.timestamp}
- **扫描模式**: ${result.mode}
- **总文件数**: ${result.totalFiles}
- **发现问题**: ${result.vulnerabilities.length}

## 统计
| 严重级别 | 数量 |
|---------|------|
| 🔴 Critical | ${summary.critical} |
| 🟠 High | ${summary.high} |
| 🟡 Medium | ${summary.medium} |
| 🟢 Low | ${summary.low} |
| 🔵 Info | ${summary.info} |

## 详细问题

`;

  const sortedVulns = sortVulnerabilities(result.vulnerabilities);

  for (const vuln of sortedVulns.slice(0, 50)) { // Limit to 50 issues
    report += `### [${vuln.severity.toUpperCase()}] ${vuln.name}

**文件**: \`${vuln.location.file}:${vuln.location.line}\`

**描述**: ${vuln.description}

`;
    if (vuln.snippet) {
      report += `**代码片段**:
\`\`\`${vuln.snippet.language}
${vuln.snippet.code}
\`\`\`

`;
    }
    if (vuln.fixSuggestion) {
      report += `**修复建议**: ${vuln.fixSuggestion}

`;
    }
    if (vuln.cwe) {
      report += `**CWE**: ${vuln.cwe}

`;
    }
    report += '---\n\n';
  }

  if (sortedVulns.length > 50) {
    report += `\n> 仅显示前50个问题，共发现 ${sortedVulns.length} 个问题。\n`;
  }

  return report;
}
