#!/usr/bin/env node
/**
 * Code Audit MCP Server
 * AI-Native Code Security Audit MCP Server
 * 
 * Features:
 * - Multi-language AST parsing (Python, JavaScript, TypeScript, Go, Java, PHP)
 * - Vulnerability detection (OWASP Top 10, CWE)
 * - Call graph analysis
 * - Data flow analysis
 * - AI-powered deep audit
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import * as fs from 'fs/promises';
import * as path from 'path';

import type {
  SupportedLanguage,
  Severity,
  Vulnerability,
  AuditResult,
  AuditScanInput,
  AuditQuickScanInput,
  AuditAnalyzeFileInput,
  CallGraph,
  CallGraphNode,
  CallGraphEdge,
} from './types';

import { ParserFactory } from './parsers/types.js';
import { detectVulnerabilities } from './detectors/engine.js';
import {
  findSourceFiles,
  readFileContent,
  detectLanguage,
  generateReport,
  sortVulnerabilities,
  formatDuration,
  validateTargetPath,
  severityToNumber,
  severityToEmoji,
  getRelativePath,
} from './utils/helpers.js';
import {
  FILE_EXTENSIONS,
  MAX_FILES_DEFAULT,
} from './constants';
import { initializeRules, getRulesLoader } from './rules-loader.js';
import { generateSarifJson } from './sarif.js';
import { generateExploitationGuide, formatGuideAsMarkdown } from './exploitation-guide.js';

// ============================================================================
// MCP Server Setup
// ============================================================================
const server = new Server(
  {
    name: 'code-audit-mcp-server',
    version: '2.0.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// ============================================================================
// Tool Definitions
// ============================================================================
const TOOLS = [
  {
    name: 'audit_scan',
    description: '执行完整的代码安全审计扫描，包括AST解析、漏洞检测和报告生成。支持Python、JavaScript、TypeScript、Go、Java、PHP等多种语言。',
    inputSchema: {
      type: 'object',
      properties: {
        targetPath: {
          type: 'string',
          description: '要扫描的代码路径（文件或目录）',
        },
        language: {
          type: 'string',
          enum: ['auto', 'python', 'javascript', 'typescript', 'go', 'java', 'php', 'rust'],
          description: '指定编程语言，默认自动检测',
          default: 'auto',
        },
        mode: {
          type: 'string',
          enum: ['quick', 'standard', 'deep'],
          description: '扫描模式：quick(快速扫描高危漏洞)、standard(标准扫描)、deep(深度扫描)',
          default: 'standard',
        },
        scope: {
          type: 'string',
          enum: ['all', 'security', 'quality', 'architecture'],
          description: '扫描范围',
          default: 'security',
        },
        outputFormat: {
          type: 'string',
          enum: ['markdown', 'json', 'sarif'],
          description: '输出格式',
          default: 'markdown',
        },
        maxFiles: {
          type: 'number',
          description: '最大扫描文件数',
          default: MAX_FILES_DEFAULT,
        },
      },
      required: ['targetPath'],
    },
  },
  {
    name: 'audit_quick_scan',
    description: '快速扫描，仅检测critical和high级别的漏洞。适合CI/CD流程中的快速检查。',
    inputSchema: {
      type: 'object',
      properties: {
        targetPath: {
          type: 'string',
          description: '要扫描的代码路径',
        },
        language: {
          type: 'string',
          enum: ['auto', 'python', 'javascript', 'typescript', 'go', 'java', 'php', 'rust'],
          description: '指定编程语言',
          default: 'auto',
        },
      },
      required: ['targetPath'],
    },
  },
  {
    name: 'audit_analyze_file',
    description: '对单个文件进行详细的代码安全分析，包括AST解析、函数提取和漏洞检测。',
    inputSchema: {
      type: 'object',
      properties: {
        filePath: {
          type: 'string',
          description: '要分析的文件路径',
        },
        language: {
          type: 'string',
          enum: ['auto', 'python', 'javascript', 'typescript', 'go', 'java', 'php', 'rust'],
          description: '指定编程语言',
          default: 'auto',
        },
      },
      required: ['filePath'],
    },
  },
  {
    name: 'build_call_graph',
    description: '构建代码的函数调用关系图，用于分析代码结构和数据流。',
    inputSchema: {
      type: 'object',
      properties: {
        targetPath: {
          type: 'string',
          description: '要分析的代码路径',
        },
        language: {
          type: 'string',
          enum: ['python', 'javascript', 'typescript', 'go', 'java', 'php'],
          description: '指定编程语言',
        },
        maxDepth: {
          type: 'number',
          description: '调用图的最大深度',
          default: 10,
        },
      },
      required: ['targetPath', 'language'],
    },
  },
  {
    name: 'analyze_data_flow',
    description: '分析代码中的数据流，追踪用户输入到敏感函数的数据传播路径。',
    inputSchema: {
      type: 'object',
      properties: {
        targetPath: {
          type: 'string',
          description: '要分析的代码路径',
        },
        language: {
          type: 'string',
          enum: ['python', 'javascript', 'typescript', 'go', 'java', 'php'],
          description: '指定编程语言',
        },
        entryPoint: {
          type: 'string',
          description: '入口函数名称',
        },
      },
      required: ['targetPath', 'language'],
    },
  },
  {
    name: 'check_dependencies',
    description: '检查项目依赖的安全风险，包括已知漏洞的依赖版本检测。',
    inputSchema: {
      type: 'object',
      properties: {
        targetPath: {
          type: 'string',
          description: '项目根目录路径',
        },
      },
      required: ['targetPath'],
    },
  },
  {
    name: 'get_exploitation_guide',
    description: '获取漏洞的详细复现操作指南，包括攻击载荷、PoC代码和修复建议。',
    inputSchema: {
      type: 'object',
      properties: {
        vulnerabilityType: {
          type: 'string',
          description: '漏洞类型（如SQL_INJECTION、COMMAND_INJECTION、XSS等）',
        },
        language: {
          type: 'string',
          enum: ['python', 'javascript', 'typescript', 'go', 'java', 'php'],
          description: '编程语言',
          default: 'python',
        },
      },
      required: ['vulnerabilityType'],
    },
  },
];

// ============================================================================
// Tool Handlers
// ============================================================================

/**
 * Main audit scan handler
 */
async function handleAuditScan(targetPath: string, options?: {
  language?: string;
  mode?: string;
  maxFiles?: number;
  outputFormat?: string;
}): Promise<string> {
  const startTime = Date.now();
  const language = options?.language || 'auto';
  const mode = options?.mode || 'standard';
  const maxFiles = options?.maxFiles || MAX_FILES_DEFAULT;
  const outputFormat = options?.outputFormat || 'markdown';

  // Validate path
  const validation = validateTargetPath(targetPath);
  if (!validation.valid) {
    return `错误: ${validation.error}`;
  }

  // Check if path exists
  try {
    await fs.access(targetPath);
  } catch {
    return `错误: 路径不存在: ${targetPath}`;
  }

  // Find source files
  const files = await findSourceFiles(targetPath, language as SupportedLanguage | 'auto', undefined, maxFiles);
  if (files.length === 0) {
    return '未找到源代码文件';
  }

  // Analyze files
  const allVulnerabilities: Vulnerability[] = [];
  let processedFiles = 0;
  const errors: string[] = [];

  for (const file of files) {
    try {
      const content = await readFileContent(file);
      const detectedLang = language === 'auto' ? detectLanguage(file) : language as SupportedLanguage;

      // Get parser
      try {
        const parser = ParserFactory.getParser(detectedLang);
        const parseResult = await parser.parse(content, file);

        if (parseResult.success) {
          const vulns = detectVulnerabilities(parseResult, content, file, detectedLang);
          allVulnerabilities.push(...vulns);
        }
        processedFiles++;
      } catch {
        // Parser not available, use fallback
        const vulns = await fallbackDetection(file, content, detectedLang);
        allVulnerabilities.push(...vulns);
        processedFiles++;
      }
    } catch (error) {
      errors.push(`Failed to analyze ${file}: ${error}`);
    }
  }

  // Filter by mode
  let filteredVulns = allVulnerabilities;
  if (mode === 'quick') {
    filteredVulns = allVulnerabilities.filter(
      (v) => v.severity === 'critical' || v.severity === 'high'
    );
  }

  // Sort by severity
  const sortedVulns = sortVulnerabilities(filteredVulns);

  // Generate result
  const result = {
    targetPath,
    timestamp: new Date().toISOString(),
    mode,
    totalFiles: processedFiles,
    vulnerabilities: sortedVulns.slice(0, 100), // Limit output
  };

  const duration = Date.now() - startTime;

  // Generate report
  if (outputFormat === 'sarif') {
    return generateSarifJson(sortedVulns, 'code-audit-mcp-server', '2.0.0');
  }
  
  if (outputFormat === 'json') {
    const auditResult: AuditResult = {
      success: true,
      targetPath,
      timestamp: result.timestamp,
      mode: mode as 'quick' | 'standard' | 'deep',
      language: language as SupportedLanguage | 'auto',
      summary: {
        totalFiles: processedFiles,
        totalIssues: sortedVulns.length,
        critical: sortedVulns.filter((v) => v.severity === 'critical').length,
        high: sortedVulns.filter((v) => v.severity === 'high').length,
        medium: sortedVulns.filter((v) => v.severity === 'medium').length,
        low: sortedVulns.filter((v) => v.severity === 'low').length,
        info: sortedVulns.filter((v) => v.severity === 'info').length,
      },
      vulnerabilities: sortedVulns,
      errors,
      duration,
    };
    return JSON.stringify(auditResult, null, 2);
  }

  return generateReport(result, 'markdown') + `\n\n> 扫描耗时: ${formatDuration(duration)}`;
}

/**
 * Quick scan handler
 */
async function handleQuickScan(targetPath: string, language?: string): Promise<string> {
  return handleAuditScan(targetPath, {
    language,
    mode: 'quick',
    maxFiles: 100,
  });
}

/**
 * Single file analysis handler
 */
async function handleAnalyzeFile(filePath: string, language?: string): Promise<string> {
  const detectedLang = (language === 'auto' || !language) ? detectLanguage(filePath) : language as SupportedLanguage;

  try {
    await fs.access(filePath);
  } catch {
    return `错误: 文件不存在: ${filePath}`;
  }

  const content = await readFileContent(filePath);
  const lines = content.split('\n');

  let report = `# 文件分析报告\n\n`;
  report += `**文件**: ${filePath}\n`;
  report += `**语言**: ${detectedLang}\n`;
  report += `**行数**: ${lines.length}\n\n`;

  try {
    const parser = ParserFactory.getParser(detectedLang);
    const parseResult = await parser.parse(content, filePath);

    if (parseResult.success) {
      report += `## 结构分析\n\n`;
      report += `- **函数**: ${parseResult.functions.length}\n`;
      report += `- **类**: ${parseResult.classes.length}\n`;
      report += `- **导入**: ${parseResult.imports.length}\n`;
      report += `- **函数调用**: ${parseResult.calls.length}\n\n`;

      // List functions
      if (parseResult.functions.length > 0) {
        report += `### 函数列表\n\n`;
        for (const func of parseResult.functions.slice(0, 20)) {
          const relativePath = getRelativePath(process.cwd(), filePath);
          report += `- \`${func.name}\` (${relativePath}:${func.location.line})\n`;
        }
        if (parseResult.functions.length > 20) {
          report += `\n> ... 共 ${parseResult.functions.length} 个函数\n`;
        }
        report += '\n';
      }

      // List classes
      if (parseResult.classes.length > 0) {
        report += `### 类列表\n\n`;
        for (const cls of parseResult.classes) {
          report += `- \`${cls.name}\` (${getRelativePath(process.cwd(), filePath)}:${cls.location.line})\n`;
        }
        report += '\n';
      }

      // Detect vulnerabilities
      const vulns = detectVulnerabilities(parseResult, content, filePath, detectedLang);
      report += `## 安全问题\n\n`;
      report += `发现 **${vulns.length}** 个问题\n\n`;

      if (vulns.length > 0) {
        const sortedVulns = sortVulnerabilities(vulns);
        for (const vuln of sortedVulns.slice(0, 20)) {
          const emoji = severityToEmoji(vuln.severity);
          report += `### ${emoji} [${vuln.severity.toUpperCase()}] ${vuln.name}\n\n`;
          report += `**位置**: \`${getRelativePath(process.cwd(), filePath)}:${vuln.location.line}\`\n\n`;
          report += `**描述**: ${vuln.description}\n\n`;
          if (vuln.snippet) {
            report += `**代码片段**:\n\`\`\`${vuln.snippet.language}\n${vuln.snippet.code}\n\`\`\`\n\n`;
          }
          if (vuln.fixSuggestion) {
            report += `**修复建议**: ${vuln.fixSuggestion}\n\n`;
          }
          report += '---\n\n';
        }
      }
    } else {
      report += `解析失败: ${parseResult.errors.join(', ')}\n`;
    }
  } catch (error) {
    // Fallback to simple detection
    const vulns = await fallbackDetection(filePath, content, detectedLang);
    report += `## 安全问题\n\n`;
    report += `发现 **${vulns.length}** 个问题\n\n`;
    for (const vuln of vulns) {
      report += `- [${vuln.severity.toUpperCase()}] ${vuln.name} (行 ${vuln.location.line})\n`;
    }
  }

  return report;
}

/**
 * Build call graph handler
 */
async function handleBuildCallGraph(input: {
  targetPath: string;
  language: SupportedLanguage;
  maxDepth?: number;
}): Promise<string> {
  const { targetPath, language, maxDepth = 10 } = input;

  try {
    await fs.access(targetPath);
  } catch {
    return `错误: 路径不存在: ${targetPath}`;
  }

  const files = await findSourceFiles(targetPath, language, undefined, 100);
  if (files.length === 0) {
    return '未找到源代码文件';
  }

  const callGraph: CallGraph = {
    nodes: [],
    edges: [],
  };

  const functionMap = new Map<string, CallGraphNode>();

  for (const file of files) {
    try {
      const content = await readFileContent(file);
      const parser = ParserFactory.getParser(language);
      const parseResult = await parser.parse(content, file);

      if (parseResult.success) {
        // Add functions as nodes
        for (const func of parseResult.functions) {
          const node: CallGraphNode = {
            id: func.id,
            name: func.name,
            type: func.isMethod ? 'method' : 'function',
            file: getRelativePath(targetPath, file),
            line: func.location.line,
          };
          callGraph.nodes.push(node);
          functionMap.set(func.name, node);
        }

        // Add edges for calls
        for (const call of parseResult.calls) {
          const caller = parseResult.functions.find(
            (f) =>
              call.location.line >= f.location.line &&
              call.location.line <= (f.endLine || f.location.line)
          );

          if (caller && functionMap.has(call.name)) {
            callGraph.edges.push({
              from: caller.id,
              to: functionMap.get(call.name)!.id,
              location: call.location,
            });
          }
        }
      }
    } catch (error) {
      // Skip files that can't be parsed
    }
  }

  // Generate report
  let report = `# 调用图分析\n\n`;
  report += `- **分析路径**: ${targetPath}\n`;
  report += `- **语言**: ${language}\n`;
  report += `- **节点数**: ${callGraph.nodes.length}\n`;
  report += `- **边数**: ${callGraph.edges.length}\n\n`;

  report += `## 函数节点\n\n`;
  for (const node of callGraph.nodes.slice(0, 50)) {
    report += `- \`${node.name}\` (${node.file}:${node.line})\n`;
  }
  if (callGraph.nodes.length > 50) {
    report += `\n> ... 共 ${callGraph.nodes.length} 个节点\n`;
  }

  report += `\n## 调用关系\n\n`;
  report += '```mermaid\ngraph TD\n';
  for (const edge of callGraph.edges.slice(0, 100)) {
    const fromNode = callGraph.nodes.find((n) => n.id === edge.from);
    const toNode = callGraph.nodes.find((n) => n.id === edge.to);
    if (fromNode && toNode) {
      report += `    ${fromNode.name} --> ${toNode.name}\n`;
    }
  }
  report += '```\n';

  if (callGraph.edges.length > 100) {
    report += `\n> 仅显示前100条调用关系\n`;
  }

  return report;
}

/**
 * Data flow analysis handler
 */
async function handleAnalyzeDataFlow(input: {
  targetPath: string;
  language: SupportedLanguage;
  entryPoint?: string;
}): Promise<string> {
  const { targetPath, language, entryPoint } = input;

  try {
    await fs.access(targetPath);
  } catch {
    return `错误: 路径不存在: ${targetPath}`;
  }

  const files = await findSourceFiles(targetPath, language, undefined, 50);
  if (files.length === 0) {
    return '未找到源代码文件';
  }

  let report = `# 数据流分析\n\n`;
  report += `- **分析路径**: ${targetPath}\n`;
  report += `- **语言**: ${language}\n`;
  report += `- **入口点**: ${entryPoint || '自动检测'}\n\n`;

  // Track user input sources
  const sources: Array<{ file: string; line: number; source: string }> = [];
  const sinks: Array<{ file: string; line: number; sink: string }> = [];

  const userInputPatterns = [
    { pattern: /request\.(args|form|data|json)/i, name: 'HTTP请求参数' },
    { pattern: /req\.(query|body|params)/i, name: 'Express请求参数' },
    { pattern: /\$_GET|\$_POST|\$_REQUEST/i, name: 'PHP超全局变量' },
    { pattern: /input\s*\(/i, name: '用户输入函数' },
  ];

  const dangerousSinks = [
    { pattern: /eval\s*\(/i, name: 'eval()' },
    { pattern: /exec\s*\(/i, name: 'exec()' },
    { pattern: /system\s*\(/i, name: 'system()' },
    { pattern: /execute\s*\(/i, name: 'SQL执行' },
    { pattern: /innerHTML\s*=/i, name: 'innerHTML' },
  ];

  for (const file of files) {
    try {
      const content = await readFileContent(file);
      const lines = content.split('\n');

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        // Check for sources
        for (const { pattern, name } of userInputPatterns) {
          if (pattern.test(line)) {
            sources.push({
              file: getRelativePath(targetPath, file),
              line: i + 1,
              source: name,
            });
          }
          pattern.lastIndex = 0;
        }

        // Check for sinks
        for (const { pattern, name } of dangerousSinks) {
          if (pattern.test(line)) {
            sinks.push({
              file: getRelativePath(targetPath, file),
              line: i + 1,
              sink: name,
            });
          }
          pattern.lastIndex = 0;
        }
      }
    } catch (error) {
      // Skip files that can't be read
    }
  }

  report += `## 污点源 (用户输入)\n\n`;
  if (sources.length > 0) {
    for (const src of sources.slice(0, 20)) {
      report += `- ${src.source} - \`${src.file}:${src.line}\`\n`;
    }
    if (sources.length > 20) {
      report += `\n> ... 共 ${sources.length} 个污点源\n`;
    }
  } else {
    report += `未检测到用户输入源\n`;
  }

  report += `\n## 危险汇点 (敏感函数)\n\n`;
  if (sinks.length > 0) {
    for (const sink of sinks.slice(0, 20)) {
      report += `- ${sink.sink} - \`${sink.file}:${sink.line}\`\n`;
    }
    if (sinks.length > 20) {
      report += `\n> ... 共 ${sinks.length} 个危险汇点\n`;
    }
  } else {
    report += `未检测到危险函数调用\n`;
  }

  report += `\n## 数据流路径\n\n`;
  report += `> 数据流追踪需要更深入的AST分析，当前仅显示潜在的污点源和汇点。\n`;

  return report;
}

/**
 * Dependencies check handler
 */
async function handleCheckDependencies(input: { targetPath: string }): Promise<string> {
  const { targetPath } = input;

  try {
    await fs.access(targetPath);
  } catch {
    return `错误: 路径不存在: ${targetPath}`;
  }

  let report = `# 依赖安全检查\n\n`;
  report += `- **检查路径**: ${targetPath}\n\n`;

  const dependencyFiles = [
    'package.json',
    'requirements.txt',
    'Pipfile',
    'go.mod',
    'pom.xml',
    'build.gradle',
    'composer.json',
    'Cargo.toml',
  ];

  const foundFiles: string[] = [];

  for (const depFile of dependencyFiles) {
    try {
      const filePath = path.join(targetPath, depFile);
      await fs.access(filePath);
      foundFiles.push(depFile);
    } catch {
      // File doesn't exist
    }
  }

  if (foundFiles.length === 0) {
    report += `未找到依赖管理文件\n`;
    return report;
  }

  report += `## 发现的依赖文件\n\n`;
  for (const file of foundFiles) {
    report += `- \`${file}\`\n`;
  }

  report += `\n## 安全建议\n\n`;
  report += `1. 定期更新依赖到最新版本\n`;
  report += `2. 使用 \`npm audit\`、\`pip-audit\`、\`snyk\` 等工具检查已知漏洞\n`;
  report += `3. 移除未使用的依赖\n`;
  report += `4. 固定依赖版本以避免供应链攻击\n`;

  return report;
}

/**
 * Get exploitation guide handler
 */
function handleGetExploitationGuide(vulnerabilityType: string, language: SupportedLanguage): string {
  // Create a mock vulnerability for guide generation
  const mockVuln: Vulnerability = {
    id: 'mock',
    name: vulnerabilityType,
    description: `${vulnerabilityType}漏洞`,
    severity: 'high',
    location: { file: 'example', line: 1 },
    ruleId: vulnerabilityType,
    confidence: 1.0,
  };
  
  try {
    const guide = generateExploitationGuide(mockVuln, language);
    return formatGuideAsMarkdown(guide);
  } catch (error) {
    return `无法生成漏洞复现指南: ${error}`;
  }
}

/**
 * Fallback detection when parser is not available
 */
async function fallbackDetection(
  filePath: string,
  content: string,
  _language: SupportedLanguage
): Promise<Vulnerability[]> {
  const vulnerabilities: Vulnerability[] = [];
  const lines = content.split('\n');

  const patterns = [
    { pattern: /eval\s*\(/g, name: '代码注入风险', severity: 'critical' as Severity, description: '使用 eval() 可能导致代码注入' },
    { pattern: /exec\s*\(/g, name: '命令注入风险', severity: 'critical' as Severity, description: '使用 exec() 可能导致命令注入' },
    { pattern: /system\s*\(/g, name: '命令注入风险', severity: 'critical' as Severity, description: '使用 system() 可能导致命令注入' },
    { pattern: /innerHTML\s*=/g, name: 'XSS风险', severity: 'high' as Severity, description: '使用 innerHTML 可能导致 XSS' },
    { pattern: /document\.write/g, name: 'XSS风险', severity: 'high' as Severity, description: '使用 document.write 可能导致 XSS' },
    { pattern: /password\s*=\s*["'][^"']+["']/gi, name: '硬编码密码', severity: 'medium' as Severity, description: '检测到硬编码的密码' },
    { pattern: /api[_-]?key\s*=\s*["'][^"']+["']/gi, name: '硬编码API密钥', severity: 'medium' as Severity, description: '检测到硬编码的 API 密钥' },
  ];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const { pattern, name, severity, description } of patterns) {
      pattern.lastIndex = 0;
      if (pattern.test(line)) {
        vulnerabilities.push({
          id: `${name}_${filePath}_${i + 1}`.replace(/\s+/g, '_').toLowerCase(),
          name,
          description,
          severity,
          location: { file: filePath, line: i + 1 },
          ruleId: 'PATTERN_MATCH',
          confidence: 0.7,
        });
      }
    }
  }

  return vulnerabilities;
}

// ============================================================================
// MCP Server Handlers
// ============================================================================
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: TOOLS,
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const input = args || {};

  try {
    let result: string;

    switch (name) {
      case 'audit_scan':
        result = await handleAuditScan(input.targetPath as string, {
          language: input.language as string,
          mode: input.mode as string,
          maxFiles: input.maxFiles as number,
          outputFormat: input.outputFormat as string,
        });
        break;
      case 'audit_quick_scan':
        result = await handleQuickScan(input.targetPath as string, input.language as string);
        break;
      case 'audit_analyze_file':
        result = await handleAnalyzeFile(input.filePath as string, input.language as string);
        break;
      case 'build_call_graph':
        result = await handleBuildCallGraph({
          targetPath: input.targetPath as string,
          language: input.language as SupportedLanguage,
          maxDepth: input.maxDepth as number
        });
        break;
      case 'analyze_data_flow':
        result = await handleAnalyzeDataFlow({
          targetPath: input.targetPath as string,
          language: input.language as SupportedLanguage,
          entryPoint: input.entryPoint as string
        });
        break;
      case 'check_dependencies':
        result = await handleCheckDependencies(input as { targetPath: string });
        break;
      case 'get_exploitation_guide':
        result = handleGetExploitationGuide(
          input.vulnerabilityType as string,
          (input.language as SupportedLanguage) || 'python'
        );
        break;
      default:
        result = `未知工具: ${name}`;
    }

    return {
      content: [
        {
          type: 'text',
          text: result,
        },
      ],
    };
  } catch (error) {
    return {
      content: [
        {
          type: 'text',
          text: `错误: ${error instanceof Error ? error.message : String(error)}`,
        },
      ],
    };
  }
});

// ============================================================================
// Main
// ============================================================================
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('Code Audit MCP Server v2.0.0 running on stdio');
}

main().catch(console.error);
