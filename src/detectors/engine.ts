/**
 * Code Audit MCP Server - Vulnerability Detection Engine
 */

import type {
  SupportedLanguage,
  Severity,
  Vulnerability,
  FunctionInfo,
  Location,
  DetectionContext,
} from '../types';
import type { ParseResult, CallInfo } from '../parsers/types';
import {
  DANGEROUS_FUNCTIONS,
  SQL_INJECTION_PATTERNS,
  XSS_PATTERNS,
  SSRF_PATTERNS,
  PATH_TRAVERSAL_PATTERNS,
  SENSITIVE_DATA_PATTERNS,
  WEAK_CRYPTO_PATTERNS,
  CWE_NAMES,
  USER_INPUT_SOURCES,
} from '../constants';
import {
  generateVulnerabilityId,
  extractCodeSnippetWithLanguage,
  getLineContent,
} from '../utils/helpers';

// ============================================================================
// Rule Definition
// ============================================================================
interface DetectionRule {
  id: string;
  name: string;
  description: string;
  category: string;
  severity: Severity;
  languages: SupportedLanguage[];
  cwe?: string;
  owasp?: string;
  enabled: boolean;
  tags: string[];
}

// ============================================================================
// Detection Engine
// ============================================================================
export class DetectionEngine {
  private rules: DetectionRule[];
  private language: SupportedLanguage;

  constructor(language: SupportedLanguage) {
    this.language = language;
    this.rules = this.loadDefaultRules();
  }

  /**
   * Run all detectors on parsed code
   */
  detect(
    parseResult: ParseResult,
    content: string,
    filePath: string
  ): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    // Create detection context
    const context: DetectionContext = {
      filePath,
      language: this.language,
      content,
      ast: parseResult.ast,
      functions: parseResult.functions,
      imports: parseResult.imports,
    };

    // Run each detector
    vulnerabilities.push(
      ...this.detectSQLInjection(context, parseResult, content)
    );
    vulnerabilities.push(
      ...this.detectCommandInjection(context, parseResult, content)
    );
    vulnerabilities.push(...this.detectXSS(context, parseResult, content));
    vulnerabilities.push(...this.detectSSRF(context, parseResult, content));
    vulnerabilities.push(
      ...this.detectPathTraversal(context, parseResult, content)
    );
    vulnerabilities.push(...this.detectHardcodedSecrets(context, content));
    vulnerabilities.push(
      ...this.detectWeakCryptography(context, parseResult, content)
    );
    vulnerabilities.push(
      ...this.detectDeserialization(context, parseResult, content)
    );
    vulnerabilities.push(
      ...this.detectDangerousFunctions(context, parseResult, content)
    );
    vulnerabilities.push(
      ...this.detectInsecureDependencies(context, parseResult)
    );
    vulnerabilities.push(...this.detectXXE(context, parseResult, content));
    vulnerabilities.push(...this.detectOpenRedirect(context, parseResult, content));

    // Remove duplicates
    return this.removeDuplicates(vulnerabilities);
  }

  // ============================================================================
  // SQL Injection Detection
  // ============================================================================
  private detectSQLInjection(
    context: DetectionContext,
    parseResult: ParseResult,
    content: string
  ): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const pattern of SQL_INJECTION_PATTERNS) {
        if (pattern.test(line)) {
          vulnerabilities.push(
            this.createVulnerability(
              'SQL_INJECTION',
              'SQL注入',
              '检测到潜在的SQL注入漏洞。用户输入可能直接拼接到SQL查询中。',
              'high',
              { file: context.filePath, line: i + 1 },
              context,
              content,
              'CWE-89',
              'A03:2021',
              this.getSQLInjectionFix(context.language)
            )
          );
        }
        // Reset regex
        pattern.lastIndex = 0;
      }
    }

    // Check for dangerous SQL function calls
    for (const call of parseResult.calls) {
      const sqlFunctions = ['execute', 'query', 'raw', 'exec', 'executescript'];
      if (sqlFunctions.some((f) => call.name.toLowerCase().includes(f))) {
        const line = lines[call.location.line - 1];
        if (
          line &&
          (line.includes('f"') ||
            line.includes("f'") ||
            line.includes('+') ||
            line.includes('${'))
        ) {
          if (
            !vulnerabilities.some((v) => v.location.line === call.location.line)
          ) {
            vulnerabilities.push(
              this.createVulnerability(
                'SQL_INJECTION_RISK',
                'SQL注入风险',
                '检测到潜在的SQL注入风险。请确认SQL查询是否使用了参数化查询。',
                'medium',
                call.location,
                context,
                content,
                'CWE-89',
                'A03:2021',
                this.getSQLInjectionFix(context.language)
              )
            );
          }
        }
      }
    }

    return vulnerabilities;
  }

  // ============================================================================
  // Command Injection Detection
  // ============================================================================
  private detectCommandInjection(
    context: DetectionContext,
    parseResult: ParseResult,
    content: string
  ): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const dangerousFuncs = DANGEROUS_FUNCTIONS[this.language] || [];
    const lines = content.split('\n');

    for (const call of parseResult.calls) {
      for (const dangerous of dangerousFuncs) {
        if (call.name.includes(dangerous) || call.callee === dangerous) {
          const line = lines[call.location.line - 1];
          const hasUserInput = this.checkUserInputPattern(line, context);
          const severity: Severity = hasUserInput ? 'critical' : 'high';

          vulnerabilities.push(
            this.createVulnerability(
              'COMMAND_INJECTION',
              '命令注入',
              `检测到潜在的系统命令执行函数 "${call.name}"。${
                hasUserInput ? '可能存在命令注入风险。' : '请确保输入经过严格验证。'
              }`,
              severity,
              call.location,
              context,
              content,
              'CWE-78',
              'A03:2021',
              this.getCommandInjectionFix(context.language)
            )
          );
        }
      }
    }

    return vulnerabilities;
  }

  // ============================================================================
  // XSS Detection
  // ============================================================================
  private detectXSS(
    context: DetectionContext,
    parseResult: ParseResult,
    content: string
  ): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const pattern of XSS_PATTERNS) {
        if (pattern.test(line)) {
          vulnerabilities.push(
            this.createVulnerability(
              'XSS',
              '跨站脚本攻击(XSS)',
              '检测到潜在的XSS漏洞。用户输入可能直接输出到HTML中。',
              'high',
              { file: context.filePath, line: i + 1 },
              context,
              content,
              'CWE-79',
              'A03:2021',
              this.getXSSFix(context.language)
            )
          );
        }
        pattern.lastIndex = 0;
      }
    }

    return vulnerabilities;
  }

  // ============================================================================
  // SSRF Detection
  // ============================================================================
  private detectSSRF(
    context: DetectionContext,
    parseResult: ParseResult,
    content: string
  ): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const pattern of SSRF_PATTERNS) {
        if (pattern.test(line)) {
          vulnerabilities.push(
            this.createVulnerability(
              'SSRF',
              '服务端请求伪造(SSRF)',
              '检测到潜在的SSRF漏洞。用户输入可能被用于发起服务端请求。',
              'high',
              { file: context.filePath, line: i + 1 },
              context,
              content,
              'CWE-918',
              'A10:2021',
              this.getSSRFFix(context.language)
            )
          );
        }
        pattern.lastIndex = 0;
      }
    }

    // Check for URL fetching functions with variable arguments
    const urlFunctions = [
      'fetch',
      'request',
      'get',
      'post',
      'urlopen',
      'http.Get',
      'axios',
    ];
    for (const call of parseResult.calls) {
      if (urlFunctions.some((f) => call.name.includes(f))) {
        const line = lines[call.location.line - 1];
        if (line && this.checkUserInputPattern(line, context)) {
          vulnerabilities.push(
            this.createVulnerability(
              'SSRF_RISK',
              'SSRF风险',
              '检测到URL请求函数可能使用了用户可控的URL参数。',
              'medium',
              call.location,
              context,
              content,
              'CWE-918',
              'A10:2021',
              this.getSSRFFix(context.language)
            )
          );
        }
      }
    }

    return vulnerabilities;
  }

  // ============================================================================
  // Path Traversal Detection
  // ============================================================================
  private detectPathTraversal(
    context: DetectionContext,
    parseResult: ParseResult,
    content: string
  ): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const pattern of PATH_TRAVERSAL_PATTERNS) {
        if (pattern.test(line)) {
          vulnerabilities.push(
            this.createVulnerability(
              'PATH_TRAVERSAL',
              '路径遍历',
              '检测到潜在的路径遍历漏洞。用户输入可能被用于文件路径操作。',
              'high',
              { file: context.filePath, line: i + 1 },
              context,
              content,
              'CWE-22',
              'A01:2021',
              this.getPathTraversalFix(context.language)
            )
          );
        }
        pattern.lastIndex = 0;
      }
    }

    // Check file operation functions
    const fileFunctions = [
      'open',
      'read',
      'write',
      'readFile',
      'writeFile',
      'file_get_contents',
      'fopen',
    ];
    for (const call of parseResult.calls) {
      if (
        fileFunctions.some((f) => call.name.toLowerCase().includes(f))
      ) {
        const line = lines[call.location.line - 1];
        if (line && this.checkUserInputPattern(line, context)) {
          vulnerabilities.push(
            this.createVulnerability(
              'PATH_TRAVERSAL_RISK',
              '路径遍历风险',
              '文件操作函数可能使用了用户可控的路径参数。',
              'medium',
              call.location,
              context,
              content,
              'CWE-22',
              'A01:2021',
              this.getPathTraversalFix(context.language)
            )
          );
        }
      }
    }

    return vulnerabilities;
  }

  // ============================================================================
  // Hardcoded Secrets Detection
  // ============================================================================
  private detectHardcodedSecrets(
    context: DetectionContext,
    content: string
  ): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const pattern of SENSITIVE_DATA_PATTERNS) {
        if (pattern.test(line)) {
          vulnerabilities.push(
            this.createVulnerability(
              'HARDCODED_SECRET',
              '硬编码敏感信息',
              '检测到潜在的硬编码敏感信息（密码、密钥等）。敏感信息应存储在环境变量或配置文件中。',
              'medium',
              { file: context.filePath, line: i + 1 },
              context,
              content,
              'CWE-798',
              'A07:2021',
              '将敏感信息移动到环境变量或安全的配置管理系统中。\n例如: const apiKey = process.env.API_KEY;'
            )
          );
        }
        pattern.lastIndex = 0;
      }
    }

    return vulnerabilities;
  }

  // ============================================================================
  // Weak Cryptography Detection
  // ============================================================================
  private detectWeakCryptography(
    context: DetectionContext,
    parseResult: ParseResult,
    content: string
  ): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const pattern of WEAK_CRYPTO_PATTERNS) {
        if (pattern.test(line)) {
          vulnerabilities.push(
            this.createVulnerability(
              'WEAK_CRYPTO',
              '弱加密算法',
              '检测到使用弱加密算法。建议使用更安全的加密方式如 SHA-256、AES-256-GCM。',
              'medium',
              { file: context.filePath, line: i + 1 },
              context,
              content,
              'CWE-327',
              'A02:2021',
              '使用强加密算法:\n- 哈希: SHA-256 或更高\n- 加密: AES-256-GCM\n- 密码: bcrypt, scrypt, Argon2'
            )
          );
        }
        pattern.lastIndex = 0;
      }
    }

    return vulnerabilities;
  }

  // ============================================================================
  // Deserialization Detection
  // ============================================================================
  private detectDeserialization(
    context: DetectionContext,
    parseResult: ParseResult,
    content: string
  ): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const dangerousDeser: Record<SupportedLanguage, string[]> = {
      python: ['pickle.loads', 'pickle.load', 'marshal.loads', 'yaml.load', 'yaml.unsafe_load'],
      javascript: ['eval', 'Function', 'vm.run'],
      typescript: ['eval', 'Function'],
      java: ['ObjectInputStream', 'XMLDecoder', 'Yaml.load'],
      php: ['unserialize'],
      go: ['gob.Decode'],
      rust: [],
    };

    const functions = dangerousDeser[this.language] || [];
    for (const call of parseResult.calls) {
      for (const dangerous of functions) {
        if (call.name.includes(dangerous) || call.callee === dangerous) {
          vulnerabilities.push(
            this.createVulnerability(
              'DESERIALIZATION',
              '不安全的反序列化',
              `检测到不安全的反序列化函数 "${call.name}"。可能导致远程代码执行。`,
              'critical',
              call.location,
              context,
              content,
              'CWE-502',
              'A08:2021',
              this.getDeserializationFix(context.language)
            )
          );
        }
      }
    }

    return vulnerabilities;
  }

  // ============================================================================
  // XXE Detection
  // ============================================================================
  private detectXXE(
    context: DetectionContext,
    parseResult: ParseResult,
    content: string
  ): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const lines = content.split('\n');

    const xxePatterns = [
      /XMLParser|lxml\.etree|xml\.etree|DocumentBuilder|SAXParser/gi,
      /parseXml|parseXML|loadXML|fromXML/gi,
    ];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const pattern of xxePatterns) {
        if (pattern.test(line)) {
          vulnerabilities.push(
            this.createVulnerability(
              'XXE',
              'XML外部实体注入(XXE)',
              '检测到XML解析操作。请确保禁用了外部实体解析。',
              'high',
              { file: context.filePath, line: i + 1 },
              context,
              content,
              'CWE-611',
              'A05:2021',
              '禁用外部实体解析:\n- Python: lxml.etree.XMLParser(resolve_entities=False)\n- Java: 设置 FEATURE_SECURE_PROCESSING\n- PHP: libxml_disable_entity_loader(true)'
            )
          );
        }
        pattern.lastIndex = 0;
      }
    }

    return vulnerabilities;
  }

  // ============================================================================
  // Open Redirect Detection
  // ============================================================================
  private detectOpenRedirect(
    context: DetectionContext,
    parseResult: ParseResult,
    content: string
  ): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const lines = content.split('\n');

    const redirectPatterns = [
      /redirect\s*\(\s*[^"']*request/i,
      /redirect\s*\(\s*[^"']*\+/i,
      /header\s*\(\s*['"]?Location['"]?\s*:\s*[^"']*request/i,
      /response\.redirect\s*\(\s*[^"']*request/i,
    ];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const pattern of redirectPatterns) {
        if (pattern.test(line)) {
          vulnerabilities.push(
            this.createVulnerability(
              'OPEN_REDIRECT',
              '开放重定向',
              '检测到潜在的开放重定向漏洞。用户输入可能被用于重定向URL。',
              'medium',
              { file: context.filePath, line: i + 1 },
              context,
              content,
              'CWE-601',
              'A01:2021',
              '验证重定向URL:\n- 使用允许列表验证目标URL\n- 只允许相对路径重定向\n- 验证URL是否属于受信任的域名'
            )
          );
        }
        pattern.lastIndex = 0;
      }
    }

    return vulnerabilities;
  }

  // ============================================================================
  // Dangerous Functions Detection
  // ============================================================================
  private detectDangerousFunctions(
    context: DetectionContext,
    parseResult: ParseResult,
    content: string
  ): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const dangerousFuncs = DANGEROUS_FUNCTIONS[this.language] || [];

    for (const call of parseResult.calls) {
      for (const dangerous of dangerousFuncs) {
        if (call.name.includes(dangerous) || call.callee === dangerous) {
          // Skip if already reported as command injection
          if (
            vulnerabilities.some(
              (v) =>
                v.location.line === call.location.line &&
                v.name.includes(dangerous)
            )
          ) {
            continue;
          }

          const severity = this.getDangerLevel(dangerous);
          vulnerabilities.push(
            this.createVulnerability(
              'DANGEROUS_FUNCTION',
              '危险函数调用',
              `检测到危险函数 "${call.name}" 的调用。请确保输入经过严格验证和清理。`,
              severity,
              call.location,
              context,
              content,
              undefined,
              undefined,
              '确保对所有输入进行验证和清理。考虑使用更安全的替代方案。'
            )
          );
        }
      }
    }

    return vulnerabilities;
  }

  // ============================================================================
  // Insecure Dependencies Detection
  // ============================================================================
  private detectInsecureDependencies(
    context: DetectionContext,
    parseResult: ParseResult
  ): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    const insecurePackages: Record<SupportedLanguage, string[]> = {
      python: ['pickle', 'marshal', 'subprocess', 'os.system', 'eval'],
      javascript: ['eval', 'child_process', 'vm'],
      typescript: ['eval', 'child_process', 'vm'],
      java: [],
      go: [],
      php: [],
      rust: [],
    };

    const packages = insecurePackages[this.language] || [];
    for (const imp of parseResult.imports) {
      for (const pkg of packages) {
        if (imp.from.includes(pkg) || imp.name === pkg) {
          vulnerabilities.push({
            id: generateVulnerabilityId('INSECURE_DEPENDENCY', imp.location),
            name: '不安全的依赖',
            description: `检测到引入可能存在安全风险的依赖 "${imp.from}"。`,
            severity: 'low',
            location: imp.location,
            ruleId: 'INSECURE_DEPENDENCY',
            confidence: 0.6,
            fixSuggestion: '评估是否真正需要此依赖，或寻找更安全的替代方案。',
          });
        }
      }
    }

    return vulnerabilities;
  }

  // ============================================================================
  // Helper Methods
  // ============================================================================
  private createVulnerability(
    ruleId: string,
    name: string,
    description: string,
    severity: Severity,
    location: Location,
    context: DetectionContext,
    content: string,
    cwe?: string,
    owasp?: string,
    fixSuggestion?: string
  ): Vulnerability {
    const id = generateVulnerabilityId(ruleId, location);
    const snippet = content
      ? extractCodeSnippetWithLanguage(content, location.line, context.language, 3)
      : undefined;

    return {
      id,
      name,
      description,
      severity,
      location,
      snippet,
      ruleId,
      cwe: cwe ? `${cwe}: ${CWE_NAMES[cwe] || ''}` : undefined,
      owasp,
      fixSuggestion,
      confidence: 0.8,
    };
  }

  private checkUserInputPattern(line: string, context: DetectionContext): boolean {
    const patterns = USER_INPUT_SOURCES[context.language] || [];
    return patterns.some((p) => p.test(line));
  }

  private getDangerLevel(funcName: string): Severity {
    const critical = ['eval', 'exec', 'system', 'popen', 'pickle.loads'];
    const high = ['subprocess', 'spawn', 'shell_exec', 'passthru'];

    if (critical.some((c) => funcName.includes(c))) return 'critical';
    if (high.some((h) => funcName.includes(h))) return 'high';
    return 'medium';
  }

  private loadDefaultRules(): DetectionRule[] {
    return [
      {
        id: 'SQL_INJECTION',
        name: 'SQL注入',
        description: '检测SQL注入漏洞',
        category: 'injection',
        severity: 'high',
        languages: ['python', 'javascript', 'typescript', 'go', 'java', 'php'],
        cwe: 'CWE-89',
        owasp: 'A03:2021',
        enabled: true,
        tags: ['injection', 'sql', 'database'],
      },
      {
        id: 'COMMAND_INJECTION',
        name: '命令注入',
        description: '检测命令注入漏洞',
        category: 'injection',
        severity: 'critical',
        languages: ['python', 'javascript', 'typescript', 'go', 'java', 'php'],
        cwe: 'CWE-78',
        owasp: 'A03:2021',
        enabled: true,
        tags: ['injection', 'command', 'rce'],
      },
      {
        id: 'XSS',
        name: '跨站脚本攻击',
        description: '检测XSS漏洞',
        category: 'xss',
        severity: 'high',
        languages: ['javascript', 'typescript', 'python', 'php'],
        cwe: 'CWE-79',
        owasp: 'A03:2021',
        enabled: true,
        tags: ['xss', 'injection', 'web'],
      },
    ];
  }

  private removeDuplicates(vulnerabilities: Vulnerability[]): Vulnerability[] {
    const seen = new Set<string>();
    return vulnerabilities.filter((v) => {
      const key = `${v.ruleId}:${v.location.file}:${v.location.line}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  // Fix suggestions
  private getSQLInjectionFix(lang: SupportedLanguage): string {
    const fixes: Record<SupportedLanguage, string> = {
      python: '使用参数化查询:\ncursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
      javascript: '使用参数化查询或ORM:\ndb.query("SELECT * FROM users WHERE id = $1", [userId])',
      typescript: '使用参数化查询或ORM:\ndb.query("SELECT * FROM users WHERE id = $1", [userId])',
      go: '使用参数化查询:\ndb.Query("SELECT * FROM users WHERE id = $1", userID)',
      java: '使用PreparedStatement:\nPreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");\nstmt.setString(1, userId);',
      php: '使用预处理语句:\n$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");\n$stmt->execute([$userId]);',
      rust: '使用参数化查询',
    };
    return fixes[lang] || '使用参数化查询，避免字符串拼接SQL';
  }

  private getCommandInjectionFix(lang: SupportedLanguage): string {
    return (
      '避免直接执行用户输入。使用参数数组而不是字符串拼接:\n' +
      '- 使用 subprocess.run(["cmd", arg1, arg2]) 而不是 os.system(f"cmd {arg}")\n' +
      '- 使用允许列表验证输入\n' +
      '- 转义特殊字符'
    );
  }

  private getXSSFix(_lang: SupportedLanguage): string {
    return (
      '对用户输入进行HTML编码:\n' +
      '- 使用模板引擎的自动转义功能\n' +
      '- 使用 textContent 而不是 innerHTML\n' +
      '- 使用 DOMPurify 等库清理HTML'
    );
  }

  private getSSRFFix(_lang: SupportedLanguage): string {
    return (
      '防止SSRF:\n' +
      '- 使用允许列表验证URL\n' +
      '- 禁止访问私有IP地址\n' +
      '- 限制协议（只允许 http/https）\n' +
      '- 使用网络隔离'
    );
  }

  private getPathTraversalFix(_lang: SupportedLanguage): string {
    return (
      '防止路径遍历:\n' +
      '- 使用 basename() 或类似函数处理文件名\n' +
      '- 规范化路径并验证是否在允许目录内\n' +
      '- 使用允许列表验证文件名\n' +
      '- 避免使用用户输入构建文件路径'
    );
  }

  private getDeserializationFix(lang: SupportedLanguage): string {
    const fixes: Record<SupportedLanguage, string> = {
      python: '避免使用 pickle/marshal 反序列化不受信任的数据。\n使用 JSON 或其他安全格式:\nimport json\ndata = json.loads(json_string)',
      javascript: '避免使用 eval() 或 Function() 处理用户输入。\n使用 JSON.parse():\nconst data = JSON.parse(jsonString)',
      typescript: '避免使用 eval() 或 Function() 处理用户输入。\n使用 JSON.parse():\nconst data = JSON.parse(jsonString)',
      java: '避免使用 ObjectInputStream 反序列化不受信任的数据。\n使用 JSON 或其他安全格式。',
      php: '避免使用 unserialize() 处理用户输入。\n使用 json_decode():\n$data = json_decode($jsonString, true);',
      go: '使用 JSON 或其他安全格式进行序列化。',
      rust: '使用安全的序列化库如 serde_json。',
    };
    return fixes[lang] || '避免反序列化不受信任的数据';
  }
}

// ============================================================================
// Export
// ============================================================================
export function detectVulnerabilities(
  parseResult: ParseResult,
  content: string,
  filePath: string,
  language: SupportedLanguage
): Vulnerability[] {
  const engine = new DetectionEngine(language);
  return engine.detect(parseResult, content, filePath);
}
