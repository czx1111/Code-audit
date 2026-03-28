/**
 * Code Audit MCP Server - Constants
 */

import type { SupportedLanguage, Severity } from './types';

// ============================================================================
// File Patterns
// ============================================================================
export const FILE_EXTENSIONS: Record<SupportedLanguage, string[]> = {
  python: ['.py', '.pyi', '.pyw'],
  javascript: ['.js', '.jsx', '.mjs', '.cjs'],
  typescript: ['.ts', '.tsx'],
  go: ['.go'],
  java: ['.java'],
  php: ['.php', '.phtml', '.php3', '.php4', '.php5'],
  rust: ['.rs'],
};

export const DEFAULT_EXCLUDE_PATTERNS = [
  '**/node_modules/**',
  '**/.git/**',
  '**/dist/**',
  '**/build/**',
  '**/__pycache__/**',
  '**/.venv/**',
  '**/venv/**',
  '**/vendor/**',
  '**/.idea/**',
  '**/.vscode/**',
  '**/*.min.js',
  '**/*.min.css',
  '**/package-lock.json',
  '**/yarn.lock',
  '**/pnpm-lock.yaml',
];

// ============================================================================
// Vulnerability Patterns
// ============================================================================
export const DANGEROUS_FUNCTIONS: Record<SupportedLanguage, string[]> = {
  python: [
    'eval', 'exec', 'execfile', 'compile',
    'os.system', 'os.popen',
    'subprocess.call', 'subprocess.run', 'subprocess.Popen',
    'pickle.loads', 'pickle.load',
    'marshal.loads',
    'yaml.load', 'yaml.unsafe_load',
    'shelve.open',
  ],
  javascript: [
    'eval', 'Function',
    'setTimeout', 'setInterval',
    'exec', 'execSync', 'spawn', 'spawnSync',
    'execFile', 'execFileSync',
  ],
  typescript: [
    'eval', 'Function',
    'setTimeout', 'setInterval',
    'exec', 'execSync', 'spawn', 'spawnSync',
  ],
  go: [
    'exec.Command', 'exec.CommandContext',
    'os.executable',
  ],
  java: [
    'Runtime.exec', 'ProcessBuilder',
    'ScriptEngine.eval',
    'Class.forName', 'ClassLoader.loadClass',
  ],
  php: [
    'eval', 'exec', 'shell_exec', 'system', 'passthru',
    'popen', 'proc_open', 'pcntl_exec',
    'assert', 'create_function', 'preg_replace',
    'unserialize',
  ],
  rust: [
    'std::process::Command::new',
  ],
};

export const SQL_INJECTION_PATTERNS: RegExp[] = [
  /f["'].*SELECT.*\{/,
  /f["'].*INSERT.*\{/,
  /f["'].*UPDATE.*\{/,
  /f["'].*DELETE.*\{/,
  /String\.format.*SELECT/i,
  /String\.format.*INSERT/i,
  /String\.format.*UPDATE/i,
  /String\.format.*DELETE/i,
  /\+\s*["'].*SELECT/i,
  /\+\s*["'].*INSERT/i,
  /\+\s*["'].*UPDATE/i,
  /\+\s*["'].*DELETE/i,
  /executeQuery\s*\(\s*[^"]*\+/,
  /query\s*\(\s*f["']/,
];

export const XSS_PATTERNS: RegExp[] = [
  /innerHTML\s*=/,
  /outerHTML\s*=/,
  /document\.write\s*\(/,
  /\.html\s*\(\s*[^$]/,
  /dangerouslySetInnerHTML/,
  /v-html\s*=/,
  /\[\(html\)\]/,
];

export const SSRF_PATTERNS: RegExp[] = [
  /requests\.get\s*\(\s*[^"']/,
  /requests\.post\s*\(\s*[^"']/,
  /urllib\.request\.urlopen\s*\(\s*[^"']/,
  /http\.Get\s*\(\s*[^"']/,
  /http\.Post\s*\(\s*[^"']/,
  /fetch\s*\(\s*[^"']/,
  /axios\.(get|post|put|delete)\s*\(\s*[^"']/,
  /curl_exec/,
  /file_get_contents\s*\(\s*\$/,
];

export const PATH_TRAVERSAL_PATTERNS: RegExp[] = [
  /open\s*\(\s*[^"']*request/,
  /open\s*\(\s*[^"']*\+/,
  /readFile\s*\(\s*[^"']*req/,
  /readFile\s*\(\s*[^"']*\+/,
  /fs\.readFileSync\s*\(\s*[^"']*req/,
  /os\.Open\s*\(\s*[^"']*\+/,
  /new\s+File\s*\(\s*[^"']*request/,
  /new\s+File\s*\(\s*[^"']*\+/,
];

export const SENSITIVE_DATA_PATTERNS: RegExp[] = [
  /password\s*[=:]\s*["'][^"']+["']/i,
  /api[_-]?key\s*[=:]\s*["'][^"']+["']/i,
  /secret[_-]?key\s*[=:]\s*["'][^"']+["']/i,
  /access[_-]?token\s*[=:]\s*["'][^"']+["']/i,
  /private[_-]?key\s*[=:]\s*["'][^"']+["']/i,
  /aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["'][^"']+["']/i,
  /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/,
];

export const WEAK_CRYPTO_PATTERNS: RegExp[] = [
  /MD5\s*\(/,
  /SHA1\s*\(/,
  /md5\s*\(/,
  /sha1\s*\(/,
  /DES\s*\(/,
  /des_encrypt/,
  /hashlib\.md5\s*\(/,
  /hashlib\.sha1\s*\(/,
  /Crypto\.Cipher\.DES/,
  /ECB/i,
];

// ============================================================================
// CWE/OWASP Mappings
// ============================================================================
export const CWE_NAMES: Record<string, string> = {
  'CWE-79': 'Cross-site Scripting (XSS)',
  'CWE-89': 'SQL Injection',
  'CWE-78': 'OS Command Injection',
  'CWE-20': 'Improper Input Validation',
  'CWE-200': 'Exposure of Sensitive Information',
  'CWE-22': 'Path Traversal',
  'CWE-787': 'Out-of-bounds Write',
  'CWE-125': 'Out-of-bounds Read',
  'CWE-352': 'Cross-Site Request Forgery (CSRF)',
  'CWE-287': 'Improper Authentication',
  'CWE-862': 'Missing Authorization',
  'CWE-269': 'Improper Privilege Management',
  'CWE-327': 'Use of Broken or Risky Cryptographic Algorithm',
  'CWE-798': 'Use of Hard-coded Credentials',
  'CWE-502': 'Deserialization of Untrusted Data',
  'CWE-611': 'XML External Entity (XXE)',
  'CWE-918': 'Server-Side Request Forgery (SSRF)',
  'CWE-90': 'LDAP Injection',
  'CWE-91': 'XML Injection',
  'CWE-94': 'Code Injection',
  'CWE-95': 'Eval Injection',
  'CWE-639': 'Authorization Bypass Through User-Controlled Key',
  'CWE-384': 'Session Fixation',
  'CWE-306': 'Missing Authentication for Critical Function',
  'CWE-863': 'Incorrect Authorization',
  'CWE-250': 'Execution with Unnecessary Privileges',
  'CWE-732': 'Incorrect Permission Assignment',
  'CWE-312': 'Cleartext Storage of Sensitive Information',
  'CWE-319': 'Cleartext Transmission of Sensitive Information',
  'CWE-117': 'Improper Output Neutralization for Logs',
  'CWE-917': 'Expression Language Injection',
  'CWE-1004': 'Sensitive Cookie Without HttpOnly Flag',
  'CWE-614': 'Sensitive Cookie in HTTPS Session Without Secure Attribute',
};

export const OWASP_TOP_10_2021: Record<string, { name: string; cwes: string[] }> = {
  'A01:2021': {
    name: 'Broken Access Control',
    cwes: ['CWE-22', 'CWE-23', 'CWE-35', 'CWE-59', 'CWE-200', 'CWE-201', 'CWE-219', 'CWE-264', 'CWE-269', 'CWE-285', 'CWE-286', 'CWE-287', 'CWE-352', 'CWE-359', 'CWE-377', 'CWE-402', 'CWE-425', 'CWE-441', 'CWE-497', 'CWE-538', 'CWE-540', 'CWE-548', 'CWE-552', 'CWE-566', 'CWE-601', 'CWE-639', 'CWE-651', 'CWE-668', 'CWE-706', 'CWE-862', 'CWE-863', 'CWE-913', 'CWE-922', 'CWE-1275'],
  },
  'A02:2021': {
    name: 'Cryptographic Failures',
    cwes: ['CWE-261', 'CWE-296', 'CWE-310', 'CWE-319', 'CWE-321', 'CWE-322', 'CWE-323', 'CWE-324', 'CWE-325', 'CWE-326', 'CWE-327', 'CWE-328', 'CWE-329', 'CWE-330', 'CWE-331', 'CWE-335', 'CWE-336', 'CWE-337', 'CWE-338', 'CWE-340', 'CWE-347', 'CWE-523', 'CWE-720', 'CWE-757', 'CWE-759', 'CWE-760', 'CWE-780', 'CWE-818', 'CWE-916'],
  },
  'A03:2021': {
    name: 'Injection',
    cwes: ['CWE-20', 'CWE-74', 'CWE-75', 'CWE-77', 'CWE-78', 'CWE-79', 'CWE-80', 'CWE-83', 'CWE-87', 'CWE-88', 'CWE-89', 'CWE-90', 'CWE-91', 'CWE-93', 'CWE-94', 'CWE-95', 'CWE-96', 'CWE-97', 'CWE-98', 'CWE-99', 'CWE-100', 'CWE-113', 'CWE-116', 'CWE-138', 'CWE-184', 'CWE-470', 'CWE-471', 'CWE-564', 'CWE-610', 'CWE-643', 'CWE-644', 'CWE-652', 'CWE-917'],
  },
  'A04:2021': {
    name: 'Insecure Design',
    cwes: ['CWE-73', 'CWE-183', 'CWE-209', 'CWE-213', 'CWE-235', 'CWE-256', 'CWE-257', 'CWE-266', 'CWE-269', 'CWE-280', 'CWE-311', 'CWE-312', 'CWE-313', 'CWE-316', 'CWE-419', 'CWE-430', 'CWE-434', 'CWE-444', 'CWE-451', 'CWE-472', 'CWE-501', 'CWE-522', 'CWE-525', 'CWE-539', 'CWE-579', 'CWE-598', 'CWE-602', 'CWE-642', 'CWE-646', 'CWE-650', 'CWE-653', 'CWE-656', 'CWE-657', 'CWE-799', 'CWE-807', 'CWE-840', 'CWE-841', 'CWE-927', 'CWE-1021', 'CWE-1173'],
  },
  'A05:2021': {
    name: 'Security Misconfiguration',
    cwes: ['CWE-2', 'CWE-5', 'CWE-6', 'CWE-7', 'CWE-10', 'CWE-13', 'CWE-15', 'CWE-16', 'CWE-260', 'CWE-315', 'CWE-520', 'CWE-526', 'CWE-537', 'CWE-541', 'CWE-547', 'CWE-611', 'CWE-754', 'CWE-779', 'CWE-782', 'CWE-784', 'CWE-800', 'CWE-805', 'CWE-806', 'CWE-811', 'CWE-813', 'CWE-852', 'CWE-915', 'CWE-942', 'CWE-945', 'CWE-1004', 'CWE-1032', 'CWE-1062', 'CWE-1174'],
  },
  'A06:2021': {
    name: 'Vulnerable and Outdated Components',
    cwes: ['CWE-937', 'CWE-1035', 'CWE-1104'],
  },
  'A07:2021': {
    name: 'Identification and Authentication Failures',
    cwes: ['CWE-79', 'CWE-261', 'CWE-287', 'CWE-288', 'CWE-290', 'CWE-294', 'CWE-295', 'CWE-297', 'CWE-300', 'CWE-302', 'CWE-304', 'CWE-307', 'CWE-346', 'CWE-384', 'CWE-522', 'CWE-613', 'CWE-620', 'CWE-640', 'CWE-798', 'CWE-804', 'CWE-940', 'CWE-1216'],
  },
  'A08:2021': {
    name: 'Software and Data Integrity Failures',
    cwes: ['CWE-345', 'CWE-353', 'CWE-426', 'CWE-494', 'CWE-502', 'CWE-565', 'CWE-784', 'CWE-829', 'CWE-830', 'CWE-913', 'CWE-1031'],
  },
  'A09:2021': {
    name: 'Security Logging and Monitoring Failures',
    cwes: ['CWE-117', 'CWE-223', 'CWE-532', 'CWE-778'],
  },
  'A10:2021': {
    name: 'Server-Side Request Forgery (SSRF)',
    cwes: ['CWE-918'],
  },
};

// ============================================================================
// Sensitive Sinks
// ============================================================================
export const SENSITIVE_SINKS: Record<SupportedLanguage, Record<string, string[]>> = {
  python: {
    sql: ['execute', 'executemany', 'executescript', 'raw', 'RawSQL'],
    command: ['system', 'popen', 'spawn', 'call', 'run', 'Popen'],
    file: ['open', 'read', 'write', 'read_file', 'write_file'],
    network: ['urlopen', 'request', 'get', 'post', 'Request'],
    deserialization: ['loads', 'load', 'yaml.load', 'pickle.loads'],
  },
  javascript: {
    sql: ['query', 'execute', 'raw', 'sql'],
    command: ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile'],
    file: ['readFile', 'writeFile', 'open', 'createWriteStream', 'createReadStream'],
    network: ['fetch', 'request', 'get', 'post', 'axios'],
    deserialization: ['parse', 'decode', 'unserialize'],
  },
  typescript: {
    sql: ['query', 'execute', 'raw', 'sql'],
    command: ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile'],
    file: ['readFile', 'writeFile', 'open', 'createWriteStream', 'createReadStream'],
    network: ['fetch', 'request', 'get', 'post', 'axios'],
    deserialization: ['parse', 'decode', 'unserialize'],
  },
  go: {
    sql: ['Query', 'QueryRow', 'Exec', 'Prepare'],
    command: ['Command', 'CommandContext'],
    file: ['Open', 'Create', 'ReadFile', 'WriteFile'],
    network: ['Get', 'Post', 'Do', 'NewRequest'],
    deserialization: ['Unmarshal', 'Decode'],
  },
  java: {
    sql: ['executeQuery', 'executeUpdate', 'execute', 'prepareStatement'],
    command: ['exec', 'Runtime.exec', 'ProcessBuilder.command'],
    file: ['FileInputStream', 'FileOutputStream', 'FileReader', 'FileWriter', 'Files.read'],
    network: ['openConnection', 'getInputStream', 'URL'],
    deserialization: ['readObject', 'readUnshared', 'XMLDecoder.readObject'],
  },
  php: {
    sql: ['query', 'exec', 'prepare', 'execute'],
    command: ['exec', 'shell_exec', 'system', 'passthru', 'popen', 'proc_open'],
    file: ['fopen', 'file_get_contents', 'file_put_contents', 'readfile', 'include', 'require'],
    network: ['file_get_contents', 'curl_exec', 'fsockopen', 'stream_socket_client'],
    deserialization: ['unserialize'],
  },
  rust: {
    sql: [],
    command: [],
    file: [],
    network: [],
    deserialization: [],
  },
};

// ============================================================================
// User Input Sources
// ============================================================================
export const USER_INPUT_SOURCES: Record<SupportedLanguage, RegExp[]> = {
  python: [
    /request\.(args|form|data|json|values)\.get\s*\(/i,
    /request\.(GET|POST)\[/i,
    /\$_GET/i,
    /\$_POST/i,
    /input\s*\(/i,
    /sys\.argv/i,
    /os\.environ/i,
  ],
  javascript: [
    /req\.(query|body|params|headers)/i,
    /request\.(query|body|params)/i,
    /\.value\s*\(/i,
    /process\.argv/i,
    /prompt\s*\(/i,
  ],
  typescript: [
    /req\.(query|body|params|headers)/i,
    /request\.(query|body|params)/i,
    /\.value\s*\(/i,
    /process\.argv/i,
  ],
  go: [
    /r\.FormValue/i,
    /r\.URL\.Query/i,
    /r\.PostForm/i,
    /os\.Getenv/i,
  ],
  java: [
    /request\.getParameter/i,
    /request\.getHeader/i,
    /@RequestParam/i,
    /@PathVariable/i,
    /System\.getenv/i,
  ],
  php: [
    /\$_GET/i,
    /\$_POST/i,
    /\$_REQUEST/i,
    /\$_COOKIE/i,
    /\$_FILES/i,
    /file_get_contents\s*\(\s*['"]php:\/\/input/i,
  ],
  rust: [
    /std::env::args/i,
    /std::env::var/i,
  ],
};

// ============================================================================
// Limits and Thresholds
// ============================================================================
export const MAX_FILE_SIZE = 1024 * 1024; // 1MB
export const MAX_FILES_DEFAULT = 1000;
export const MAX_DEPTH = 20;
export const MAX_RESULTS = 10000;
export const TIMEOUT_MS = 300000; // 5 minutes

// ============================================================================
// Report Templates
// ============================================================================
export const REPORT_HEADER = `# 代码安全审计报告

## 概要
- **扫描路径**: {targetPath}
- **扫描时间**: {timestamp}
- **扫描模式**: {mode}
- **总文件数**: {totalFiles}
- **发现问题**: {totalIssues}

## 统计
| 严重级别 | 数量 |
|---------|------|
| 🔴 Critical | {critical} |
| 🟠 High | {high} |
| 🟡 Medium | {medium} |
| 🟢 Low | {low} |
| 🔵 Info | {info} |

## 详细问题

`;

export const VULNERABILITY_TEMPLATE = `### [{severity}] {name} - {file}:{line}

**描述**: {description}

**代码位置**: \`{file}:{line}\`

**代码片段**:
\`\`\`{language}
{code}
\`\`\`

**修复建议**:
{fixSuggestion}

**调用链**: {callChain}

**CWE**: {cwe}
**OWASP**: {owasp}

---

`;
