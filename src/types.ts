/**
 * Code Audit MCP Server - Type Definitions
 */

// ============================================================================
// Language Types
// ============================================================================
export type SupportedLanguage = 'python' | 'javascript' | 'typescript' | 'go' | 'java' | 'php' | 'rust';

// ============================================================================
// Severity
// ============================================================================
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

// ============================================================================
// Location
// ============================================================================
export interface Location {
  file: string;
  line: number;
  column?: number;
  endLine?: number;
  endColumn?: number;
}

// ============================================================================
// AST Types
// ============================================================================
export interface ASTNode {
  id: string;
  type: 'function' | 'class' | 'variable' | 'call' | 'import' | 'export' | 'other';
  name?: string;
  language: SupportedLanguage;
  location: Location;
  children?: ASTNode[];
  parentId?: string;
  metadata?: Record<string, unknown>;
}

// ============================================================================
// Function Info
// ============================================================================
export interface Parameter {
  name: string;
  type?: string;
  defaultValue?: string;
  isOptional?: boolean;
  isVariadic?: boolean;
}

export interface FunctionInfo {
  id: string;
  name: string;
  location: Location;
  endLine?: number;
  parameters: Parameter[];
  returnType?: string;
  isAsync?: boolean;
  isExported?: boolean;
  isMethod?: boolean;
  className?: string;
  decorators?: string[];
  calls?: string[];
  calledBy?: string[];
  complexity?: number;
  documentation?: string;
}

// ============================================================================
// Class Info
// ============================================================================
export interface ClassInfo {
  id: string;
  name: string;
  location: Location;
  endLine?: number;
  parentClass?: string;
  interfaces?: string[];
  methods: string[];
  properties?: string[];
  decorators?: string[];
  documentation?: string;
}

// ============================================================================
// Vulnerability
// ============================================================================
export interface Vulnerability {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  location: Location;
  snippet?: CodeSnippet;
  ruleId: string;
  cwe?: string;
  owasp?: string;
  fixSuggestion?: string;
  fixCode?: string;
  confidence: number;
  callChain?: string[];
  references?: string[];
  tags?: string[];
}

// ============================================================================
// Code Snippet
// ============================================================================
export interface CodeSnippet {
  code: string;
  language: string;
  startLine: number;
  highlightedLines?: number[];
}

// ============================================================================
// Audit Result
// ============================================================================
export interface AuditResult {
  success: boolean;
  targetPath: string;
  timestamp: string;
  mode: 'quick' | 'standard' | 'deep';
  language: SupportedLanguage | 'auto';
  summary: {
    totalFiles: number;
    totalIssues: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  vulnerabilities: Vulnerability[];
  errors: string[];
  duration: number;
  metadata?: {
    projectType?: string;
    frameworks?: string[];
    dependencies?: Record<string, string>;
  };
}

// ============================================================================
// Parse Result
// ============================================================================
export interface ParseResult {
  success: boolean;
  ast?: ASTNode;
  functions: FunctionInfo[];
  classes: ClassInfo[];
  imports: ImportInfo[];
  exports: ExportInfo[];
  variables: VariableInfo[];
  calls: CallInfo[];
  errors: string[];
}

export interface ImportInfo {
  name: string;
  from: string;
  alias?: string;
  isDefault: boolean;
  isNamespace: boolean;
  location: Location;
}

export interface ExportInfo {
  name: string;
  type: 'function' | 'class' | 'variable' | 'default';
  location: Location;
}

export interface VariableInfo {
  name: string;
  type?: string;
  value?: string;
  isConstant: boolean;
  isExported: boolean;
  location: Location;
}

export interface CallInfo {
  name: string;
  callee: string;
  arguments: string[];
  location: Location;
  isAsync: boolean;
}

// ============================================================================
// Call Graph
// ============================================================================
export interface CallGraph {
  nodes: CallGraphNode[];
  edges: CallGraphEdge[];
}

export interface CallGraphNode {
  id: string;
  name: string;
  type: 'function' | 'method';
  file: string;
  line: number;
}

export interface CallGraphEdge {
  from: string;
  to: string;
  location?: Location;
}

// ============================================================================
// Data Flow
// ============================================================================
export interface DataFlowNode {
  id: string;
  type: 'source' | 'sink' | 'sanitizer' | 'intermediate';
  name: string;
  location: Location;
  taintSource?: string;
}

export interface DataFlowPath {
  source: DataFlowNode;
  sink: DataFlowNode;
  path: DataFlowNode[];
  isVulnerable: boolean;
}

// ============================================================================
// Rule Definition
// ============================================================================
export interface Rule {
  id: string;
  name: string;
  description: string;
  category: RuleCategory;
  severity: Severity;
  languages: SupportedLanguage[];
  cwe?: string;
  owasp?: string;
  enabled: boolean;
  tags: string[];
  patterns?: RulePattern[];
  customCheck?: string;
}

export type RuleCategory = 
  | 'injection'
  | 'xss'
  | 'ssrf'
  | 'crypto'
  | 'auth'
  | 'secrets'
  | 'deserialization'
  | 'path-traversal'
  | 'access-control'
  | 'other';

export interface RulePattern {
  pattern: string | RegExp;
  message?: string;
  confidence?: number;
}

// ============================================================================
// Report
// ============================================================================
export interface Report {
  header: string;
  summary: string;
  details: string;
  format: 'markdown' | 'json' | 'html' | 'sarif';
}

// ============================================================================
// MCP Tool Types
// ============================================================================
export interface AuditScanInput {
  targetPath: string;
  language?: SupportedLanguage | 'auto';
  mode?: 'quick' | 'standard' | 'deep';
  scope?: 'all' | 'security' | 'quality' | 'architecture';
  outputFormat?: 'markdown' | 'json' | 'html';
  maxFiles?: number;
  excludePatterns?: string[];
}

export interface AuditQuickScanInput {
  targetPath: string;
  language?: SupportedLanguage | 'auto';
}

export interface AuditAnalyzeFileInput {
  filePath: string;
  language?: SupportedLanguage;
}

export interface BuildCallGraphInput {
  targetPath: string;
  language: SupportedLanguage;
  maxDepth?: number;
}

export interface AnalyzeDataFlowInput {
  targetPath: string;
  language: SupportedLanguage;
  entryPoint?: string;
}

export interface AIDeepAuditInput {
  targetPath: string;
  language?: SupportedLanguage | 'auto';
  focus?: 'security' | 'quality' | 'architecture';
  context?: string;
}

// ============================================================================
// Detection Context
// ============================================================================
export interface DetectionContext {
  filePath: string;
  language: SupportedLanguage;
  content: string;
  ast?: ASTNode;
  functions: FunctionInfo[];
  imports: ImportInfo[];
}
