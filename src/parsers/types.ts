/**
 * Code Audit MCP Server - AST Parser Types and Base Class
 */

import type {
  SupportedLanguage,
  ASTNode,
  FunctionInfo,
  ClassInfo,
  Location,
} from '../types';
import { generateId } from '../utils/helpers';

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
// Base Parser
// ============================================================================
export abstract class BaseParser {
  abstract readonly language: SupportedLanguage;
  abstract parse(content: string, filePath: string): Promise<ParseResult>;

  protected createLocation(
    file: string,
    line: number,
    column?: number,
    endLine?: number,
    endColumn?: number
  ): Location {
    return {
      file,
      line,
      column,
      endLine,
      endColumn,
    };
  }

  protected createFunctionInfo(
    id: string,
    name: string,
    file: string,
    startLine: number,
    endLine: number,
    options?: Partial<FunctionInfo>
  ): FunctionInfo {
    return {
      id,
      name,
      location: this.createLocation(file, startLine, undefined, endLine),
      parameters: [],
      endLine,
      ...options,
    };
  }

  protected createClassInfo(
    id: string,
    name: string,
    file: string,
    startLine: number,
    endLine: number,
    options?: Partial<ClassInfo>
  ): ClassInfo {
    return {
      id,
      name,
      location: this.createLocation(file, startLine, undefined, endLine),
      methods: [],
      endLine,
      ...options,
    };
  }

  protected generateId(prefix: string = ''): string {
    return prefix ? `${prefix}_${generateId()}` : generateId();
  }
}

// ============================================================================
// Parser Factory
// ============================================================================
import { PythonParser } from './python';
import { JavaScriptParser } from './javascript';
import { TypeScriptParser } from './typescript';
import { GoParser } from './go';
import { JavaParser } from './java';
import { PHPParser } from './php';

export class ParserFactory {
  private static parsers: Map<SupportedLanguage, BaseParser> = new Map();

  static getParser(language: SupportedLanguage): BaseParser {
    if (!this.parsers.has(language)) {
      switch (language) {
        case 'python':
          this.parsers.set(language, new PythonParser());
          break;
        case 'javascript':
          this.parsers.set(language, new JavaScriptParser());
          break;
        case 'typescript':
          this.parsers.set(language, new TypeScriptParser());
          break;
        case 'go':
          this.parsers.set(language, new GoParser());
          break;
        case 'java':
          this.parsers.set(language, new JavaParser());
          break;
        case 'php':
          this.parsers.set(language, new PHPParser());
          break;
        default:
          throw new Error(`Unsupported language: ${language}`);
      }
    }
    return this.parsers.get(language)!;
  }

  static getSupportedLanguages(): SupportedLanguage[] {
    return ['python', 'javascript', 'typescript', 'go', 'java', 'php'];
  }
}
