/**
 * Code Audit MCP Server - PHP AST Parser
 */

import { BaseParser, ParseResult, CallInfo } from './types';
import type { ASTNode, FunctionInfo, ClassInfo, Parameter } from '../types';

export class PHPParser extends BaseParser {
  readonly language = 'php';

  private patterns = {
    classDecl: /(?:abstract|final)?\s*class\s+(\w+)(?:\s+extends\s+(\w+))?(?:\s+implements\s+([\w,\s]+))?/g,
    functionDecl: /(?:public|private|protected)?\s*(?:static)?\s*function\s+(\w+)\s*\(([^)]*)\)/g,
    use: /use\s+([\w\\]+)(?:\s+as\s+(\w+))?;/g,
    call: /(\w+(?:->\w+)*(?:\(\))?(?:::\w+)?)\s*\(([^)]*)\)/g,
    variable: /\$(\w+)/g,
  };

  async parse(content: string, filePath: string): Promise<ParseResult> {
    const result: ParseResult = {
      success: true,
      functions: [],
      classes: [],
      imports: [],
      exports: [],
      variables: [],
      calls: [],
      errors: [],
    };

    try {
      const lines = content.split('\n');
      let currentClass: ClassInfo | null = null;

      for (let lineNum = 0; lineNum < lines.length; lineNum++) {
        const line = lines[lineNum];
        const trimmedLine = line.trim();

        if (!trimmedLine || trimmedLine.startsWith('//') || trimmedLine.startsWith('#') || trimmedLine.startsWith('/*')) {
          continue;
        }

        // Check for class declaration
        const classMatch = trimmedLine.match(this.patterns.classDecl);
        if (classMatch) {
          currentClass = this.createClassInfo(
            this.generateId('class'),
            classMatch[1],
            filePath,
            lineNum + 1,
            lineNum + 1,
            {
              parentClass: classMatch[2],
              interfaces: classMatch[3]?.split(',').map((s) => s.trim()),
              methods: [],
            }
          );
          result.classes.push(currentClass);
          continue;
        }

        // Check for function declaration
        const funcMatch = trimmedLine.match(this.patterns.functionDecl);
        if (funcMatch) {
          const name = funcMatch[1];
          const params = this.parseParameters(funcMatch[2] || '');

          const func = this.createFunctionInfo(
            this.generateId('func'),
            name,
            filePath,
            lineNum + 1,
            lineNum + 1,
            {
              parameters: params,
              isMethod: !!currentClass,
              className: currentClass?.name,
              isExported: name.startsWith('__') || trimmedLine.includes('public'),
            }
          );
          result.functions.push(func);

          if (currentClass) {
            currentClass.methods.push(func.id);
          }
          continue;
        }

        // Check for use statements
        const useMatch = trimmedLine.match(this.patterns.use);
        if (useMatch) {
          result.imports.push({
            name: useMatch[2] || useMatch[1].split('\\').pop() || useMatch[1],
            from: useMatch[1],
            alias: useMatch[2],
            isDefault: false,
            isNamespace: false,
            location: this.createLocation(filePath, lineNum + 1),
          });
          continue;
        }

        // Extract function calls
        const calls = this.extractCalls(trimmedLine, filePath, lineNum + 1);
        result.calls.push(...calls);
      }

      // Calculate end lines
      this.calculateEndLines(result.functions, lines);
      this.calculateEndLines(result.classes, lines);

      // Build AST
      result.ast = this.buildAST(content, filePath);
    } catch (error) {
      result.success = false;
      result.errors.push(`Parse error: ${error}`);
    }

    return result;
  }

  private parseParameters(paramsStr: string): Parameter[] {
    if (!paramsStr.trim()) return [];

    const params: Parameter[] = [];
    const parts = paramsStr.split(',');

    for (const part of parts) {
      const trimmed = part.trim();
      if (!trimmed) continue;

      // PHP params: Type $name = default
      const match = trimmed.match(/(?:([\w\\?]+)\s+)?\$(\w+)(?:\s*=\s*(.+))?/);
      if (match) {
        params.push({
          name: match[2],
          type: match[1],
          defaultValue: match[3]?.trim(),
          isOptional: !!match[3],
        });
      }
    }

    return params;
  }

  private extractCalls(line: string, filePath: string, lineNum: number): CallInfo[] {
    const calls: CallInfo[] = [];
    let match;

    this.patterns.call.lastIndex = 0;
    while ((match = this.patterns.call.exec(line)) !== null) {
      // Skip keywords
      const keywords = ['if', 'for', 'while', 'foreach', 'switch', 'function', 'class'];
      if (keywords.includes(match[1])) continue;

      calls.push({
        name: match[1],
        callee: match[1],
        arguments: match[2] ? match[2].split(',').map((s) => s.trim()) : [],
        location: this.createLocation(filePath, lineNum),
        isAsync: false,
      });
    }

    return calls;
  }

  private calculateEndLines(
    items: Array<{ location: { line: number }; endLine?: number }>,
    lines: string[]
  ): void {
    for (const item of items) {
      let braceCount = 0;
      let foundOpen = false;

      for (let j = item.location.line - 1; j < lines.length; j++) {
        const line = lines[j];
        for (const char of line) {
          if (char === '{') {
            braceCount++;
            foundOpen = true;
          } else if (char === '}') {
            braceCount--;
            if (foundOpen && braceCount === 0) {
              item.endLine = j + 1;
              break;
            }
          }
        }
        if (item.endLine) break;
      }

      if (!item.endLine) {
        item.endLine = lines.length;
      }
    }
  }

  private buildAST(content: string, filePath: string): ASTNode {
    const rootNode: ASTNode = {
      id: this.generateId('root'),
      type: 'other',
      language: 'php',
      location: this.createLocation(filePath, 1, 1),
      children: [],
    };

    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const trimmed = lines[i].trim();

      if (trimmed.includes('function ')) {
        rootNode.children?.push({
          id: this.generateId('function'),
          type: 'function',
          language: 'php',
          location: this.createLocation(filePath, i + 1),
        });
      } else if (trimmed.includes('class ')) {
        rootNode.children?.push({
          id: this.generateId('class'),
          type: 'class',
          language: 'php',
          location: this.createLocation(filePath, i + 1),
        });
      }
    }

    return rootNode;
  }
}
