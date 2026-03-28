/**
 * Code Audit MCP Server - JavaScript AST Parser
 */

import { BaseParser, ParseResult, ImportInfo, CallInfo } from './types';
import type { ASTNode, FunctionInfo, ClassInfo, Parameter } from '../types';

export class JavaScriptParser extends BaseParser {
  readonly language: 'javascript' | 'typescript' = 'javascript';

  private patterns = {
    functionDecl: /(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)/g,
    arrowFunction: /(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:\([^)]*\)|[^=])\s*=>/g,
    classDecl: /(?:export\s+)?class\s+(\w+)(?:\s+extends\s+(\w+))?/g,
    methodDecl: /(?:async\s+)?(\w+)\s*\(([^)]*)\)\s*\{/g,
    importES6: /import\s+(?:\{([^}]+)\}|(\w+)(?:\s*,\s*\{([^}]+)\})?)\s+from\s+['"]([^'"]+)['"]/g,
    importCommonJS: /require\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
    call: /(\w+(?:\.\w+)*)\s*\(([^)]*)\)/g,
    templateLiteral: /`([^`]*\$\{[^}]+\}[^`]*)`/g,
    export: /export\s+(?:default\s+)?(?:function\s+)?(\w+)/g,
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

        if (!trimmedLine || trimmedLine.startsWith('//') || trimmedLine.startsWith('/*')) {
          continue;
        }

        // Check for class definition
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
              methods: [],
            }
          );
          result.classes.push(currentClass);
          continue;
        }

        // Check for function declarations
        const funcMatch = trimmedLine.match(this.patterns.functionDecl);
        if (funcMatch) {
          const func = this.createFunctionInfo(
            this.generateId('func'),
            funcMatch[1],
            filePath,
            lineNum + 1,
            lineNum + 1,
            {
              parameters: this.parseParameters(funcMatch[2]),
              isAsync: trimmedLine.includes('async '),
              isExported: trimmedLine.startsWith('export'),
            }
          );
          result.functions.push(func);
          continue;
        }

        // Check for arrow functions
        const arrowMatch = trimmedLine.match(this.patterns.arrowFunction);
        if (arrowMatch) {
          const func = this.createFunctionInfo(
            this.generateId('func'),
            arrowMatch[1],
            filePath,
            lineNum + 1,
            lineNum + 1,
            {
              parameters: [],
              isAsync: trimmedLine.includes('async '),
            }
          );
          result.functions.push(func);
          continue;
        }

        // Check for ES6 imports
        const importMatch = trimmedLine.match(this.patterns.importES6);
        if (importMatch) {
          const from = importMatch[4];
          if (importMatch[2]) {
            // Default import
            result.imports.push({
              name: importMatch[2],
              from,
              isDefault: true,
              isNamespace: false,
              location: this.createLocation(filePath, lineNum + 1),
            });
          }
          if (importMatch[1] || importMatch[3]) {
            // Named imports
            const namedImports = (importMatch[1] || importMatch[3] || '').split(',');
            for (const imp of namedImports) {
              const [name, alias] = imp.trim().split(/\s+as\s+/);
              if (name) {
                result.imports.push({
                  name: name.trim(),
                  from,
                  alias: alias?.trim(),
                  isDefault: false,
                  isNamespace: false,
                  location: this.createLocation(filePath, lineNum + 1),
                });
              }
            }
          }
          continue;
        }

        // Check for CommonJS require
        const requireMatch = trimmedLine.match(this.patterns.importCommonJS);
        if (requireMatch) {
          result.imports.push({
            name: requireMatch[1],
            from: requireMatch[1],
            isDefault: false,
            isNamespace: true,
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

  protected parseParameters(paramsStr: string): Parameter[] {
    if (!paramsStr.trim()) return [];

    return paramsStr.split(',').map((param) => {
      const trimmed = param.trim();
      const [name, defaultValue] = trimmed.split('=');
      return {
        name: name.trim(),
        defaultValue: defaultValue?.trim(),
        isOptional: !!defaultValue,
      };
    });
  }

  private extractCalls(line: string, filePath: string, lineNum: number): CallInfo[] {
    const calls: CallInfo[] = [];
    let match;

    this.patterns.call.lastIndex = 0;
    while ((match = this.patterns.call.exec(line)) !== null) {
      // Skip keywords
      const keywords = ['if', 'for', 'while', 'switch', 'catch', 'function', 'class'];
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
      language: 'javascript',
      location: this.createLocation(filePath, 1, 1),
      children: [],
    };

    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const trimmed = lines[i].trim();

      if (trimmed.startsWith('function ') || trimmed.includes('=>')) {
        rootNode.children?.push({
          id: this.generateId('function'),
          type: 'function',
          language: 'javascript',
          location: this.createLocation(filePath, i + 1),
        });
      } else if (trimmed.startsWith('class ')) {
        rootNode.children?.push({
          id: this.generateId('class'),
          type: 'class',
          language: 'javascript',
          location: this.createLocation(filePath, i + 1),
        });
      }
    }

    return rootNode;
  }
}
