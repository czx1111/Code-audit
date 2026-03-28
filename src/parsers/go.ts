/**
 * Code Audit MCP Server - Go AST Parser
 */

import { BaseParser, ParseResult, CallInfo } from './types';
import type { ASTNode, FunctionInfo, ClassInfo, Parameter } from '../types';

export class GoParser extends BaseParser {
  readonly language = 'go';

  private patterns = {
    functionDecl: /func\s+(?:\((\w+)\s+\*?(\w+)\)\s+)?(\w+)\s*\(([^)]*)\)(?:\s*\(([^)]*)\))?(?:\s+error)?/g,
    structDecl: /type\s+(\w+)\s+struct/g,
    interfaceDecl: /type\s+(\w+)\s+interface/g,
    import: /import\s+(?:\(([^)]+)\)|"([^"]+)")/g,
    importSingle: /"([^"]+)"/g,
    methodCall: /(\w+(?:\.\w+)*)\s*\(([^)]*)\)/g,
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

      for (let lineNum = 0; lineNum < lines.length; lineNum++) {
        const line = lines[lineNum];
        const trimmedLine = line.trim();

        if (!trimmedLine || trimmedLine.startsWith('//')) {
          continue;
        }

        // Check for function declaration
        const funcMatch = trimmedLine.match(this.patterns.functionDecl);
        if (funcMatch) {
          const receiverType = funcMatch[2];
          const name = funcMatch[3];
          const params = this.parseParameters(funcMatch[4] || '');
          const returnTypes = funcMatch[5];

          const func = this.createFunctionInfo(
            this.generateId('func'),
            name,
            filePath,
            lineNum + 1,
            lineNum + 1,
            {
              parameters: params,
              returnType: returnTypes,
              isMethod: !!receiverType,
              className: receiverType,
              isExported: name[0] === name[0].toUpperCase(),
            }
          );
          result.functions.push(func);
          continue;
        }

        // Check for struct declaration
        const structMatch = trimmedLine.match(this.patterns.structDecl);
        if (structMatch) {
          result.classes.push(
            this.createClassInfo(
              this.generateId('struct'),
              structMatch[1],
              filePath,
              lineNum + 1,
              lineNum + 1,
              { methods: [] }
            )
          );
          continue;
        }

        // Check for interface declaration
        const interfaceMatch = trimmedLine.match(this.patterns.interfaceDecl);
        if (interfaceMatch) {
          result.classes.push(
            this.createClassInfo(
              this.generateId('interface'),
              interfaceMatch[1],
              filePath,
              lineNum + 1,
              lineNum + 1,
              { methods: [] }
            )
          );
          continue;
        }

        // Check for imports
        if (trimmedLine.startsWith('import')) {
          const importBlockMatch = trimmedLine.match(this.patterns.import);
          if (importBlockMatch) {
            if (importBlockMatch[2]) {
              // Single import
              result.imports.push({
                name: importBlockMatch[2],
                from: importBlockMatch[2],
                isDefault: false,
                isNamespace: true,
                location: this.createLocation(filePath, lineNum + 1),
              });
            }
          }
          continue;
        }

        // Extract method calls
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

      // Go params: name type or name1, name2 type
      const typeMatch = trimmed.match(/(\w+)(?:\s+(\*?[\w.]+(?:\[\])?))?$/);
      if (typeMatch) {
        params.push({
          name: typeMatch[1],
          type: typeMatch[2]?.trim(),
        });
      }
    }

    return params;
  }

  private extractCalls(line: string, filePath: string, lineNum: number): CallInfo[] {
    const calls: CallInfo[] = [];
    let match;

    this.patterns.methodCall.lastIndex = 0;
    while ((match = this.patterns.methodCall.exec(line)) !== null) {
      // Skip keywords
      const keywords = ['if', 'for', 'switch', 'func', 'go', 'defer'];
      if (keywords.includes(match[1])) continue;

      calls.push({
        name: match[1],
        callee: match[1],
        arguments: match[2] ? match[2].split(',').map((s) => s.trim()) : [],
        location: this.createLocation(filePath, lineNum),
        isAsync: line.includes('go ') || line.includes('defer '),
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
      language: 'go',
      location: this.createLocation(filePath, 1, 1),
      children: [],
    };

    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const trimmed = lines[i].trim();

      if (trimmed.startsWith('func ')) {
        rootNode.children?.push({
          id: this.generateId('function'),
          type: 'function',
          language: 'go',
          location: this.createLocation(filePath, i + 1),
        });
      } else if (trimmed.startsWith('type ') && trimmed.includes('struct')) {
        rootNode.children?.push({
          id: this.generateId('class'),
          type: 'class',
          language: 'go',
          location: this.createLocation(filePath, i + 1),
        });
      }
    }

    return rootNode;
  }
}
