/**
 * Code Audit MCP Server - Java AST Parser
 */

import { BaseParser, ParseResult, CallInfo } from './types';
import type { ASTNode, FunctionInfo, ClassInfo, Parameter } from '../types';

export class JavaParser extends BaseParser {
  readonly language = 'java';

  private patterns = {
    classDecl: /(?:public|private|protected)?\s*(?:abstract|final)?\s*class\s+(\w+)(?:\s+extends\s+(\w+))?(?:\s+implements\s+([\w,\s]+))?/g,
    interfaceDecl: /(?:public|private|protected)?\s*interface\s+(\w+)(?:\s+extends\s+([\w,\s]+))?/g,
    methodDecl: /(?:public|private|protected)?\s*(?:static|final|abstract|synchronized)?\s*(?:<[^>]+>\s+)?(\w+(?:<[^>]+>)?)\s+(\w+)\s*\(([^)]*)\)/g,
    import: /import\s+(?:static\s+)?([\w.]+)(?:\.\*)?;/g,
    call: /(\w+(?:\.\w+)*)\s*\(([^)]*)\)/g,
    annotation: /@(\w+)(?:\(([^)]*)\))?/g,
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
      const annotations: string[] = [];

      for (let lineNum = 0; lineNum < lines.length; lineNum++) {
        const line = lines[lineNum];
        const trimmedLine = line.trim();

        if (!trimmedLine || trimmedLine.startsWith('//') || trimmedLine.startsWith('/*')) {
          continue;
        }

        // Check for annotations
        const annotationMatch = trimmedLine.match(this.patterns.annotation);
        if (annotationMatch && trimmedLine.startsWith('@')) {
          annotations.push(annotationMatch[1]);
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
              decorators: annotations.length > 0 ? [...annotations] : undefined,
              methods: [],
            }
          );
          result.classes.push(currentClass);
          annotations.length = 0;
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
              {
                interfaces: interfaceMatch[2]?.split(',').map((s) => s.trim()),
                methods: [],
              }
            )
          );
          continue;
        }

        // Check for method declaration
        const methodMatch = trimmedLine.match(this.patterns.methodDecl);
        if (methodMatch && !trimmedLine.includes('new ') && !trimmedLine.includes('return ')) {
          const returnType = methodMatch[1];
          const name = methodMatch[2];
          const params = this.parseParameters(methodMatch[3] || '');

          // Skip if it looks like a variable declaration
          if (['if', 'for', 'while', 'switch', 'catch'].includes(name)) {
            continue;
          }

          const method = this.createFunctionInfo(
            this.generateId('method'),
            name,
            filePath,
            lineNum + 1,
            lineNum + 1,
            {
              parameters: params,
              returnType,
              isMethod: true,
              className: currentClass?.name,
              isExported: trimmedLine.includes('public'),
            }
          );
          result.functions.push(method);

          if (currentClass) {
            currentClass.methods.push(method.id);
          }

          annotations.length = 0;
          continue;
        }

        // Check for imports
        const importMatch = trimmedLine.match(this.patterns.import);
        if (importMatch) {
          result.imports.push({
            name: importMatch[1].split('.').pop() || importMatch[1],
            from: importMatch[1],
            isDefault: false,
            isNamespace: importMatch[1].endsWith('.*'),
            location: this.createLocation(filePath, lineNum + 1),
          });
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

      // Java params: Type name or Type... name
      const match = trimmed.match(/([\w.<>?\[\]]+(?:\.\.\.)?)\s+(\w+)$/);
      if (match) {
        params.push({
          name: match[2],
          type: match[1].replace('...', '[]'),
          isVariadic: match[1].includes('...'),
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
      // Skip keywords and new expressions
      const keywords = ['if', 'for', 'while', 'switch', 'catch', 'new', 'return'];
      if (keywords.some((k) => match![1].startsWith(k))) continue;

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
      language: 'java',
      location: this.createLocation(filePath, 1, 1),
      children: [],
    };

    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const trimmed = lines[i].trim();

      if (trimmed.includes('void ') || /\w+\s+\w+\s*\(/.test(trimmed)) {
        if (!trimmed.startsWith('//') && !trimmed.startsWith('*')) {
          rootNode.children?.push({
            id: this.generateId('function'),
            type: 'function',
            language: 'java',
            location: this.createLocation(filePath, i + 1),
          });
        }
      } else if (trimmed.includes('class ')) {
        rootNode.children?.push({
          id: this.generateId('class'),
          type: 'class',
          language: 'java',
          location: this.createLocation(filePath, i + 1),
        });
      }
    }

    return rootNode;
  }
}
