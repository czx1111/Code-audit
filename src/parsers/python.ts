/**
 * Code Audit MCP Server - Python AST Parser
 * Uses regex-based parsing for maximum performance and reliability
 */

import { BaseParser, ParseResult, ImportInfo, CallInfo } from './types';
import type { ASTNode, FunctionInfo, ClassInfo, Parameter } from '../types';

export class PythonParser extends BaseParser {
  readonly language = 'python';

  // Regex patterns for Python parsing
  private patterns = {
    functionDef: /^(?:async\s+)?def\s+(\w+)\s*\(([^)]*)\)(?:\s*->\s*([^\s:]+))?:/gm,
    classDef: /^class\s+(\w+)(?:\s*\(([^)]*)\))?:/gm,
    import: /^import\s+(\w+)(?:\s+as\s+(\w+))?$/gm,
    fromImport: /^from\s+([\w.]+)\s+import\s+(.+)$/gm,
    variable: /^(\w+)\s*=\s*(.+)$/gm,
    call: /(\w+(?:\.\w+)*)\s*\(([^)]*)\)/g,
    decorator: /^@(\w+)(?:\(([^)]*)\))?$/gm,
    docstring: /"""([\s\S]*?)"""|'''([\s\S]*?)'''/g,
    asyncDef: /^async\s+def\s+(\w+)\s*\(([^)]*)\)/gm,
    selfParam: /\bself\b/,
    clsParam: /\bcls\b/,
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
      const classStack: ClassInfo[] = [];
      const functionStack: FunctionInfo[] = [];
      const decorators: string[] = [];

      for (let lineNum = 0; lineNum < lines.length; lineNum++) {
        const line = lines[lineNum];
        const trimmedLine = line.trim();
        const indent = line.length - line.trimStart().length;

        // Skip empty lines and comments
        if (!trimmedLine || trimmedLine.startsWith('#')) {
          continue;
        }

        // Check for decorator
        if (trimmedLine.startsWith('@')) {
          const decoratorMatch = trimmedLine.match(this.patterns.decorator);
          if (decoratorMatch) {
            decorators.push(decoratorMatch[1]);
          }
          continue;
        }

        // Check for class definition
        const classMatch = trimmedLine.match(this.patterns.classDef);
        if (classMatch) {
          currentClass = this.parseClassDefinition(
            classMatch,
            filePath,
            lineNum + 1,
            decorators.slice()
          );
          result.classes.push(currentClass);
          classStack.push(currentClass);
          decorators.length = 0;
          continue;
        }

        // Check for function definition
        const funcMatch = trimmedLine.match(this.patterns.functionDef);
        if (funcMatch) {
          const func = this.parseFunctionDefinition(
            funcMatch,
            filePath,
            lineNum + 1,
            lines,
            decorators.slice(),
            currentClass
          );
          result.functions.push(func);

          if (currentClass && indent > 0) {
            currentClass.methods.push(func.id);
            func.isMethod = true;
            func.className = currentClass.name;
          }
          decorators.length = 0;
          continue;
        }

        // Check for import statements
        const importMatch = trimmedLine.match(this.patterns.import);
        if (importMatch) {
          result.imports.push({
            name: importMatch[1],
            from: importMatch[1],
            alias: importMatch[2],
            isDefault: false,
            isNamespace: true,
            location: this.createLocation(filePath, lineNum + 1),
          });
          continue;
        }

        const fromImportMatch = trimmedLine.match(this.patterns.fromImport);
        if (fromImportMatch) {
          const module = fromImportMatch[1];
          const imports = fromImportMatch[2].split(',').map((s) => s.trim());
          for (const imp of imports) {
            const [name, alias] = imp.split(/\s+as\s+/);
            result.imports.push({
              name: name.trim(),
              from: module,
              alias: alias?.trim(),
              isDefault: false,
              isNamespace: false,
              location: this.createLocation(filePath, lineNum + 1),
            });
          }
          continue;
        }

        // Check for function calls
        const calls = this.extractCalls(trimmedLine, filePath, lineNum + 1);
        result.calls.push(...calls);
      }

      // Calculate end lines for functions and classes
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

  private parseFunctionDefinition(
    match: RegExpMatchArray,
    filePath: string,
    lineNum: number,
    lines: string[],
    decorators: string[],
    currentClass: ClassInfo | null
  ): FunctionInfo {
    const name = match[1];
    const paramsStr = match[2] || '';
    const returnType = match[3];
    const parameters = this.parseParameters(paramsStr);
    const isAsync = match[0].includes('async ');

    return this.createFunctionInfo(
      this.generateId('func'),
      name,
      filePath,
      lineNum,
      lineNum, // Will be updated later
      {
        parameters,
        returnType,
        isAsync,
        isExported: decorators.includes('export') || name.startsWith('test_'),
        decorators: decorators.length > 0 ? decorators : undefined,
        className: currentClass?.name,
        isMethod: currentClass !== null,
        calls: [],
        calledBy: [],
        complexity: 1,
      }
    );
  }

  private parseClassDefinition(
    match: RegExpMatchArray,
    filePath: string,
    lineNum: number,
    decorators: string[]
  ): ClassInfo {
    const name = match[1];
    const parents =
      match[2]?.split(',').map((s) => s.trim()).filter(Boolean) || [];

    return this.createClassInfo(
      this.generateId('class'),
      name,
      filePath,
      lineNum,
      lineNum, // Will be updated later
      {
        parentClass: parents[0],
        interfaces: parents.slice(1),
        decorators: decorators.length > 0 ? decorators : undefined,
      }
    );
  }

  private parseParameters(paramsStr: string): Parameter[] {
    if (!paramsStr.trim()) return [];

    const params: Parameter[] = [];
    const parts = paramsStr.split(',');

    for (const part of parts) {
      const trimmed = part.trim();
      if (!trimmed || trimmed === 'self' || trimmed === 'cls') continue;

      // Handle typed parameters: name: type = default
      const typedMatch = trimmed.match(
        /^(\w+)(?:\s*:\s*([^=]+))?(?:\s*=\s*(.+))?$/
      );
      if (typedMatch) {
        params.push({
          name: typedMatch[1],
          type: typedMatch[2]?.trim(),
          defaultValue: typedMatch[3]?.trim(),
          isOptional: !!typedMatch[3],
          isVariadic: trimmed.startsWith('*'),
        });
      }
    }

    return params;
  }

  private extractCalls(line: string, filePath: string, lineNum: number): CallInfo[] {
    const calls: CallInfo[] = [];
    let match;

    // Reset regex
    this.patterns.call.lastIndex = 0;
    while ((match = this.patterns.call.exec(line)) !== null) {
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
    for (let i = 0; i < items.length; i++) {
      const item = items[i];
      let endLine = lines.length;

      // Find the next item at same or lower indentation level
      const startIndent = lines[item.location.line - 1]?.search(/\S/) || 0;

      for (let j = item.location.line; j < lines.length; j++) {
        const currentLine = lines[j];
        if (!currentLine.trim() || currentLine.trim().startsWith('#')) continue;

        const currentIndent = currentLine.search(/\S/);
        if (currentIndent <= startIndent && j > item.location.line - 1) {
          // Check if this is a new definition
          const trimmed = currentLine.trim();
          if (
            trimmed.startsWith('def ') ||
            trimmed.startsWith('async def ') ||
            trimmed.startsWith('class ')
          ) {
            endLine = j;
            break;
          }
        }
      }

      item.endLine = endLine;
    }
  }

  private buildAST(content: string, filePath: string): ASTNode {
    const rootNode: ASTNode = {
      id: this.generateId('root'),
      type: 'other',
      language: 'python',
      location: this.createLocation(filePath, 1, 1),
      children: [],
    };

    // Simple AST building - can be enhanced
    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();

      if (trimmed.startsWith('def ') || trimmed.startsWith('async def ')) {
        rootNode.children?.push({
          id: this.generateId('function'),
          type: 'function',
          language: 'python',
          location: this.createLocation(filePath, i + 1),
        });
      } else if (trimmed.startsWith('class ')) {
        rootNode.children?.push({
          id: this.generateId('class'),
          type: 'class',
          language: 'python',
          location: this.createLocation(filePath, i + 1),
        });
      }
    }

    return rootNode;
  }
}
