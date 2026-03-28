/**
 * Code Audit MCP Server - TypeScript AST Parser
 * Extends JavaScript parser with TypeScript-specific features
 */

import { JavaScriptParser } from './javascript';
import { ParseResult } from './types';
import type { Parameter } from '../types';

export class TypeScriptParser extends JavaScriptParser {
  readonly language = 'typescript';

  private tsPatterns = {
    interface: /(?:export\s+)?interface\s+(\w+)(?:\s+extends\s+(\w+))?/g,
    typeAlias: /(?:export\s+)?type\s+(\w+)\s*=/g,
    enumDecl: /(?:export\s+)?enum\s+(\w+)/g,
    decorator: /@(\w+)(?:\(([^)]*)\))?/g,
    typedParam: /(\w+)(?:\s*\?\s*)?(?:\s*:\s*([^,=)]+))?(?:\s*=\s*([^,)]+))?/g,
    generic: /<([^>]+)>/g,
  };

  async parse(content: string, filePath: string): Promise<ParseResult> {
    // Use JavaScript parser as base
    const result = await super.parse(content, filePath);
    result.ast!.language = 'typescript';

    const lines = content.split('\n');

    // Add TypeScript-specific parsing
    for (let lineNum = 0; lineNum < lines.length; lineNum++) {
      const line = lines[lineNum];
      const trimmedLine = line.trim();

      // Check for interface declarations
      const interfaceMatch = trimmedLine.match(this.tsPatterns.interface);
      if (interfaceMatch) {
        result.classes.push(
          this.createClassInfo(
            this.generateId('interface'),
            interfaceMatch[1],
            filePath,
            lineNum + 1,
            lineNum + 1,
            {
              parentClass: interfaceMatch[2],
              methods: [],
            }
          )
        );
      }

      // Check for enum declarations
      const enumMatch = trimmedLine.match(this.tsPatterns.enumDecl);
      if (enumMatch) {
        result.variables.push({
          name: enumMatch[1],
          type: 'enum',
          isConstant: true,
          isExported: trimmedLine.startsWith('export'),
          location: this.createLocation(filePath, lineNum + 1),
        });
      }
    }

    return result;
  }

  protected parseParameters(paramsStr: string): Parameter[] {
    if (!paramsStr.trim()) return [];

    const params: Parameter[] = [];
    // Handle TypeScript typed parameters
    const paramParts = this.splitParams(paramsStr);

    for (const part of paramParts) {
      const trimmed = part.trim();
      if (!trimmed) continue;

      // Match TypeScript parameter syntax: name?: type = default
      const match = trimmed.match(
        /^(\.\.\.)?(\w+)(\?)?(?:\s*:\s*([^=]+))?(?:\s*=\s*(.+))?$/
      );

      if (match) {
        params.push({
          name: match[2],
          type: match[4]?.trim(),
          defaultValue: match[5]?.trim(),
          isOptional: !!match[3] || !!match[5],
          isVariadic: !!match[1],
        });
      }
    }

    return params;
  }

  private splitParams(paramsStr: string): string[] {
    const params: string[] = [];
    let depth = 0;
    let current = '';

    for (const char of paramsStr) {
      if (char === '<' || char === '(' || char === '[' || char === '{') {
        depth++;
      } else if (char === '>' || char === ')' || char === ']' || char === '}') {
        depth--;
      } else if (char === ',' && depth === 0) {
        params.push(current);
        current = '';
        continue;
      }
      current += char;
    }

    if (current.trim()) {
      params.push(current);
    }

    return params;
  }
}
