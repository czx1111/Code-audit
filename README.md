<div align="center">

# 🔐 Code Audit MCP Server

**AI原生代码安全审计 MCP Server**

支持多语言AST分析、调用图分析、漏洞检测和AI深度审计

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)
[![Node.js](https://img.shields.io/badge/Node.js-18%2B-green.svg)](https://nodejs.org/)
[![MCP](https://img.shields.io/badge/MCP-1.6.1-blue.svg)](https://modelcontextprotocol.io/)

[English](#english) | [中文文档](#中文文档)

</div>

---

## 中文文档

### ✨ 功能特性

- 🔍 **多语言支持**: Python, JavaScript/TypeScript, Go, Java, PHP, Rust
- 🌳 **AST解析**: 将源代码解析为抽象语法树进行深度分析
- 📊 **调用图分析**: 构建函数调用关系图，追踪数据流
- 🛡️ **漏洞检测**: 内置 OWASP Top 10、CWE 等安全规则（25+ 规则）
- 🤖 **AI深度审计**: 利用 LLM 进行语义级安全分析
- 📋 **漏洞复现指南**: 自动生成漏洞复现步骤、Payload 和 PoC 代码
- 📄 **多种报告格式**: Markdown, JSON, SARIF (GitHub Code Scanning 兼容)

### 📦 安装

```bash
# 克隆仓库
git clone https://github.com/your-username/code-audit-mcp-server.git
cd code-audit-mcp-server

# 安装依赖
npm install

# 构建
npm run build
```

### ⚙️ 配置

#### MCP 客户端配置

在 Claude Desktop、Cursor、CatPaw 等 MCP 客户端配置中添加:

```json
{
  "mcpServers": {
    "code-audit": {
      "command": "node",
      "args": ["/path/to/code-audit-mcp-server/dist/index.js"]
    }
  }
}
```

#### 环境变量（可选）

```bash
# AI 分析 API Key
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."
```

### 🚀 使用方法

#### 1. 完整扫描 (`audit_scan`)

执行完整的代码安全审计扫描：

```json
{
  "name": "audit_scan",
  "arguments": {
    "targetPath": "/path/to/code",
    "language": "auto",
    "mode": "standard",
    "scope": "security",
    "outputFormat": "markdown"
  }
}
```

参数说明：
- `targetPath`: 要扫描的代码路径（文件或目录）
- `language`: 编程语言，默认 `auto` 自动检测
- `mode`: 扫描模式 `quick` | `standard` | `deep`
- `scope`: 扫描范围 `all` | `security` | `quality` | `architecture`
- `outputFormat`: 输出格式 `markdown` | `json` | `sarif`

#### 2. 快速扫描 (`audit_quick_scan`)

仅检测 critical 和 high 级别的漏洞，适合 CI/CD：

```json
{
  "name": "audit_quick_scan",
  "arguments": {
    "targetPath": "/path/to/code",
    "language": "auto"
  }
}
```

#### 3. 单文件分析 (`audit_analyze_file`)

对单个文件进行详细的代码安全分析：

```json
{
  "name": "audit_analyze_file",
  "arguments": {
    "filePath": "/path/to/file.py",
    "language": "python"
  }
}
```

#### 4. 构建调用图 (`build_call_graph`)

构建代码的函数调用关系图：

```json
{
  "name": "build_call_graph",
  "arguments": {
    "targetPath": "/path/to/code",
    "language": "python",
    "maxDepth": 10
  }
}
```

#### 5. 数据流分析 (`analyze_data_flow`)

追踪用户输入到敏感函数的数据传播路径：

```json
{
  "name": "analyze_data_flow",
  "arguments": {
    "targetPath": "/path/to/code",
    "language": "python",
    "entryPoint": "main"
  }
}
```

#### 6. 依赖检查 (`check_dependencies`)

检查项目依赖的安全风险：

```json
{
  "name": "check_dependencies",
  "arguments": {
    "targetPath": "/path/to/project"
  }
}
```

#### 7. 获取漏洞复现指南 (`get_exploitation_guide`) ⭐ 新增

获取漏洞的详细复现操作指南：

```json
{
  "name": "get_exploitation_guide",
  "arguments": {
    "ruleId": "SQL_INJECTION",
    "language": "python"
  }
}
```

输出包括：
- 漏洞概述和影响范围
- 前置条件
- 详细复现步骤
- 攻击载荷示例
- Python PoC 代码
- 修复建议
- 参考链接

### 🛡️ 检测的漏洞类型

#### 注入类漏洞
| 漏洞类型 | CWE | 严重程度 |
|---------|-----|---------|
| SQL注入 | CWE-89 | Critical |
| 命令注入 | CWE-78 | Critical |
| LDAP注入 | CWE-90 | High |
| XPath注入 | CWE-91 | High |
| NoSQL注入 | - | High |

#### 认证授权问题
| 漏洞类型 | CWE | 严重程度 |
|---------|-----|---------|
| 身份认证绕过 | CWE-287 | Critical |
| 权限提升 | CWE-269 | High |
| 会话管理问题 | CWE-384 | High |
| 不安全的直接对象引用 | CWE-639 | High |

#### 数据安全问题
| 漏洞类型 | CWE | 严重程度 |
|---------|-----|---------|
| 敏感数据泄露 | CWE-200 | High |
| 硬编码密码 | CWE-798 | Medium |
| 不安全的加密 | CWE-327 | Medium |
| 日志注入 | CWE-117 | Medium |

#### 其他漏洞
| 漏洞类型 | CWE | 严重程度 |
|---------|-----|---------|
| XSS | CWE-79 | High |
| SSRF | CWE-918 | High |
| XXE | CWE-611 | High |
| 路径遍历 | CWE-22 | High |
| 不安全的反序列化 | CWE-502 | Critical |
| 开放重定向 | CWE-601 | Medium |
| 服务端模板注入 | CWE-94 | Critical |

### 📁 项目结构

```
code-audit-mcp-server/
├── src/
│   ├── index.ts              # 主入口，MCP 工具定义
│   ├── types.ts              # 类型定义
│   ├── constants.ts          # 常量和模式
│   ├── exploitation-guide.ts # 漏洞复现指南生成器
│   ├── sarif.ts              # SARIF 格式输出
│   ├── rules-loader.ts       # YAML 规则加载器
│   ├── parsers/              # AST 解析器
│   │   ├── types.ts          # 解析器接口
│   │   ├── python.ts         # Python 解析器
│   │   ├── javascript.ts     # JavaScript 解析器
│   │   ├── typescript.ts     # TypeScript 解析器
│   │   ├── go.ts             # Go 解析器
│   │   ├── java.ts           # Java 解析器
│   │   └── php.ts            # PHP 解析器
│   ├── detectors/            # 漏洞检测引擎
│   │   └── engine.ts
│   ├── ai/                   # AI 分析模块
│   │   └── analyzer.ts
│   └── utils/                # 工具函数
│       └── helpers.ts
├── rules/                    # YAML 安全规则
│   └── security-rules.yaml
├── test-vulnerable-code/     # 测试用例
├── package.json
├── tsconfig.json
├── LICENSE
└── README.md
```

### 🔧 开发

```bash
# 开发模式
npm run dev

# 构建
npm run build

# 运行测试
npm test

# 代码检查
npm run lint
```

### 🤝 与 Skills 协同使用

本项目可以与 Code Audit Skill 协同使用，实现更强大的审计能力：

```
┌─────────────────────────────────────────────────────────────┐
│                    Code Audit Skill                          │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ Phase 1: 项目分析 → MCP: findSourceFiles            │    │
│  │ Phase 2: AST解析   → MCP: audit_scan                │    │
│  │ Phase 3: 调用图    → MCP: build_call_graph          │    │
│  │ Phase 4: 数据流    → MCP: analyze_data_flow         │    │
│  │ Phase 5: 漏洞复现  → MCP: get_exploitation_guide    │    │
│  │ Phase 6: 报告生成  → MCP: SARIF 输出                │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

### 📄 许可证

[MIT License](LICENSE)

---

## English

### ✨ Features

- 🔍 **Multi-language Support**: Python, JavaScript/TypeScript, Go, Java, PHP, Rust
- 🌳 **AST Parsing**: Parse source code into Abstract Syntax Trees for deep analysis
- 📊 **Call Graph Analysis**: Build function call relationship graphs, track data flow
- 🛡️ **Vulnerability Detection**: Built-in OWASP Top 10, CWE security rules (25+ rules)
- 🤖 **AI Deep Audit**: Leverage LLM for semantic-level security analysis
- 📋 **Exploitation Guide**: Auto-generate vulnerability reproduction steps, payloads, and PoC code
- 📄 **Multiple Report Formats**: Markdown, JSON, SARIF (GitHub Code Scanning compatible)

### 📦 Installation

```bash
# Clone repository
git clone https://github.com/your-username/code-audit-mcp-server.git
cd code-audit-mcp-server

# Install dependencies
npm install

# Build
npm run build
```

### ⚙️ Configuration

Add to your MCP client configuration (Claude Desktop, Cursor, etc.):

```json
{
  "mcpServers": {
    "code-audit": {
      "command": "node",
      "args": ["/path/to/code-audit-mcp-server/dist/index.js"]
    }
  }
}
```

### 🛡️ Supported Vulnerability Types

- **Injection**: SQL Injection, Command Injection, LDAP Injection, XPath Injection, NoSQL Injection
- **Authentication**: Auth Bypass, Privilege Escalation, Session Management Issues
- **Data Security**: Sensitive Data Exposure, Hardcoded Credentials, Weak Cryptography
- **Other**: XSS, SSRF, XXE, Path Traversal, Insecure Deserialization, Open Redirect, SSTI

### 📄 License

[MIT License](LICENSE)

---

<div align="center">

**⭐ If you find this project helpful, please give it a star! ⭐**

</div>
