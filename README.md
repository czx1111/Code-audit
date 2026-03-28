<div align="center">

# 🔐 Code Audit MCP Server

**AI原生代码安全审计 MCP Server**

支持多语言AST分析、调用图分析、漏洞检测和AI深度审计

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)
[![Node.js](https://img.shields.io/badge/Node.js-18%2B-green.svg)](https://nodejs.org/)
[![MCP](https://img.shields.io/badge/MCP-1.6.1-blue.svg)](https://modelcontextprotocol.io/)

</div>

---

## 📖 目录

- [项目简介](#项目简介)
- [功能特性](#功能特性)
- [安装指南](#安装指南)
- [配置方法](#配置方法)
- [使用教程](#使用教程)
- [支持的漏洞类型](#支持的漏洞类型)
- [项目结构](#项目结构)
- [开发指南](#开发指南)

---

## 项目简介

Code Audit MCP Server 是一个基于 Model Context Protocol (MCP) 的 AI 原生代码安全审计工具。它可以与 Claude、Cursor、CatPaw 等 AI 编辑器无缝集成，提供专业的代码安全审计能力。

### 为什么选择 Code Audit MCP Server？

- 🚀 **零配置集成** - 一行配置即可在 AI 编辑器中使用
- 🔍 **深度分析** - 基于 AST 的代码语义分析，不仅仅是正则匹配
- 🛡️ **全面覆盖** - 支持 OWASP Top 10 和 CWE 常见漏洞类型
- 📋 **可操作性强** - 每个漏洞都附带详细的复现步骤和修复建议
- 🤖 **AI 增强** - 可选的 AI 深度审计功能

---

## 功能特性

### 1. 🔍 多语言代码扫描

支持主流编程语言的代码安全审计：

| 语言 | AST解析 | 调用图 | 数据流 |
|------|--------|--------|--------|
| Python | ✅ | ✅ | ✅ |
| JavaScript | ✅ | ✅ | ✅ |
| TypeScript | ✅ | ✅ | ✅ |
| Go | ✅ | ✅ | 🔄 |
| Java | ✅ | ✅ | 🔄 |
| PHP | ✅ | 🔄 | 🔄 |

### 2. 🛡️ 漏洞检测

内置 25+ 条安全检测规则，覆盖：

- **注入类漏洞**: SQL注入、命令注入、代码注入、LDAP注入等
- **认证授权**: 身份认证绕过、权限提升、会话管理等
- **数据安全**: 敏感数据泄露、硬编码密码、弱加密等
- **其他漏洞**: XSS、SSRF、XXE、路径遍历、反序列化等

### 3. 📊 调用图分析

自动构建代码的函数调用关系图，帮助理解：
- 函数之间的调用关系
- 数据在函数间的流动路径
- 潜在的攻击面

### 4. 🌊 数据流分析

追踪用户输入到敏感函数的数据传播路径：
- 识别用户输入点（source）
- 追踪数据传播过程
- 发现到达危险函数的路径（sink）

### 5. 📋 漏洞复现指南 ⭐ 特色功能

每个检测到的漏洞都会生成详细的复现指南：
- 漏洞概述和影响范围
- 详细复现步骤
- 攻击载荷示例
- Python PoC 代码
- 修复建议

### 6. 📄 多格式报告

支持多种报告输出格式：
- **Markdown** - 适合人工阅读
- **JSON** - 适合程序处理
- **SARIF** - GitHub Code Scanning 兼容格式

---

## 安装指南

### 环境要求

- Node.js >= 18.0
- npm >= 9.0

直接下载

# 下载项目
[https://github.com/czx1111/Code-audit-MCP]


cd code-audit-mcp-server-main

# 安装依赖并构建
npm install && npm run build
```

### 验证安装

```bash
# 运行测试
node dist/index.js --version
```

---

## 配置方法

### 在 Claude Desktop 中配置

编辑 Claude Desktop 配置文件：

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`

**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

添加以下内容：

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

### 在 Cursor 中配置

编辑 Cursor 配置文件：

**macOS/Linux**: `~/.cursor/mcp.json`

**Windows**: `%APPDATA%\Cursor\mcp.json`

```json
{
  "mcpServers": {
    "code-audit": {
      "command": "node",
      "args": ["D:/yourpath/code-audit-mcp-server/dist/index.js"]
    }
  }
}
```

### 在 CatPaw 中配置

打开 CatPaw 设置 -> MCP Servers -> 添加新服务器：

```json
{
  "name": "code-audit",
  "command": "node",
  "args": ["/path"]
}
```

---

## 使用教程

### 工具列表

| 工具名称 | 功能描述 |
|---------|---------|
| `audit_scan` | 完整代码安全审计扫描 |
| `audit_quick_scan` | 快速扫描（仅高危漏洞） |
| `audit_analyze_file` | 单文件深度分析 |
| `build_call_graph` | 构建函数调用图 |
| `analyze_data_flow` | 数据流分析 |
| `check_dependencies` | 依赖安全检查 |
| `get_exploitation_guide` | 获取漏洞复现指南 |

### 1. 完整扫描

最常用的功能，对整个项目进行全面的安全审计：

**参数说明**：
- `targetPath`: 代码路径（文件或目录）
- `language`: 编程语言，默认 `auto` 自动检测
- `mode`: 扫描模式
  - `quick` - 快速模式，仅扫描关键文件
  - `standard` - 标准模式（默认）
  - `deep` - 深度模式，包含 AI 分析
- `scope`: 扫描范围
  - `all` - 全部检查
  - `security` - 仅安全漏洞（默认）
  - `quality` - 代码质量
  - `architecture` - 架构分析
- `outputFormat`: 输出格式 `markdown` | `json` | `sarif`

**使用示例**：

```
请使用 audit_scan 扫描 d:/my-project 目录的代码安全性
```

### 2. 快速扫描

适合 CI/CD 流程，仅检测 Critical 和 High 级别漏洞：

```
请使用 audit_quick_scan 快速扫描 d:/my-project
```

### 3. 单文件分析

深入分析单个文件的安全问题：

```
请使用 audit_analyze_file 分析 d:/my-project/app.py 文件
```

### 4. 构建调用图

生成函数调用关系图：

```
请使用 build_call_graph 构建 d:/my-project 的调用图
```

### 5. 数据流分析

追踪数据流动路径：

```
请使用 analyze_data_flow 分析 d:/my-project 的数据流
```

### 6. 获取漏洞复现指南

当发现漏洞后，获取详细的复现操作：

```
请使用 get_exploitation_guide 获取 SQL_INJECTION 漏洞的复现指南
```

### 输出示例

```
# 代码安全审计报告

## 📊 扫描摘要
- 扫描文件: 15 个
- 发现漏洞: 3 个
- Critical: 1 个
- High: 1 个
- Medium: 1 个

## 🔴 Critical: SQL 注入

**文件**: src/db.py
**位置**: 第 42 行
**代码**: `query = f"SELECT * FROM users WHERE id = {user_id}"`

### 漏洞描述
直接将用户输入拼接到 SQL 查询中，可能导致 SQL 注入攻击。

### 复现步骤
1. 访问 /user?id=1
2. 输入测试载荷: 1' OR '1'='1
3. 观察是否返回异常数据

### 修复建议
使用参数化查询：
```python
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```
```

---

## 支持的漏洞类型

### 注入类漏洞

| 漏洞类型 | CWE 编号 | 严重程度 | 检测能力 |
|---------|---------|---------|---------|
| SQL 注入 | CWE-89 | 🔴 Critical | ✅ |
| 命令注入 | CWE-78 | 🔴 Critical | ✅ |
| 代码注入 | CWE-94 | 🔴 Critical | ✅ |
| LDAP 注入 | CWE-90 | 🟠 High | ✅ |
| XPath 注入 | CWE-91 | 🟠 High | ✅ |
| NoSQL 注入 | - | 🟠 High | ✅ |
| 模板注入 | CWE-94 | 🔴 Critical | ✅ |

### 认证授权漏洞

| 漏洞类型 | CWE 编号 | 严重程度 | 检测能力 |
|---------|---------|---------|---------|
| 身份认证绕过 | CWE-287 | 🔴 Critical | ✅ |
| 权限提升 | CWE-269 | 🟠 High | ✅ |
| 会话管理问题 | CWE-384 | 🟠 High | ✅ |
| 不安全的直接对象引用 | CWE-639 | 🟠 High | ✅ |

### 数据安全漏洞

| 漏洞类型 | CWE 编号 | 严重程度 | 检测能力 |
|---------|---------|---------|---------|
| 敏感数据泄露 | CWE-200 | 🟠 High | ✅ |
| 硬编码密码 | CWE-798 | 🟡 Medium | ✅ |
| 不安全的加密 | CWE-327 | 🟡 Medium | ✅ |
| 日志注入 | CWE-117 | 🟡 Medium | ✅ |

### 其他漏洞

| 漏洞类型 | CWE 编号 | 严重程度 | 检测能力 |
|---------|---------|---------|---------|
| XSS（跨站脚本） | CWE-79 | 🟠 High | ✅ |
| SSRF（服务端请求伪造） | CWE-918 | 🟠 High | ✅ |
| XXE（XML外部实体） | CWE-611 | 🟠 High | ✅ |
| 路径遍历 | CWE-22 | 🟠 High | ✅ |
| 不安全的反序列化 | CWE-502 | 🔴 Critical | ✅ |
| 开放重定向 | CWE-601 | 🟡 Medium | ✅ |

---

## 项目结构

code-audit-mcp-server/
├── 📁 src/                      # 源代码
│   ├── 📄 index.ts              # MCP 工具入口
│   ├── 📄 types.ts              # 类型定义
│   ├── 📄 constants.ts          # 常量配置
│   ├── 📄 exploitation-guide.ts # 漏洞复现指南生成
│   ├── 📄 sarif.ts              # SARIF 格式输出
│   ├── 📄 rules-loader.ts       # YAML 规则加载
│   ├── 📁 parsers/              # AST 解析器
│   │   ├── 📄 types.ts          # 解析器接口
│   │   ├── 📄 python.ts         # Python 解析器
│   │   ├── 📄 javascript.ts     # JavaScript 解析器
│   │   ├── 📄 typescript.ts     # TypeScript 解析器
│   │   ├── 📄 go.ts             # Go 解析器
│   │   ├── 📄 java.ts           # Java 解析器
│   │   └── 📄 php.ts            # PHP 解析器
│   ├── 📁 detectors/            # 漏洞检测引擎
│   │   └── 📄 engine.ts
│   ├── 📁 ai/                   # AI 分析模块
│   │   └── 📄 analyzer.ts
│   └── 📁 utils/                # 工具函数
│       └── 📄 helpers.ts
├── 📁 rules/                    # 安全规则（YAML）
│   └── 📄 security-rules.yaml   # 安全检测规则
├── 📁 test-vulnerable-code/     # 测试用例（有漏洞的代码）
├── 📁 test-project/             # 测试项目
├── 📄 package.json              # 项目配置
├── 📄 tsconfig.json             # TypeScript 配置
├── 📄 LICENSE                   # MIT 许可证
└── 📄 README.md                 # 项目文档

---

## 开发指南

### 本地开发

```bash
# 安装依赖
npm install

# 开发模式（热重载）
npm run dev

# 构建生产版本
npm run build

# 运行测试
npm test

# 代码检查
npm run lint
```

### 添加自定义规则

在 `rules/security-rules.yaml` 中添加自定义检测规则：

```yaml
rules:
  - id: CUSTOM_CHECK
    name: 自定义安全检查
    description: 检测自定义的安全问题
    severity: medium
    languages:
      - python
      - javascript
    patterns:
      - pattern: "dangerous_function($VAR)"
    message: 发现危险函数调用
```

### 扩展解析器

在 `src/parsers/` 目录下添加新的语言解析器：

```typescript
// src/parsers/rust.ts
export class RustParser implements Parser {
  async parse(code: string, filePath: string): Promise<ParseResult> {
    // 实现 Rust AST 解析
  }
}
```

---

## 许可证

本项目采用 [MIT 许可证](LICENSE)。

---

## 贡献

欢迎提交 Issue 和 Pull Request！

---

<div align="center">

**⭐ 如果这个项目对你有帮助，请给一个 Star！⭐**

</div>

欢迎大家关注微信公众号，获取更多技术分享。
![qrcode_for_gh_19fda9b4ef1b_258](https://github.com/user-attachments/assets/b3bfbc4a-2652-49f7-976c-a63ec9be8ae0)

