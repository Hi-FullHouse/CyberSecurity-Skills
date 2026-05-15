---
id: 12-005
title: "🌐 JavaScript/Node.js代码审计 (JavaScript & Node.js Code Audit)"
category: 代码审计
category_en: "Code Audit"
difficulty: ★★★
tools: "ESLint, RetireJS, Semgrep, CodeQL"
last_updated: 2025-07
tags: ["code-audit", "static-analysis", "php-audit", "java-audit", "javascript-audit"]
subdomain: code-audit
nist_csf: ["PR.IP-12", "ID.RA-01"]
mitre_attack: []
---
# 🌐 JavaScript/Node.js代码审计 (JavaScript & Node.js Code Audit)

## 概述
审查JavaScript应用（前端和后端）中的安全漏洞，包括Node.js特有风险和客户端XSS、原型污染等问题。

## 核心技能

### 1. Node.js Web安全

```javascript
// --- NoSQL注入 (MongoDB) ---
// 危险
const user = await User.findOne({ username: req.body.username, password: req.body.password });

// 攻击payload: { "username": "admin", "password": { "$gt": "" } }
// 这将返回任何密码大于空字符串的admin用户

// 安全: 类型验证
if (typeof req.body.password !== 'string') {
    return res.status(400).send('Invalid input');
}
const user = await User.findOne({ username: req.body.username, password: req.body.password });

// --- 命令注入 ---
// 危险
const exec = require('child_process').exec;
exec('ping -c 3 ' + req.query.ip, (err, stdout) => {
    res.send(stdout);
});

// 安全
const execFile = require('child_process').execFile;
execFile('ping', ['-c', '3', validateIP(req.query.ip)], (err, stdout) => {
    res.send(stdout);
});

// --- 路径遍历 ---
// 危险
const fs = require('fs');
const data = fs.readFileSync('/var/www/files/' + req.params.file);

// 攻击: ../../../etc/passwd

// 安全
const path = require('path');
const safePath = path.resolve('/var/www/files/', path.basename(req.params.file));
// 检查路径是否在允许范围内
if (!safePath.startsWith('/var/www/files/')) {
    return res.status(403).send('Forbidden');
}
```

### 2. 原型污染

```javascript
// --- 原型污染漏洞 ---
// 危险操作
function merge(target, source) {
    for (let key in source) {
        if (source.hasOwnProperty(key)) {
            target[key] = source[key];  // 危险：可能覆盖原型属性
        }
    }
}

// 攻击payload: JSON.parse('{"__proto__": {"admin": true}}')
// 或: {"constructor": {"prototype": {"admin": true}}}

// 检测原型污染
// inquirer, lodash.merge, jQuery.extend 等常见库都曾受影响

// 安全合并
function safeMerge(target, source) {
    for (let key in source) {
        if (source.hasOwnProperty(key)) {
            if (key === '__proto__' || key === 'constructor') continue;
            if (typeof source[key] === 'object') {
                target[key] = safeMerge(target[key] || {}, source[key]);
            } else {
                target[key] = source[key];
            }
        }
    }
    return target;
}

// 防止原型污染的通用方法
Object.freeze(Object.prototype);
// 或使用 Map 替代对象
```

### 3. 前端XSS与DOM Clobbering

```javascript
// --- DOM XSS ---
// 危险
document.getElementById('output').innerHTML = location.hash.substring(1);
document.write('<div>' + new URLSearchParams(location.search).get('name') + '</div>');
element.innerHTML = userInput;

// 安全
document.getElementById('output').textContent = location.hash.substring(1);
element.textContent = userInput;

// --- DOM Clobbering ---
// 通过HTML元素覆盖DOM变量
// 攻击:
// <a id="config"></a>
// <a id="config" href="x:alert(1)"></a>

// 可能导致现有JS中的变量被覆盖
// 检测: 使用id/name属性的HTML元素

// --- 客户端模板注入 ---
// 危险 (Angular)
<div ng-bind-html="userInput"></div>
// 危险 (Vue)
<div v-html="userInput"></div>
// 安全
<div>{{ userInput }}</div>  // Vue自动转义
```

### 4. Express框架审计

```javascript
// --- helmet安全检查 ---
const express = require('express');
const helmet = require('helmet');
const app = express();

app.use(helmet());  // 设置安全响应头
// 包含: CSP, HSTS, X-Frame-Options, X-Content-Type-Options 等

// --- CSRF保护 ---
const csrf = require('csurf');
app.use(csrf({ cookie: true }));

// --- 速率限制 ---
const rateLimit = require('express-rate-limit');
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,  // 15分钟
    max: 100                    // 最多100次请求
});
app.use('/api/', limiter);

// --- Session配置 ---
const session = require('express-session');
app.use(session({
    secret: process.env.SESSION_SECRET,  // 使用环境变量
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: true,         // HTTPS
        sameSite: 'strict',
        maxAge: 3600000      // 1小时
    }
}));

// --- Body Parsers限制 ---
app.use(express.json({ limit: '1mb' }));  // 限制请求体大小
app.use(express.urlencoded({ extended: false, limit: '1mb' }));  // extended: false 防止嵌套对象

// --- 错误处理 ---
// 不要泄露敏感信息
app.use((err, req, res, next) => {
    console.error(err.stack);  // 服务端日志
    res.status(500).send('Internal Server Error');  // 通用错误响应
});
```

### 5. 依赖安全

```bash
# 检查已知漏洞的依赖
npm audit
npm audit --json
npm audit --audit-level=high

# 修复
npm audit fix
npm audit fix --force  # 可能破坏兼容性

# Yarn
yarn audit
yarn audit:json

# 检查过期包
npm outdated

# Snyk扫描
snyk test
snyk monitor

# 依赖锁定
# 确保使用 package-lock.json 或 yarn.lock
# 使用 npm ci 替代 npm install 确保一致性安装

# 检查恶意包
npm doctor
# 使用第三方工具: @snyk/protect

# 最小权限依赖
# 避免使用广泛权限的包
# 检查包的下载量和维护状况
```

### 6. 安全配置与中间件

```javascript
// --- CORS配置 ---
const cors = require('cors');
// 危险: * 通配符
app.use(cors());
// 安全: 白名单
app.use(cors({
    origin: ['https://example.com', 'https://admin.example.com'],
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    maxAge: 86400
}));

// --- Express Rate Limiting ---
// 建议对敏感端点使用更严格的限制
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: 'Too many login attempts, please try again later.'
});
app.use('/api/login', loginLimiter);

// --- Content Security Policy ---
app.use(helmet.contentSecurityPolicy({
    directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'strict-dynamic'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        frameSrc: ["'none'"],
        upgradeInsecureRequests: []
    }
}));

// --- 请求验证 (Joi/Zod) ---
const Joi = require('joi');
const schema = Joi.object({
    username: Joi.string().alphanum().min(3).max(30).required(),
    password: Joi.string().pattern(/^[a-zA-Z0-9]{8,30}$/),
    email: Joi.string().email()
});

app.post('/register', (req, res) => {
    const { error, value } = schema.validate(req.body);
    if (error) {
        return res.status(400).send(error.details[0].message);
    }
    // 安全使用已验证的 value
});
```

### 7. 常见漏洞模式与审计命令

```bash
# 搜索原型污染
grep -rn "__proto__\|constructor.prototype\|merge\|extend\|assign" --include="*.js" | grep -v "node_modules"

# 搜索eval相关
grep -rn "eval(\|setTimeout(\|setInterval(\|new Function(" --include="*.js"

# 搜索不安全的innerHTML
grep -rn "innerHTML\|outerHTML\|insertAdjacentHTML" --include="*.js"

# 搜索命令执行
grep -rn "exec(\|spawn(\|fork(\|execFile(" --include="*.js"

# 搜索文件操作
grep -rn "readFile\|writeFile\|createWriteStream\|createReadStream\|unlink\|rmdir" --include="*.js" | grep -v "node_modules"

# 搜索敏感信息
grep -rn "password\|secret\|token\|api_key\|apikey\|credential" --include="*.{js,env,json}" | grep -v "node_modules"

# 搜索不安全的正则表达式（ReDoS）
grep -rn "(\+.*)+" --include="*.js"  # 重复分组可能为ReDoS

# 检查环境变量
grep -rn "process\.env" --include="*.js" | grep -i "password\|secret\|key\|token"
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| ESLint Plugin Security | ESLint安全规则 | https://github.com/nodesecurity/eslint-plugin-security |
| NodeJsScan | Node.js安全扫描 | https://github.com/ajinabraham/NodeJsScan |
| npm audit | 依赖漏洞检查 | npm内置 |
| Retire.js | JS库漏洞检测 | https://retirejs.github.io/retire.js/ |
| Snyk | 依赖安全扫描 | https://snyk.io/ |
| SonarJS | JS代码质量 | https://www.sonarsource.com/ |

## 参考资源
- [OWASP Node.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
- [Node.js Security Checklist](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Nodejs_Security_Cheat_Sheet.md)
- [Snyk Blog - Node.js Security](https://snyk.io/blog/tag/node-js-security/)
- [PortSwigger - DOM-based Vulnerabilities](https://portswigger.net/web-security/dom-based)
