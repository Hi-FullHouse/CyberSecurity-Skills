---
id: 12-004
title: "🐹 Go代码审计 (Go Code Audit)"
category: 代码审计
category_en: "Code Audit"
difficulty: ★★★
tools: "gosec, staticcheck, govulncheck, Semgrep"
last_updated: 2025-07
tags: ["code-audit", "static-analysis", "php-audit", "java-audit", "javascript-audit"]
subdomain: code-audit
nist_csf: ["PR.IP-12", "ID.RA-01"]
mitre_attack: []
---
# 🐹 Go代码审计 (Go Code Audit)

## 概述
Go语言以内存安全（带GC、无野指针）和并发原语著称，但依然存在Web安全漏洞、配置错误、加密API误用、竞争条件和逻辑漏洞等风险。Go代码审计的重点在于数据流安全、并发安全和配置安全。

## 核心技能

### 1. SQL注入

```go
// --- 字符串拼接SQL ---
// 危险: 直接拼接SQL
func getUser(w http.ResponseWriter, r *http.Request) {
    id := r.URL.Query().Get("id")
    query := fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", id)  // 注入!
    rows, _ := db.Query(query)
}

// 攻击: id=1' OR '1'='1

// 安全: 参数化查询
func getUser(w http.ResponseWriter, r *http.Request) {
    id := r.URL.Query().Get("id")
    query := "SELECT * FROM users WHERE id = ?"
    rows, _ := db.Query(query, id)  // 驱动会处理转义
}

// --- 使用database/sql + 字符串生成 ---
// 危险: 排序/列名参数化
func getItems(w http.ResponseWriter, r *http.Request) {
    order := r.URL.Query().Get("order")         // "name; DROP TABLE items"
    query := "SELECT * FROM items ORDER BY " + order  // ORDER BY 不支持?
    rows, _ := db.Query(query)
}

// 安全: 白名单验证
var allowedOrders = map[string]bool{"name": true, "price": true, "date": true}
func getItems(w http.ResponseWriter, r *http.Request) {
    order := r.URL.Query().Get("order")
    if !allowedOrders[order] {
        order = "name"  // 默认值
    }
    query := "SELECT * FROM items ORDER BY " + order
}

// --- GORM ORM安全问题 ---
// 危险: Where 中的字符串注入
db.Where("name = " + r.URL.Query().Get("name")).Find(&users)

// 安全: 使用?占位符
db.Where("name = ?", r.URL.Query().Get("name")).Find(&users)
```

### 2. 命令注入

```go
// --- os/exec 命令注入 ---
// 危险: shell 执行
func ping(w http.ResponseWriter, r *http.Request) {
    ip := r.URL.Query().Get("ip")
    cmd := exec.Command("sh", "-c", "ping -c 3 "+ip)  // shell注入!
    out, _ := cmd.Output()
    w.Write(out)
}

// 攻击: ip=127.0.0.1; rm -rf /

// 安全: 不使用shell, 直接传递参数
func ping(w http.ResponseWriter, r *http.Request) {
    ip := r.URL.Query().Get("ip")
    if !isValidIP(ip) {
        http.Error(w, "invalid ip", 400)
        return
    }
    cmd := exec.Command("ping", "-c", "3", ip)  // 参数分离, 无shell注入
    out, _ := cmd.Output()
    w.Write(out)
}

// --- 危险的 syscall.Exec ---
// 危险: 用户输入控制命令行
syscall.Exec("/bin/sh", []string{"sh", "-c", userInput}, os.Environ())
```

### 3. 路径遍历

```go
// --- 文件读取路径遍历 ---
// 危险
func readFile(w http.ResponseWriter, r *http.Request) {
    filename := r.URL.Query().Get("file")
    data, _ := os.ReadFile("/var/www/data/" + filename)  // ../../etc/passwd
    w.Write(data)
}

// 安全: 路径清理和检查
func readFile(w http.ResponseWriter, r *http.Request) {
    filename := r.URL.Query().Get("file")
    
    // 使用path.Clean清理路径
    cleanPath := filepath.Clean("/var/www/data/" + filename)
    
    // 确保在允许的目录内
    allowedBase := "/var/www/data/"
    if !strings.HasPrefix(cleanPath, allowedBase) {
        http.Error(w, "access denied", 403)
        return
    }
    
    data, _ := os.ReadFile(cleanPath)
    w.Write(data)
}

// --- http.Dir 遍历 ---
// 危险
http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("/var/www/static/"))))
// 如果Go版本较旧, 可能存在路径遍历漏洞

// 安全: 检查Go版本 >= 1.20 (修复了目录遍历)
```

### 4. SSRF (服务端请求伪造)

```go
// --- 未验证URL的请求 ---
// 危险
func proxy(w http.ResponseWriter, r *http.Request) {
    target := r.URL.Query().Get("url")
    resp, _ := http.Get(target)  // 可请求内网: http://169.254.169.254/latest/meta-data/
    io.Copy(w, resp.Body)
}

// 安全: URL验证 + IP检查
func proxy(w http.ResponseWriter, r *http.Request) {
    target := r.URL.Query().Get("url")
    
    parsedURL, err := url.Parse(target)
    if err != nil { http.Error(w, "invalid url", 400); return }
    
    // 阻止内网地址
    ips, _ := net.LookupIP(parsedURL.Hostname())
    for _, ip := range ips {
        if ip.IsPrivate() || ip.IsLoopback() {
            http.Error(w, "access denied", 403)
            return
        }
    }
    
    // 白名单验证
    allowedHosts := []string{"api.example.com", "data.example.com"}
    if !contains(allowedHosts, parsedURL.Hostname()) {
        http.Error(w, "host not allowed", 403)
        return
    }
    
    resp, _ := http.Get(target)
    io.Copy(w, resp.Body)
}

// --- net.Dial SSRF ---
// 危险: 用户控制的地址
conn, _ := net.Dial("tcp", userInput)  // 可连接内网redis/mysql
```

### 5. 反序列化漏洞

```go
// --- encoding/gob 反序列化 ---
// 危险: 从不可信源反序列化
func decode(data []byte) {
    var obj MyStruct
    dec := gob.NewDecoder(bytes.NewReader(data))
    dec.Decode(&obj)  // gob解码过程中可能执行意外的内存分配
}

// --- encoding/json 中的意外字段 ---
// 危险: 接受额外字段
type User struct {
    Name     string `json:"name"`
    Password string `json:"-"`
}

var u User
json.Unmarshal([]byte(`{"name":"admin","role":"admin"}`), &u)  // role字段被忽略

// 安全: 使用 DisallowUnknownFields
dec := json.NewDecoder(body)
dec.DisallowUnknownFields()
dec.Decode(&u)

// --- yaml/v2 反序列化 ---
// 危险: !!map 标签可实现任意类型
// yaml: !!map { !!python/object:xxx ... }

// 安全: 限制yaml解码器
yaml.Unmarshal(data, &obj)  // 确保obj类型明确
```

### 6. 竞争条件 (Race Condition)

```go
// --- TOCTOU (Time-of-Check-Time-of-Use) ---
// 危险: 先检查后使用
func checkAndWrite(filename string) error {
    if _, err := os.Stat(filename); os.IsNotExist(err) {
        // 此时文件可能已经被创建 (竞态)
        return os.WriteFile(filename, []byte("data"), 0644)
    }
    return nil
}

// 安全: 使用O_EXCL原子创建
func checkAndWrite(filename string) error {
    f, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
    if err != nil {
        return err  // 文件已存在或创建失败
    }
    defer f.Close()
    _, err = f.Write([]byte("data"))
    return err
}

// --- map 并发读写 ---
// 危险: 无锁的map并发访问
var cache = make(map[string]string)

func setCache(k, v string) { cache[k] = v }  // 并发写 → fatal error: concurrent map writes
func getCache(k string) string { return cache[k] }

// 安全: 使用 sync.Map 或 sync.RWMutex
var cache sync.Map
func setCache(k, v string) { cache.Store(k, v) }
func getCache(k string) string { v, _ := cache.Load(k); return v.(string) }

// --- 共享变量无保护 ---
// 危险
var counter int
func increment() { counter++ }  // 非原子操作, 数据竞争

// 安全: 使用原子操作
var counter atomic.Int64
func increment() { counter.Add(1) }
```

### 7. 加密API误用

```go
// --- 弱哈希 ---
// 危险: MD5/SHA1用于密码
hash := md5.Sum([]byte(password))  // 可快速暴力破解

// 安全: 使用bcrypt/scrypt/Argon2
hashed, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

// --- ECB模式加密 ---
// 危险: AES-ECB
block, _ := aes.NewCipher(key)
// ECB模式下相同明文块产生相同密文块

// 安全: AES-GCM (认证加密)
block, _ := aes.NewCipher(key)
gcm, _ := cipher.NewGCM(block)
nonce := make([]byte, gcm.NonceSize())
ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

// --- 不安全随机数 ---
// 危险: math/rand 用于安全场景
import "math/rand"
key := make([]byte, 32)
rand.Read(key)  // 可预测!

// 安全: crypto/rand
import cryptorand "crypto/rand"
key := make([]byte, 32)
cryptorand.Read(key)

// --- TLS配置弱化 ---
// 危险: 不安全的TLS配置
tlsConfig := &tls.Config{
    InsecureSkipVerify: true,        // 跳过证书验证
    MinVersion: tls.VersionTLS10,    // 支持TLS 1.0 (已废弃)
    CipherSuites: []uint16{
        tls.TLS_RSA_WITH_RC4_128_SHA,  // RC4已破解
    },
}
```

### 8. 日志注入与信息泄露

```go
// --- 日志注入 ---
// 危险: 直接记录用户输入
log.Printf("User login: %s", userInput)  // 可伪造日志条目
// 攻击: userInput = "admin\n[INFO] Transfer completed: $1000000"

// 安全: 清理换行符
safe := strings.ReplaceAll(userInput, "\n", "_")
log.Printf("User login: %s", safe)

// --- 敏感信息泄露 ---
// 危险: 打印/记录敏感数据
log.Printf("Password: %s", password)
log.Printf("Token: %s", token)
fmt.Sprintf("conn string: %s", dsn)

// 安全: 脱敏
log.Printf("Password: [redacted]")
```

### 9. 配置与嵌入安全

```go
// --- 硬编码凭证 ---
// 危险: 源码中的硬编码密钥
const apiKey = "sk-xxxxxxxxxxxxxxxxxxxxx"
const dbPassword = "password123"

// 安全: 使用环境变量
apiKey := os.Getenv("API_KEY")
dbPassword := os.Getenv("DB_PASSWORD")

// --- 调试端点泄露 ---
// 危险: pprof 在生成环境暴露
import _ "net/http/pprof"  // 如果默认mux被使用, pprof端点公开

// 安全: 只在debug模式下注册
if os.Getenv("DEBUG") == "1" {
    runtime.SetBlockProfileRate(1)
}

// --- embed 目录遍历 ---
// go:embed 目录默认允许遍历子目录
//go:embed templates/*
var templates embed.FS  // 嵌入所有文件, 包括子目录
```

## 审计命令速查

```bash
# 运行 gosec 安全检查
gosec ./...

# 运行 staticcheck
staticcheck ./...

# 运行 govulncheck (Go漏洞扫描)
govulncheck ./...

# 搜索SQL注入风险 (字符串拼接SQL)
grep -rn 'fmt.Sprintf.*SELECT\|fmt.Sprintf.*INSERT\|fmt.Sprintf.*UPDATE\|fmt.Sprintf.*DELETE' --include="*.go" | grep '"%[^s]'

# 搜索命令注入
grep -rn 'exec\.Command.*sh\|exec\.Command.*bash' --include="*.go"

# 搜索路径遍历
grep -rn 'os\.ReadFile\|os\.Open\|ioutil\.ReadFile' --include="*.go"

# 搜索未验证的http.Get
grep -rn 'http\.Get\|http\.Post\|http\.Do' --include="*.go"

# 搜索硬编码密码/密钥
grep -rn 'password\|secret\|apiKey\|token' --include="*.go" | grep -v 'os\.Getenv\|\.env\|_test\|mock'

# 搜索弱哈希
grep -rn 'md5\.\|sha1\.\|crypto/md5\|crypto/sha1' --include="*.go"

# 搜索竞争条件 (无保护的goroutine共享数据)
grep -rn 'go func\|sync\.WaitGroup' --include="*.go" | grep -v 'sync\.Mutex\|atomic\|channel'

# 搜索 InsecureSkipVerify
grep -rn 'InsecureSkipVerify:.*true' --include="*.go"

# 搜索 debug/pprof
grep -rn 'net/http/pprof' --include="*.go"

# 搜索不安全的反序列化
grep -rn 'gob\.NewDecoder\|yaml\.Unmarshal\|xml\.Unmarshal' --include="*.go"
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| gosec | Go安全静态分析 | https://github.com/securego/gosec |
| staticcheck | Go静态代码检查 | https://staticcheck.io/ |
| govulncheck | Go漏洞扫描 | https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck |
| Semgrep | 模式匹配SAST (支持Go) | https://semgrep.dev/ |
| CodeQL | 语义代码分析 | https://codeql.github.com/ |
| go-safety | Go安全检查器 | https://github.com/nickng/go-safety |
| OWASP Dependency Check | 依赖漏洞检查 | https://owasp.org/www-project-dependency-check/ |
| race detector | Go内置竞态检测 | `go run -race` / `go build -race` |

## 参考资源
- [OWASP Go Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Go_Security_Cheat_Sheet.html)
- [Go Security Policy](https://go.dev/security)
- [Go Wiki - Security](https://go.dev/wiki/Security)
- [Secure Go Coding Practices](https://github.com/OWASP/Go-SCP)
- [HackTricks - Go Review](https://book.hacktricks.xyz/)
- [gosec Rule Documentation](https://github.com/securego/gosec#available-rules)
