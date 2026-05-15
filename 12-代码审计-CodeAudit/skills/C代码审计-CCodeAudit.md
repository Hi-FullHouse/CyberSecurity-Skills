---
id: 12-003
title: "⚙️ C代码审计 (C Code Audit)"
category: 代码审计
category_en: "Code Audit"
difficulty: ★★★★
tools: "Flawfinder, Cppcheck, ASan, Valgrind"
last_updated: 2025-07
tags: ["code-audit", "static-analysis", "php-audit", "java-audit", "javascript-audit"]
subdomain: code-audit
nist_csf: ["PR.IP-12", "ID.RA-01"]
mitre_attack: []
---
# ⚙️ C代码审计 (C Code Audit)

## 概述
C语言因其底层内存操作能力而广泛应用于系统软件、嵌入式、内核模块和网络服务中。C代码的安全审计重点在于内存安全、未定义行为和危险的库函数使用。

## 核心技能

### 1. 缓冲区溢出 (Buffer Overflow)

```c
// --- 栈溢出 ---
// 危险: gets() 无边界检查
#include <stdio.h>
char buf[64];
gets(buf);  // 输入超过64字节即溢出

// 安全: 使用fgets
fgets(buf, sizeof(buf), stdin);

// --- sprintf溢出 ---
// 危险
char out[128];
sprintf(out, "User: %s (id: %d)", user_input, id);  // 如果user_input > 128字节则溢出

// 安全: 使用snprintf
snprintf(out, sizeof(out), "User: %s (id: %d)", user_input, id);

// --- strcpy/strcat溢出 ---
// 危险
char path[256];
strcpy(path, "/var/data/");
strcat(path, user_input);  // 用户输入过长则溢出

// 安全: 使用strlcpy/strlcat (BSD) 或 snprintf
snprintf(path, sizeof(path), "/var/data/%s", user_input);

// --- scanf家族 ---
// 危险
char name[32];
scanf("%s", name);  // 无长度限制

// 安全
scanf("%31s", name);  // 限制最大输入长度

// --- 内存拷贝溢出 ---
// 危险
char dst[64];
memcpy(dst, src, src_len);  // 如果src_len > 64则堆栈溢出

// 安全: 检查目标缓冲区大小
if (src_len <= sizeof(dst)) {
    memcpy(dst, src, src_len);
}
```

### 2. 格式化字符串漏洞 (Format String)

```c
// --- 格式化字符串攻击 ---
// 危险: 用户输入作为格式字符串
void log_message(char *user_input) {
    printf(user_input);  // 用户可传入 %x %n %s 等格式说明符
    fprintf(logfile, user_input);
}

// 攻击payload: "%x.%x.%x.%x.%n" 或 "%s%s%s%s"
// 利用: 读取栈内存 (%x), 任意写 (%n)

// 安全: 固定格式字符串
printf("%s", user_input);
fprintf(logfile, "%s", user_input);

// --- 审计搜索模式 ---
// grep -rn 'printf(user_input\|sprintf(buf, user_input\|fprintf(.*, user_input' --include="*.c"
// 查找任何非固定格式的 printf 类调用
```

### 3. 整数溢出与符号问题

```c
// --- 整数溢出导致缓冲区溢出 ---
// 危险
size_t len = get_user_len();
char *buf = malloc(len + 1);  // 如果 len = SIZE_MAX, len+1 = 0 → malloc(0)
if (buf) {
    memcpy(buf, user_data, len);  // 越界写入
}

// 安全: 检查溢出
if (len == SIZE_MAX) return ERROR;
char *buf = malloc(len + 1);

// --- 符号误用 ---
// 危险
int size = get_user_size();  // 用户可传入负数
char *buf = malloc(size);    // malloc(-1) → 分配失败或超大内存
if (buf) {
    memcpy(buf, data, size);  // 类型提升为size_t, 负数→超大值
}

// 安全: 检查非负
if (size <= 0 || size > MAX_SIZE) return ERROR;
char *buf = malloc((size_t)size);

// --- 整数回绕 ---
// 危险
int total = count * sizeof(element);  // 如果count很大可能回绕
char *buf = malloc(total);

// 安全
if (count > SIZE_MAX / sizeof(element)) return ERROR;
size_t total = (size_t)count * sizeof(element);
char *buf = malloc(total);
```

### 4. 释放后使用 (Use-After-Free) 与 双重释放

```c
// --- Use-After-Free ---
// 危险
char *ptr = malloc(64);
free(ptr);
strcpy(ptr, "data");  // 已释放的内存被使用

// 安全: 释放后置空
free(ptr);
ptr = NULL;

// --- 双重释放 ---
// 危险
free(ptr);
// ... 其他代码 ...
free(ptr);  // 二次释放导致堆损坏

// 安全: 释放后置空 + 释放前检查
free(ptr);
ptr = NULL;
// ...
if (ptr) {
    free(ptr);
    ptr = NULL;
}

// --- 野指针 ---
// 危险
char *ptr;  // 未初始化
strcpy(ptr, "data");  // 访问未初始化指针

// 安全
char *ptr = NULL;
ptr = malloc(64);
```

### 5. 内存泄漏

```c
// --- 内存泄漏模式 ---
// 危险: 错误路径未释放
char *read_file(const char *path) {
    char *buf = malloc(MAX_FILE_SIZE);
    FILE *f = fopen(path, "r");
    if (!f) {
        return NULL;  // 错误: buf 泄漏!
    }
    fread(buf, 1, MAX_FILE_SIZE, f);
    fclose(f);
    return buf;
}

// 安全: 错误路径释放
char *read_file(const char *path) {
    char *buf = malloc(MAX_FILE_SIZE);
    if (!buf) return NULL;
    FILE *f = fopen(path, "r");
    if (!f) {
        free(buf);  // 正确释放
        return NULL;
    }
    fread(buf, 1, MAX_FILE_SIZE, f);
    fclose(f);
    return buf;
}
```

### 6. 命令注入与shell调用

```c
// --- system/popen 注入 ---
// 危险
char cmd[256];
snprintf(cmd, sizeof(cmd), "ping -c 3 %s", user_input);
system(cmd);  // 用户输入含 ; rm -rf / 等

// 攻击: 127.0.0.1; rm -rf /

// 安全: 使用exec族函数替代
// 或用正则校验用户输入
if (!is_valid_ip(user_input)) return ERROR;

// --- popen 注入 ---
// 危险
FILE *fp = popen(user_input, "r");  // 直接执行用户输入

// 安全: 使用execvp等函数
pid_t pid = fork();
if (pid == 0) {
    execlp("ping", "ping", "-c", "3", sanitized_input, NULL);
}
```

### 7. 路径遍历与文件操作

```c
// --- 路径遍历 ---
// 危险
char path[256];
snprintf(path, sizeof(path), "/var/www/files/%s", user_input);
FILE *f = fopen(path, "r");  // ../../etc/passwd

// 攻击: ../../../etc/passwd

// 安全: 规范化并检查路径
char *real = realpath(user_input, NULL);
if (real && strncmp(real, "/var/www/files/", 15) == 0) {
    FILE *f = fopen(real, "r");
}
free(real);
```

### 8. 不安全的随机数

```c
// --- 弱随机数 ---
// 危险: rand() 可预测
srand(time(NULL));
int key = rand();  // 可预测的"随机"数

// 安全: 使用加密安全的随机数
// Linux: getrandom() / /dev/urandom
// Windows: CryptGenRandom()
unsigned int key;
int fd = open("/dev/urandom", O_RDONLY);
read(fd, &key, sizeof(key));
close(fd);
```

### 9. 整型到指针的转换

```c
// --- 类型混淆 ---
// 危险: 整型到指针的强制转换
int dev_id = get_user_dev_id();
void *ptr = (void *)(uintptr_t)dev_id;  // 用户控制指针值
*(int *)ptr = 42;  // 任意地址写

// 审计: 搜索 (void\*)(uintptr_t) 和类似模式
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Flawfinder | C/C++ 静态安全分析 | https://dwheeler.com/flawfinder/ |
| Cppcheck | C/C++ 静态分析 (含安全检测) | https://cppcheck.sourceforge.io/ |
| Clang Static Analyzer | LLVM 静态分析器 | https://clang-analyzer.llvm.org/ |
| AddressSanitizer (ASan) | 运行时内存错误检测 | GCC/Clang内置 (-fsanitize=address) |
| Valgrind (Memcheck) | 运行时内存泄漏/错误检测 | https://valgrind.org/ |
| UndefinedBehaviorSanitizer (UBSan) | 未定义行为检测 | -fsanitize=undefined |
| CodeQL | 语义代码分析 | https://codeql.github.com/ |
| Semgrep | 模式匹配SAST | https://semgrep.dev/ |

## 参考资源
- [SEI CERT C Coding Standard](https://wiki.sei.cmu.edu/confluence/display/c/SEI+CERT+C+Coding+Standard)
- [OWASP C-Based Toolchain Hardening](https://owasp.org/www-project-c-based-toolchain-hardening/)
- [CWE/SANS Top 25 Most Dangerous Software Errors](https://www.sans.org/top25-software-errors/)
- [Linux Kernel Security - Memory Safety](https://www.kernel.org/doc/html/latest/security/self-protection.html)
- [HackTricks - C Code Review](https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-ci-cd)
