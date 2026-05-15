---
id: 12-002
title: "🔧 C++代码审计 (C++ Code Audit)"
category: 代码审计
category_en: "Code Audit"
difficulty: ★★★★
tools: "Cppcheck, Clang-Tidy, PVS-Studio, CodeQL"
last_updated: 2025-07
tags: ["code-audit", "static-analysis", "php-audit", "java-audit", "javascript-audit"]
subdomain: code-audit
nist_csf: ["PR.IP-12", "ID.RA-01"]
mitre_attack: []
---
# 🔧 C++代码审计 (C++ Code Audit)

## 概述
C++在C语言基础上增加了面向对象、泛型编程和RAII等特性。C++审计除了继承C语言的缓冲区溢出等问题外，还需关注虚函数劫持、智能指针误用、STL安全、异常安全和模板元编程等特有的安全风险。

## 核心技能

### 1. C语言继承的安全问题

```cpp
// C++ 依然存在所有C语言的安全问题:
// - 缓冲区溢出 (strcpy, sprintf, gets等)
// - 格式化字符串漏洞
// - 整数溢出
// - Use-After-Free
// - 内存泄漏
// 参考 C代码审计 中的对应章节

// C++ 推荐使用安全的替代方案:
// 危险: C风格
char buf[64];
sprintf(buf, "%s", data);

// 安全: C++风格
std::string buf = data;
std::ostringstream oss;
oss << data;
```

### 2. 智能指针误用

```cpp
// --- 循环引用导致内存泄漏 ---
// 危险: shared_ptr 循环引用
struct B;
struct A {
    std::shared_ptr<B> b_ptr;
    ~A() { std::cout << "A destroyed\n"; }
};
struct B {
    std::shared_ptr<A> a_ptr;  // 循环引用!
    ~B() { std::cout << "B destroyed\n"; }
};

auto a = std::make_shared<A>();
auto b = std::make_shared<B>();
a->b_ptr = b;
b->a_ptr = a;  // 两者都不会被释放

// 安全: 使用weak_ptr打破循环
struct B {
    std::weak_ptr<A> a_ptr;  // 不增加引用计数
};

// --- 裸指针与智能指针混用 ---
// 危险
auto sp = std::make_shared<int>(42);
int *raw = sp.get();
delete raw;  // 双重释放! sp析构时会再次delete

// 危险: 同一裸指针被两个智能指针管理
int *raw = new int(42);
std::unique_ptr<int> u1(raw);
std::unique_ptr<int> u2(raw);  // 双重释放!

// --- 自定义删除器绕过 ---
// 危险: 删除器不匹配
auto sp = std::shared_ptr<int>(new int[10]);  // 应为 new int[10] 对应 delete[]
// 正确
auto sp = std::shared_ptr<int>(new int[10], std::default_delete<int[]>());

// --- reset后继续使用 ---
auto p = std::make_shared<int>(42);
p.reset();       // 内存已释放
*p = 10;         // Use-After-Free!
```

### 3. 虚函数劫持 (Vtable劫持)

```cpp
// --- 虚函数表覆写 ---
// 危险: UAF导致vtable被篡改
class Base {
public:
    virtual void doSomething() { std::cout << "Safe operation\n"; }
};

Base *obj = new Base();
delete obj;
// 攻击者控制释放后的内存，篡改vtable指针
// obj->doSomething();  // 可能执行任意代码

// --- 对象切片 ---
// 危险: 按值传递导致虚函数调用失败
void process(Base base) {  // 按值传递 → 对象切片
    base.doSomething();    // 调用Base::doSomething, 不是派生类版本
}

// 安全: 使用指针或引用
void process(Base &base) {
    base.doSomething();
}
```

### 4. STL容器安全

```cpp
// --- 迭代器失效 ---
// 危险: 插入/删除使迭代器失效
std::vector<int> v = {1, 2, 3, 4, 5};
for (auto it = v.begin(); it != v.end(); ++it) {
    if (*it % 2 == 0) {
        v.erase(it);  // 迭代器已失效! 未定义行为
    }
}

// 安全: 使用erase返回值
for (auto it = v.begin(); it != v.end(); ) {
    if (*it % 2 == 0) {
        it = v.erase(it);  // erase返回下一个有效迭代器
    } else {
        ++it;
    }
}

// 使用.erase(std::remove_if(...), v.end()) 也可以

// --- 未定义下标访问 ---
// 危险: operator[] 越界
std::vector<int> v(10);
v[100] = 42;  // 未定义行为，越界写入

// 安全: 使用at() 或 检查边界
v.at(100) = 42;  // 抛出 std::out_of_range

// --- string::c_str() 生命周期 ---
// 危险
const char *get_data() {
    std::string s = "temporary";
    return s.c_str();  // 悬垂指针! s析构后c_str失效
}

// 安全: 返回string而不是const char*
```

### 5. 异常安全

```cpp
// --- 构造函数中异常导致资源泄漏 ---
class ResourceHolder {
    int *a;
    int *b;
public:
    ResourceHolder() {
        a = new int(10);
        b = new int(20);  // 如果这里抛出异常, a 泄漏
    }
    ~ResourceHolder() {
        delete a;
        delete b;
    }
};

// 安全: 使用RAII封装
class ResourceHolder {
    std::unique_ptr<int> a;
    std::unique_ptr<int> b;
public:
    ResourceHolder() 
        : a(std::make_unique<int>(10))
        , b(std::make_unique<int>(20)) {}
    // 无需自定义析构函数
};

// --- 析构函数抛出异常 ---
// 危险
class Bad {
public:
    ~Bad() {
        throw std::runtime_error("error");  // 析构函数抛出异常 → terminate!
    }
};
```

### 6. 类型混淆与未定义行为

```cpp
// --- reinterpret_cast 滥用 ---
// 危险: 类型双关
float f = 3.14f;
int *i = reinterpret_cast<int*>(&f);  // strict aliasing 违规

// 安全: 使用 memcpy 或 std::bit_cast
int i;
std::memcpy(&i, &f, sizeof(f));  // C++20: std::bit_cast<int>(f);

// --- const_cast 修改const对象 ---
const int x = 10;
int *p = const_cast<int*>(&x);
*p = 20;  // 未定义行为! x可能存储在只读内存中

// --- 联合体类型混淆 ---
union { int i; float f; } u;
u.i = 42;
std::cout << u.f;  // 未定义行为 (除了C++20的active member)
```

### 7. 竞态条件与并发安全

```cpp
// --- 数据竞争 ---
// 危险: 无锁保护
int counter = 0;
void increment() { ++counter; }  // 多个线程同时调用

// 安全: 使用原子操作或互斥锁
std::atomic<int> counter{0};
void increment() { ++counter; }

// 或
std::mutex mtx;
int counter = 0;
void increment() {
    std::lock_guard<std::mutex> lock(mtx);
    ++counter;
}

// --- 双重检查锁定 (Double-Checked Locking) ---
// 危险: 未使用原子操作的单例
static MySingleton* instance = nullptr;
std::mutex mtx;
MySingleton* getInstance() {
    if (!instance) {          // 第一次检查 (无锁)
        std::lock_guard<std::mutex> lock(mtx);
        if (!instance) {      // 第二次检查 (加锁)
            instance = new MySingleton();  // 可能重排序!
        }
    }
    return instance;
}

// 安全: C++11 以后使用局部静态变量 (线程安全初始化)
MySingleton& getInstance() {
    static MySingleton instance;  // C++11确保线程安全初始化
    return instance;
}
```

### 8. 不安全的标准库函数

```cpp
// --- std::locale / global locale 注入 ---
// 危险: 用户控制locale可能导致任意文件读取
std::locale::global(std::locale(user_input));  // 可能加载任意 .mo 文件

// --- std::regex 拒绝服务 (ReDoS) ---
// 危险: 用户提供的正则表达式可能导致灾难性回溯
std::regex re(user_input);  // 如果输入是 (a+)+b 匹配 aaaaaaaaaaac → 超时

// 安全: 限制正则表达式来源，设置超时

// --- std::filesystem 路径遍历 ---
// 危险
namespace fs = std::filesystem;
fs::remove(fs::path(user_input));  // ../../etc/passwd

// 安全: 限制路径范围
fs::path base = "/safe/dir";
fs::path full = base / user_input;
fs::path canonical = fs::weakly_canonical(full);
if (canonical.string().starts_with(base.string())) {
    fs::remove(canonical);
}
```

## 审计命令速查

```bash
# 搜索危险C函数
grep -rn "strcpy\|strcat\|sprintf\|gets\|scanf" --include="*.cpp" --include="*.cc" --include="*.cxx"

# 搜索格式化字符串
grep -rn 'printf(.*"%\|fprintf(.*"%\|sprintf(.*"%' --include="*.cpp" | grep -v '"%s"\|"%d"'

# 搜索裸new (未使用智能指针)
grep -rn "new " --include="*.cpp" | grep -v "make_unique\|make_shared\|unique_ptr\|shared_ptr"

# 搜索reinterpret_cast (类型混淆风险)
grep -rn "reinterpret_cast" --include="*.cpp"

# 搜索const_cast
grep -rn "const_cast" --include="*.cpp"

# 搜索可能的数据竞争 (无保护的共享数据)
grep -rn "static.*int\|static.*bool\|static.*char" --include="*.cpp"

# 搜索删除器问题
grep -rn "new \[\]" --include="*.cpp"
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Cppcheck | C/C++ 静态分析 (含安全规则) | https://cppcheck.sourceforge.io/ |
| Clang-Tidy | LLVM 代码检查 + 安全规则 | https://clang.llvm.org/extra/clang-tidy/ |
| Clang Static Analyzer | 深度路径分析 | https://clang-analyzer.llvm.org/ |
| Flawfinder | C/C++ 安全扫描 | https://dwheeler.com/flawfinder/ |
| PVS-Studio | 商业C++静态分析 | https://pvs-studio.com/ |
| Coverity | 商业SAST工具 | https://scan.coverity.com/ |
| CodeQL | 语义代码分析 | https://codeql.github.com/ |
| AddressSanitizer | 运行时内存错误检测 | -fsanitize=address,undefined |
| ThreadSanitizer | 数据竞争检测 | -fsanitize=thread |

## 参考资源
- [SEI CERT C++ Coding Standard](https://wiki.sei.cmu.edu/confluence/display/cplusplus/SEI+CERT+C%2B%2B+Coding+Standard)
- [C++ Core Guidelines - Safety](https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines)
- [OWASP C++ Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/C-Based_Toolchain_Hardening_Cheat_Sheet.html)
- [CWE - C++ Specific Issues](https://cwe.mitre.org/data/definitions/681.html)
- [HackTricks - C++ Review](https://book.hacktricks.xyz/)
