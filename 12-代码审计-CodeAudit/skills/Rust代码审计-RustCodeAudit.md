---
id: 12-009
title: "🦀 Rust代码审计 (Rust Code Audit)"
category: 代码审计
category_en: "Code Audit"
difficulty: ★★★
tools: "Clippy, cargo-audit, cargo-geiger, Miri"
last_updated: 2025-07
tags: ["code-audit", "static-analysis", "php-audit", "java-audit", "javascript-audit"]
subdomain: code-audit
nist_csf: ["PR.IP-12", "ID.RA-01"]
mitre_attack: []
---
# 🦀 Rust代码审计 (Rust Code Audit)

## 概述
Rust通过所有权系统和借用检查器在编译时消除了大量内存安全漏洞，但其安全保证依赖于所有代码都是安全的（Safe Rust）。`unsafe` 代码块、FFI调用和不安全的宏可以绕过编译器检查，成为安全审计的重点区域。

## 核心技能

### 1. unsafe 代码审计

```rust
// --- 裸指针解引用 ---
// 危险: unsafe块中的裸指针操作
unsafe {
    let ptr = std::ptr::null::<i32>();
    println!("{}", *ptr);  // 空指针解引用!
}

// 安全: 始终检查指针有效性
unsafe {
    if !ptr.is_null() && /* 确保内存已分配并被正确初始化 */ {
        println!("{}", *ptr);
    }
}

// --- 可变别名与UB ---
// 危险: 同时存在可变和不可变引用
let mut data = 10;
let r1 = &data as *const i32;
let r2 = &mut data as *mut i32;
unsafe {
    println!("{}", *r1);  // 读取
    *r2 = 20;             // 写入 — 违反别名规则! UB
}

// --- 未初始化内存 ---
// 危险: 读取未初始化内存
use std::mem::MaybeUninit;
let mut uninit: MaybeUninit<[u8; 1024]> = MaybeUninit::uninit();
unsafe {
    let slice = &*uninit.as_ptr();  // 读取未初始化内存!
}

// 安全: 写入后再读取
let mut uninit = MaybeUninit::uninit();
uninit.write([0u8; 1024]);
unsafe {
    let slice = &*uninit.as_ptr();
}

// --- 未对齐指针 ---
// 危险: 未对齐访问 (部分架构上导致SIGBUS)
#[repr(packed)]
struct Packed {
    x: u8,
    y: u32,  // 未对齐
}
let p = Packed { x: 1, y: 2 };
unsafe {
    let ptr = &p.y as *const u32;
    let val = ptr.read_unaligned();  // 需要read_unaligned而非read
}
```

### 2. FFI与外部函数调用

```rust
// --- C库调用接收裸指针 ---
// 危险: 从C函数接收指针未检查有效性
extern "C" {
    fn get_string() -> *const libc::c_char;
}

unsafe {
    let s = std::ffi::CStr::from_ptr(get_string());  // 如果指针无效则UB
    println!("{:?}", s);
}

// 安全: 文档说明所有权和有效性保证
// 在FFI边界添加安全检查层

// --- CString生命周期 ---
// 危险: CString被释放后指针悬垂
unsafe {
    let p: *const libc::c_char;
    {
        let s = std::ffi::CString::new("hello").unwrap();
        p = s.as_ptr();  // p 引用了 s 的内部缓冲区
    }  // s 被释放, p 悬垂
    // 使用 p 是未定义行为
}

// --- 从C侧获取的可变指针 ---
// 危险: 不安全的FFI函数声明为返回可变指针
extern "C" {
    fn get_buffer() -> *mut u8;
}

unsafe {
    let buf = std::slice::from_raw_parts_mut(get_buffer(), 100);
    buf[0] = 42;  // 如果指针无效或越界则UB
}

// --- 违反Send/Sync特征 ---
// 危险: 将非Send类型发送到其他线程
struct NotSend(*const u8);
unsafe impl Send for NotSend {}  // 不安全的手动实现!

// 审计: 检查所有 unsafe impl Send/Sync
```

### 3. 生命周期与借用安全

```rust
// --- 生命周期延长导致悬垂引用 ---
// 危险: 返回内部引用
struct Container {
    data: Vec<u8>,
}
impl Container {
    fn get_ref(&self) -> &[u8] {
        &self.data
    }
    fn clear(&mut self) {
        self.data.clear();
    }
}

fn problem() {
    let c = Container { data: vec![1, 2, 3] };
    let r = c.get_ref();
    // drop(c);  // 如果c被移动/释放，r悬垂
    println!("{:?}", r);
}

// --- transmute 生命周期延长 ---
// 危险: 通过transmute绕过生命周期检查
fn extend_lifetime<'a, 'b>(x: &'a [u8]) -> &'b [u8] {
    unsafe { std::mem::transmute::<&'a [u8], &'b [u8]>(x) }
}

let r;
{
    let local = vec![1, 2, 3];
    r = extend_lifetime(&local);  // r的生命周期超过了local
}
println!("{:?}", r);  // 悬垂引用!

// 审计: 搜索所有 transmute 和 pointer::cast 用于生命周期转换
```

### 4. 不安全的宏和内联汇编

```rust
// --- 不安全的宏展开 ---
// 危险: 宏内部产生unsafe代码且使用者不知情
macro_rules! dangerous {
    ($ptr:expr) => {
        unsafe { *$ptr = 42; }
    };
}

let mut x = 0;
dangerous!(&mut x as *mut i32);  // 调用者可能不知道有unsafe

// 审计: 检查所有宏定义，看是否隐藏了unsafe操作

// --- 内联汇编 ---
// 危险: asm! 中的UB
unsafe {
    std::arch::asm!("nop");  // 简单nop通常安全
}

// 危险: 可能破坏栈帧
unsafe {
    std::arch::asm!("pop rax");  // 破坏栈平衡 → crash
}

// 审计: 审查所有 asm! 调用，确保遵守调用约定
```

### 5. 整数溢出与算术安全

```rust
// --- 默认溢出行为 ---
// 危险: debug模式panic, release模式回绕
let x: u8 = 200;
let y: u8 = 100;
let z = x + y;  // debug: panic, release: 44 (回绕)

// 安全: 使用显式算术方法
let z = x.checked_add(y).unwrap_or(u8::MAX);  // 检查溢出
// 或: x.saturating_add(y)  → 255
// 或: x.wrapping_add(y)    → 44 (显式回绕)
// 或: x.overflowing_add(y) → (44, true) (返回是否溢出)

// --- 有符号/无符号转换 ---
// 危险: 负数转换为无符号
let x: i32 = -1;
let y: u32 = x as u32;  // y = 4294967295 (非常大的值)
if y < 100 {  // 安全检查被绕过
    // 实际不会执行
}
```

### 6. 并发安全

```rust
// --- 数据竞争 ---
// 危险: 裸指针在线程间共享可变数据
unsafe {
    let mut data = 42;
    let ptr = &mut data as *mut i32;
    let handle = std::thread::spawn(move || {
        *ptr = 100;  // 数据竞争! main线程可能同时访问data
    });
    println!("{}", data);  // 读取
    handle.join().unwrap();
}

// 安全: 使用Mutex/Atomic/RwLock
use std::sync::{Arc, Mutex};
let data = Arc::new(Mutex::new(42));
let data_clone = data.clone();
let handle = std::thread::spawn(move || {
    *data_clone.lock().unwrap() = 100;
});
println!("{}", *data.lock().unwrap());
handle.join().unwrap();

// --- 不安全地实现Sync ---
struct MyCell<T>(std::cell::UnsafeCell<T>);
unsafe impl<T> Sync for MyCell<T> {}  // 错误! UnsafeCell不是Sync

// 审计: 检查所有unsafe impl Sync/Send的实现
```

### 7. 密码学与安全API误用

```rust
// --- 不安全的随机数 ---
// 危险: 使用非加密安全随机数
use rand::Rng;
let key: [u8; 32] = rand::thread_rng().gen();  // 使用ChaCha12, 通常是安全的
// 但: rand 默认是密码学安全的，使用 rand::rngs::StdRng 代替

// 安全: 明确使用加密安全随机数
use rand::rngs::OsRng;
use rand::RngCore;
let mut key = [0u8; 32];
OsRng.fill_bytes(&mut key);

// --- 时间比较 ---
// 危险: 非恒定时间比较
fn verify_token(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    for i in 0..a.len() {
        if a[i] != b[i] { return false; }  // 时间攻击
    }
    true
}

// 安全: 恒定时间比较
use subtle::ConstantTimeEq;
fn verify_token(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}
```

## 审计命令速查

```bash
# 搜索 unsafe 块
grep -rn "unsafe\s*{" --include="*.rs" | grep -v "^\s*//" | grep -v "test\|#\["

# 搜索 unsafe impl
grep -rn "unsafe impl" --include="*.rs"

# 搜索 raw pointer 操作
grep -rn "as \*const\|as \*mut\|from_raw_parts\|from_raw_parts_mut" --include="*.rs"

# 搜索 transmute 调用
grep -rn "transmute\|transmute_copy" --include="*.rs"

# 搜索 FFI 声明
grep -rn 'extern "C"' --include="*.rs"

# 搜索 MaybeUninit 使用
grep -rn "MaybeUninit\|uninit()" --include="*.rs"

# 搜索非安全算术
grep -rn "as \|unwrap()" --include="*.rs"

# Clippy安全检查
cargo clippy -- -W clippy::pedantic -W clippy::nursery -W clippy::cargo

# cargo-audit (Cargo.lock中的漏洞)
cargo audit

# cargo-geiger (unsafe统计)
cargo geiger
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Clippy | Rust官方lint工具 (含安全规则) | `rustup component add clippy` |
| cargo-audit | 依赖漏洞检查 | https://crates.io/crates/cargo-audit |
| cargo-geiger | unsafe代码统计 | https://crates.io/crates/cargo-geiger |
| cargo-deny | 许可证/安全策略 | https://crates.io/crates/cargo-deny |
| Miri | 未定义行为检测器 | `rustup component add miri` |
| RustSec Advisory DB | 安全公告数据库 | https://rustsec.org/ |
| Semgrep | 模式匹配SAST (支持Rust) | https://semgrep.dev/ |
| CodeQL | 语义代码分析 | https://codeql.github.com/ |

## 参考资源
- [The Rustonomicon (Unsafe Rust指南)](https://doc.rust-lang.org/nomicon/)
- [Rust Security Cheat Sheet](https://github.com/rust-secure-code/safety-dance/)
- [RustSec Advisory Database](https://rustsec.org/)
- [SEI CERT Rust Coding Standard (Draft)](https://wiki.sei.cmu.edu/confluence/display/cplusplus/SEI+CERT+C%2B%2B+Coding+Standard)
- [Rust API Guidelines - Safety](https://rust-lang.github.io/api-guidelines/)
- [HackTricks - Rust Review](https://book.hacktricks.xyz/)
