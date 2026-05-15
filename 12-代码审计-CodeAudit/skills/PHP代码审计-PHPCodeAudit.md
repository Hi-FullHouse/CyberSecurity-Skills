---
id: 12-007
title: "🔍 PHP代码审计 (PHP Code Audit)"
category: 代码审计
category_en: "Code Audit"
difficulty: ★★★
tools: "RIPS, phpcs, Psalm, Phan, 手动审查"
last_updated: 2025-07
tags: ["code-audit", "static-analysis", "php-audit", "java-audit", "javascript-audit"]
subdomain: code-audit
nist_csf: ["PR.IP-12", "ID.RA-01"]
mitre_attack: []
---
# 🔍 PHP代码审计 (PHP Code Audit)

## 概述
通过静态分析技术审查PHP代码中的安全漏洞，发现常见的Web安全问题如注入、文件操作和反序列化漏洞。

## 核心技能

### 1. 常见PHP漏洞模式

```php
// --- SQL注入 ---
// 危险代码
$sql = "SELECT * FROM users WHERE id = " . $_GET['id'];
mysql_query($sql);

// 安全代码（参数化查询）
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$_GET['id']]);

// --- XSS (反射型) ---
// 危险代码
echo "Welcome, " . $_GET['name'];

// 安全代码
echo "Welcome, " . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');

// --- 命令注入 ---
// 危险代码
$output = shell_exec("ping -c 3 " . $_POST['ip']);
system("nslookup " . $_GET['host']);

// 安全代码
$ip = filter_var($_POST['ip'], FILTER_VALIDATE_IP);
if ($ip) {
    $output = shell_exec("ping -c 3 " . escapeshellarg($ip));
}

// --- 文件包含 ---
// 危险代码
include($_GET['page'] . '.php');  // LFI/RFI

// 安全代码
$allowed_pages = ['home', 'about', 'contact'];
$page = in_array($_GET['page'], $allowed_pages) ? $_GET['page'] : 'home';
include($page . '.php');

// --- 文件上传 ---
// 危险代码
move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $_FILES['file']['name']);

// 安全代码
$allowed = ['jpg', 'png', 'gif', 'pdf'];
$ext = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));
if (in_array($ext, $allowed)) {
    $new_name = md5(uniqid()) . '.' . $ext;
    move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $new_name);
}
```

### 2. 危险函数审计清单

```php
// --- 命令执行类 ---
// 危险：直接执行系统命令
system()     // 输出并返回最后一行
exec()       // 返回最后一行
shell_exec() // 返回整个输出
passthru()   // 直接输出原始结果
popen()      // 通过管道执行
proc_open()  // 高级进程执行
pcntl_exec() // 当前进程执行
反引号 ``     // 等同于shell_exec()

// --- 文件操作类 ---
// 危险：文件包含
include()
include_once()
require()
require_once()
file_get_contents()  // 打开远程文件（allow_url_fopen开启时）
file_put_contents()
fopen()
unlink()     // 文件删除

// --- 代码执行类 ---
// 危险：动态执行代码
eval()
assert()     // 在旧版本中可执行代码
preg_replace('/pattern/e', 'code', $subject)  // /e修饰符（PHP < 5.5）
create_function()  // 已弃用
call_user_func()
call_user_func_array()
array_map()
array_filter()  // 如果回调参数可控

// --- 信息泄露类 ---
phpinfo()
var_dump()
print_r()    // 输出到页面
var_export()
debug_zval_refs()
error_reporting(E_ALL)  // 生产环境不应该显示错误

// --- 其它危险 ---
// 反序列化
unserialize($user_input)
// 类型混淆
if (strpos($_GET['admin'], 'true'))  // 0 == 'true' 为假，'true' == 0 也为假
// 文件下载
readfile()
file()
```

### 3. 反序列化漏洞审计

```php
// --- 反序列化漏洞检测 ---
// 搜索unserialize()调用
$data = unserialize($_POST['data']);  // 危险

// 检查魔法方法
// __wakeup() - unserialize时自动调用
// __destruct() - 对象销毁时自动调用
// __toString() - 对象转字符串时自动调用
// __call() - 调用不存在的方法时
// __get() - 访问不存在的属性时
// __set() - 设置不存在的属性时

// 典型POP链检测
class FileReader {
    public $filename;
    
    function __toString() {
        return file_get_contents($this->filename);  // 文件读取
    }
}

class Logger {
    public $log;
    
    function __destruct() {
        echo $this->log;  // 触发__toString
    }
}

// 利用链: unserialize -> __destruct -> __toString -> 读取文件
```

### 4. 配置安全审计

```php
// php.ini 安全配置检查
// 关键配置项
ini_get('allow_url_fopen');      // 应设为 Off
ini_get('allow_url_include');    // 应设为 Off
ini_get('disable_functions');    // 应禁用危险函数: exec,system,passthru,shell_exec,popen,proc_open,eval,assert
ini_get('open_basedir');         // 应限制目录范围
ini_get('display_errors');       // 生产环境应设为 Off
ini_get('expose_php');           // 应设为 Off
ini_get('session.cookie_httponly');  // 应设为 On
ini_get('session.cookie_secure');    // HTTPS环境下应设为 On
ini_get('session.use_only_cookies'); // 应设为 On
ini_get('session.use_strict_mode');  // 应设为 On
ini_get('session.sid_length');       // 建议 48+
ini_get('session.sid_bits_per_character');  // 建议 6

// 检查文件上传配置
ini_get('file_uploads');          // 如不需要上传功能，设为 Off
ini_get('upload_max_filesize');   // 限制上传大小
ini_get('post_max_size');         // 限制POST数据大小
ini_get('upload_tmp_dir');        // 确保在受限目录

// 检查资源限制
ini_get('max_execution_time');    // 执行超时
ini_get('memory_limit');          // 内存限制
```

### 5. 框架安全审计

```php
// --- ThinkPHP审计 ---
// 路由注入
// Route::any('test/:id', 'index/test');

// SQL注入（使用字符串条件）
Db::table('user')->where('id = ' . $id)->select();  // 危险

// 模板注入
// view()->assign('user', $user);
// 模板中使用 {php}: {php}echo system($_GET['cmd']);{/php}

// --- Laravel审计 ---
// SQL注入（RAW查询）
DB::select("SELECT * FROM users WHERE id = $id");  // 危险
// 应使用: DB::select("SELECT * FROM users WHERE id = ?", [$id]);

// 批量赋值漏洞
User::create(Input::all());  // 危险，可能覆盖角色字段

// Blade模板XSS
// {{ $var }} 自动转义是安全的
// {!! $var !!} 不转义，危险

// MassAssignment
// 检查 $fillable 和 $guarded 属性

// --- Yii审计 ---
// SQL注入
$result = Yii::$app->db->createCommand("SELECT * FROM user WHERE id=$id")->queryAll();
// 应使用绑定参数

// 反序列化
unserialize(Yii::$app->request->post('data'));
```

### 6. 自动化审计工具

```bash
# RIPS - PHP代码审计
# 商业工具
# 上传代码到 RIPS 界面进行分析

# phpcs - PHP CodeSniffer
phpcs --standard=Security /path/to/code/

# Psalm - PHP静态分析
psalm --taint-analysis

# Phan - PHP静态分析器
phan --output-mode text

# phpstan - PHP静态分析
phpstan analyse /path/to/src --level=max

# 使用grep搜索漏洞模式
# SQL注入
grep -rn "\$_GET\|\$_POST\|\$_REQUEST\|\$_COOKIE" --include="*.php" | grep -i "query\|prepare\|execute\|select\|insert\|update\|delete"

# 文件包含
grep -rn "include\|require\|include_once\|require_once" --include="*.php" | grep -E "\$_GET\|\$_POST\|\$_REQUEST"

# 命令执行
grep -rn "eval\|system\|exec\|shell_exec\|passthru\|popen\|proc_open" --include="*.php"

# 反序列化
grep -rn "unserialize" --include="*.php"
```

### 7. 修复实战

```php
<?php
// 案例1: SQL注入修复
// 原始代码
// $sql = "SELECT * FROM users WHERE username='" . $_GET['user'] . "'";
// $result = mysqli_query($conn, $sql);

// 修复后（参数化查询）
$stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
$stmt->bind_param("s", $_GET['user']);
$stmt->execute();
$result = $stmt->get_result();

// 案例2: XSS修复
// 原始代码
// echo "用户: " . $_GET['name'];

// 修复后
echo "用户: " . htmlspecialchars($_GET['name'], ENT_QUOTES | ENT_HTML5, 'UTF-8');

// 案例3: 文件上传修复
// 原始代码
// move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $_FILES['file']['name']);

// 修复后
$allowed = ['image/jpeg', 'image/png', 'image/gif'];
$mime = mime_content_type($_FILES['file']['tmp_name']);
if (in_array($mime, $allowed)) {
    $ext = pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION);
    $new_name = bin2hex(random_bytes(16)) . '.' . $ext;
    move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $new_name);
}

// 案例4: 命令注入修复
// 原始代码
// system("ping -c 3 " . $_POST['ip']);

// 修复后
$ip = filter_var($_POST['ip'], FILTER_VALIDATE_IP);
if ($ip) {
    $output = shell_exec("ping -c 3 " . escapeshellarg($ip));
    echo "<pre>" . htmlspecialchars($output) . "</pre>";
} else {
    echo "Invalid IP address";
}
?>
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| RIPS | PHP代码审计 | https://www.ripstech.com/ |
| Psalm | PHP静态分析 | https://psalm.dev/ |
| Phan | PHP静态分析器 | https://github.com/phan/phan |
| phpcs | PHP代码规范检查 | https://github.com/squizlabs/PHP_CodeSniffer |
| PHPStan | 静态分析 | https://phpstan.org/ |
| Progpilot | PHP安全审计 | https://github.com/designsecurity/progpilot |

## 参考资源
- [OWASP PHP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Security_Cheat_Sheet.html)
- [PHP Manual - Security](https://www.php.net/manual/en/security.php)
- [PHP Security Guide](https://phpsecurity.readthedocs.io/)
- [HackTricks - PHP](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp)
