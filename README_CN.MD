# SELinux libselinux `selinux_check_access()` 权限检查绕过 PoC

本仓库演示了 `libselinux`（SELinux 用户空间库）中存在的一个逻辑缺陷：当使用**策略中不存在的客体类别（unknown class）** 调用 `selinux_check_access()` 时，如果系统的 `deny_unknown` 设置为 0（多数 Linux 发行版的默认值），该函数会错误地返回成功（0），从而绕过实际的 SELinux 权限检查。

## 漏洞概述

- **影响组件**：`libselinux/src/checkAccess.c`
- **危险函数**：`selinux_check_access()`
- **缺陷根因**：当 `string_to_security_class()` 返回 0（未知类别）时，函数检查 `security_deny_unknown()`。若返回值为 0，则**直接返回 0（权限授予）**，而不向 `avc_has_perm()` 咨询实际的 SELinux 策略。
- **安全影响**：非特权攻击者可构造恶意类别字符串，注入到使用该 API 的高特权进程中，使进程误认为操作已被允许，从而执行未授权操作，例如读取敏感文件（如 `/etc/shadow`）、执行系统命令或提权。
- **CVSS v3.1 评分**：7.8（高危）– AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

## 受影响版本

`libselinux` v3.0 及更早版本（以及未修复的后续版本），且系统 `/sys/fs/selinux/deny_unknown` 内容为 `0`（CentOS 7/8、Ubuntu 18.04/20.04、Debian 10/11 等主流发行版的默认配置）。

## 概念验证（PoC）

提供的 `poc.c` 通过以下步骤演示漏洞：

1. 获取当前进程的 SELinux 上下文。
2. 使用无效类别名（`invalid_class_xyz`）调用 `selinux_check_access()`。
3. 若调用返回 0（成功），则执行任意系统命令（默认命令为 `whoami`）。

### 编译与使用方法

```bash
gcc -o poc poc.c -lselinux
./poc [命令]
```

## 示例：

```bash
./poc "id"
./poc "cat /etc/shadow"
./poc "sudo whoami"
```

## 预期输出（漏洞系统）

```
[*] Current context: docker-default (enforce)
[*] deny_unknown = 0
[*] Calling selinux_check_access() with invalid class 'invalid_class_xyz'...
[!] VULNERABLE: selinux_check_access returned 0 (success).
[!] Exploiting to execute command: whoami
labex
[+] Command executed successfully (exit code: 0)
```

## 若系统已修复或 deny_unknown=1，PoC 会报告 “NOT vulnerable”。

## 修复建议

- 代码修复（推荐）：修改 selinux_check_access()，无论 deny_unknown 为何值，遇到未知类别或权限时始终返回错误（-1，errno=EINVAL）。
- 临时缓解：以 root 身份设置 deny_unknown=1（echo 1 > /sys/fs/selinux/deny_unknown），但需评估对依赖旧行为的应用的影响。
- 应用层防护：在调用 selinux_check_access() 前，对类别和权限字符串进行白名单校验，确保其存在于已加载的策略中。

## 披露时间线

- 发现日期：2026-07-14
- 供应商报告状态：待提交（或尚未收到回复）
- CVE 编号：[CVE-2026-XXXXX]（待分配）

## 法律免责声明

本 PoC 仅用于教育和安全研究目的。请仅在您拥有或明确获授权测试的系统上使用。作者不对因使用本代码造成的任何滥用或损害承担责任。

## 许可证

MIT
