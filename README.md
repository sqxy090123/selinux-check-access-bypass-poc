# SELinux libselinux `selinux_check_access()` Permission Bypass PoC

---

### OTHER LANGUAGES
- [中文版README](./README_CN.MD)

---

This repository demonstrates a logic flaw in `libselinux` (the SELinux userspace library) where `selinux_check_access()` incorrectly returns success (0) when called with an **unknown object class** that does not exist in the loaded policy, provided that the system's `deny_unknown` setting is 0 (the default on many Linux distributions).

## Vulnerability Overview

- **Component**: `libselinux/src/checkAccess.c`
- **Function**: `selinux_check_access()`
- **Flaw**: When `string_to_security_class()` returns 0 (unknown class), the function checks `security_deny_unknown()`. If that returns 0, it **immediately returns 0 (access granted)** without consulting the actual SELinux policy via `avc_has_perm()`.
- **Impact**: An unprivileged attacker can craft a malicious class string and inject it into a privileged process that uses this API, causing the process to believe the operation is permitted, leading to unauthorized actions such as reading sensitive files, executing system commands, or privilege escalation.
- Note: This vulnerability does not directly bypass SELinux to gain root privileges, but it can trick a privileged process into executing arbitrary commands, potentially leading to arbitrary code execution or privilege escalation.
- **CVSS v3.1**: 7.8 (High) – AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

## Affected Versions

All versions of `libselinux` up to and including v3.0, and possibly later if not patched, on systems where `/sys/fs/selinux/deny_unknown` contains `0` (the default on CentOS 7/8, Ubuntu 18.04/20.04, Debian 10/11, etc.).

## Proof of Concept

The provided `poc.c` demonstrates the vulnerability by:

1. Obtaining the current SELinux context.
2. Calling `selinux_check_access()` with an invalid class name (`invalid_class_xyz`).
3. If the call returns 0 (success), it executes an arbitrary system command (default: `whoami`).

### Compilation & Usage

```bash
gcc -o poc poc.c -lselinux
./poc [command]
```

## Examples

```bash
./poc "id"
./poc "cat /etc/shadow"
./poc "sudo whoami"
```

## Expected Output (Vulnerable System)

```
[*] Current context: docker-default (enforce)
[*] deny_unknown = 0
[*] Calling selinux_check_access() with invalid class 'invalid_class_xyz'...
[!] VULNERABLE: selinux_check_access returned 0 (success).
[!] Exploiting to execute command: whoami
labex
[+] Command executed successfully (exit code: 0)
```

If the system is patched or deny_unknown=1, the PoC will report "NOT vulnerable".

## Mitigation

- Code fix (recommended): Modify selinux_check_access() to always return an error (-1, errno=EINVAL) when an unknown class or permission is encountered, regardless of the deny_unknown setting.
- Workaround: Set deny_unknown=1 (requires root), but this may break applications that rely on the old behaviour.
- Application-level: Validate class and permission strings against the loaded policy before calling selinux_check_access().

Discovery Date

- 2026-07-14

## Legal Disclaimer

This PoC is for educational and security research purposes only. Use it only on systems you own or have explicit permission to test. The author is not responsible for any misuse or damage caused by this code.

## License

MIT
