# PESCA (Privilege Escalation & Security Capability Auditor)

**PESCA** is a lightweight Linux post-exploitation and security auditing tool designed to rapidly discover and analyze Linux File Capabilities (security.capability). Built using Python's ctypes to make direct syscalls to libc, it queries extended attributes natively without relying on external system utilities like getcap.

**Key Features:**

  - Zero Binary Dependencies: Invokes libc.getxattr directly to query security.capability attributes without shelling out to getcap.
  - High-Risk Prioritization: Flags critical capabilities (CAP_SETUID, CAP_SETGID, CAP_DAC_READ_SEARCH, CAP_DAC_OVERRIDE, CAP_SYS_PTRACE, CAP_SYS_ADMIN) that lead to privilege escalation.
  - Targeted Exploitation PoC Guidance: Automatically generates context-aware syntax and exploitation notes for identified vulnerable binaries.
  - Rich Terminal UI: Displays results in clean, formatted Markdown tables using Python's rich library.

**Requirements:**

  - Operating System: Linux / UNIX-like system with libc.so.6
  - Python Version: Python 3.8+
  - Dependencies: rich

**Install the required library:**

```bash 
pip install rich
```

**Usage:**
  - Run the auditor directly with Python:
    - `python3 pesca.py`


PESCA scans common system binary locations by default:
  - /usr/bin
  - /usr/sbin
  - /usr/local/bin
  - /bin
  - /sbin
  - /opt

**Output Example:**

```
                  
                                 ██████╗ ███████╗███████╗ ██████╗ █████╗ 
                                 ██╔══██╗██╔════╝██╔════╝██╔════╝██╔══██╗
                                 ██████╔╝█████╗  ███████╗██║     ███████║
                                 ██╔═══╝ ██╔══╝  ╚════██║██║     ██╔══██║
                                 ██║     ███████╗███████╗╚██████╗██║  ██║
                                 ╚═╝     ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝
                          Privilege Escalation & Security Capability Auditor v1.0

┌───────────┬──────────────────┬─────────────────┬─────────────────────────────────────────────────────────┐
│  Status   │ Binary Path      │ Capabilities    │ Exploitation PoC / Notes                                │
├───────────┼──────────────────┼─────────────────┼─────────────────────────────────────────────────────────┤
│ HIGH-RISK │ /usr/bin/python3 │ CAP_SETUID      │ /usr/bin/python3 -c 'import os; os.setuid(0);           │
│           │                  │                 │ os.system("/bin/sh")'                                   │
│ INFO      │ /usr/bin/ping    │ CAP_NET_RAW     │ No direct standard PoC                                  │
└───────────┴──────────────────┴─────────────────┴─────────────────────────────────────────────────────────┘
```
