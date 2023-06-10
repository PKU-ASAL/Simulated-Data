APTLOG = [
    "read",
    "readv",
    "write",
    "writev",
    "fcntl",
    "rmdir",
    "rename",
    "chmod",
    "execve",
    "clone",
    "pipe",
    "fork",
    "accept",
    "sendmsg",
    "recvmsg",
    "recvfrom",
    "send",
    "sendto",
]

class APTLOG_TYPE:
    FILE_OP = ["read", "readv", "write", "writev", "fcntl", "rmdir", "rename", "chmod"]
    PROCESS_OP = ["clone", "pipe", "fork"]
    NET_OP = ["sendmsg", "recvmsg", "recvfrom", "send", "sendto"]
    EXECVE_OP = ['execve']


class APTLOG_ARTRIBUTE:
    FILE_ARTRIBUTE = ['proc.cmdline', 'fd.name', 'log_id', 'is_warn']
    PROCESS_ARTRIBUTE = ['proc.pcmdline', 'proc.cmdline', 'log_id', 'is_warn']
    NET_ARTRIBUTE = ['proc.cmdline', 'fd.name', 'log_id', 'is_warn']
    EXECVE_ARTRIBUTE = ['proc.cmdline', 'evt.args', 'log_id', 'is_warn']


class APTLOG_KEY:
    FILE = "FILE"
    PROCESS = "PROCESS"
    NET = "NET"
    EXECVE = "EXECVE"
