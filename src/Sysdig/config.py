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
    PROCESS_OP = ["clone", "pipe", "fork",'execve']
    NET_OP = ["sendmsg", "recvmsg", "recvfrom", "send", "sendto"]


class APTLOG_ARTRIBUTE:
    FILE_ARTRIBUTE = ['proc.cmdline', 'fd.name', 'is_warn']
    PROCESS_ARTRIBUTE = ['proc.pcmdline', 'proc.cmdline', 'is_warn']
    NET_ARTRIBUTE = ['proc.cmdline', 'fd.name', 'is_warn']
    # EXECVE_ARTRIBUTE = ['proc.cmdline', 'evt.args', 'is_warn']

class BENLOG_ARTRIBUTE:
    FILE_ARTRIBUTE = ['proc.cmdline', 'fd.name']
    PROCESS_ARTRIBUTE = ['proc.pcmdline', 'proc.cmdline']
    NET_ARTRIBUTE = ['proc.cmdline', 'fd.name']
    # EXECVE_ARTRIBUTE = ['proc.cmdline', 'evt.args', 'is_warn']


class APTLOG_KEY:
    FILE = "FILE"
    PROCESS = "PROCESS"
    NET = "NET"
    # EXECVE = "EXECVE"

class APTLOG_NODE_TYPE:
    PROCESS = 0
    FILE = 1
    NET = 2

