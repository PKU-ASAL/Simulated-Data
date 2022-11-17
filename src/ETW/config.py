EVENTS = [
        "PROCESS_CREATION",
        "FILE_TIME_MODIFICATION",
        "DNS_QUERY",
        "FILE_CREATION",
        "NETWORK_CONNECTION",
        "REG_VALUE_SET",
        "FILE_RENAMING",
        "REG_CREATION",
        "FILE_DELETION",
        "HOST_PORT_LISTENING",
        "SCHTASK_CREATION"
    ]

class EVENT_TYPE:
        FILE_OP = [ "FileIO/Read", "FileIO/Write"]
        IMAGE_OP = ["Image/Load"]
        PROCESS_OP = ['Process/Start']
        NETRec_OP = ['TcpIp/Recv']
        NETSend_OP = ['TcpIp/Send']


class EVENT_ARTRIBUTE:
        FILE_ARTRIBUTE = ['MSec','PID','PName','TID', 'EventName','FileName','Offset', 'IrpPtr', 'FileObject', 'FileKey' ,'IoSize','IoFlags']
        IMAGE_ARTRIBUTE = ['MSec', 'PID', 'PName','TID','EventName', 'ImageBase', 'ImageSize','ImageChecksum', 'TimeDateStamp', 'DefaultBase','FileName']
        PROCESS_START_ARTRIBUTE = ['MSec', 'PID', 'PName', 'TID', 'EventName', 'ProcessID', 'ParentID', 'ImageFileName','DirectoryTableBase','Flags','SessionID','ExitStatus','UniqueProcessKey','CommandLine','is_warn']
        WITHPARENT_PROCESS_START_ARTRIBUTE = ['MSec', 'PID', 'PName', 'TID', 'EventName', 'ProcessID', 'ParentID', 'PPName', 'ImageFileName','DirectoryTableBase','Flags','SessionID','ExitStatus','UniqueProcessKey','CommandLine', 'is_warn']
        PROCESS_STOP_ARTRIBUTE = ['MSec', 'PID', 'PName', 'TID', 'EventName', 'ProcessID', 'ParentID', 'ImageFileName','DirectoryTableBase','Flags','SessionID','ExitStatus','UniqueProcessKey','CommandLine']
        NETSend_ARTRIBUTE = ['MSec','PID','PName','TID','EventName','size','daddr','saddr','dport', 'sport','startime','endtime','seqnum','connid']
        NETRecv_ARTRIBUTE = ['MSec','PID','PName','TID','EventName','daddr','saddr','dport', 'sport','size','connid','seqnum']

class EVENT_KEY:
        FILE = "FILE"
        PROCESS = "PROCESS"
        NET = "NET"
class NODE_TYPE:
    PROCESS = 0
    FILE = 1
    NET = 2