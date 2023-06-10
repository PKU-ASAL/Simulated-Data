ANFU_EVENTS = [
        "PROCESS_CREATION",
        "DNS_QUERY",
        "PROCESS_EXIT",
        "NETWORK_CONNECTION",
        "FILE_DELETION",
        "FILE_RENAMING",
        "FILE_CREATION",
        "REG_VALUE_SET",
        "REG_CREATION",
        "FILE_TIME_MODIFICATION",
        "SCHTASK_CREATION"
    ]

class ANFU_TYPE:
        FILE_OP = ["FILE_CREATION", "FILE_RENAMING", "FILE_TIME_MODIFICATION",]
        PROCESS_OP = ['PROCESS_CREATION', 'HOST_PROCESS_CREATION']
        NET_OP = ['NETWORK_CONNECTION']
        DNS_OP = ['DNS_QUERY']
        REG_OP = ['REG_VALUE_SET', 'REG_CREATION']
        SCHTASK_OP = ['SCHTASK_CREATION']

class ANFU_ARTRIBUTE:
        FILE_ARTRIBUTE = ['pfilepath', 'filename', 'pcommand','pid']
        PROCESS_ARTRIBUTE = ['ppfilepath', 'pfilepath', 'pcommand', 'ppcommand', 'ppid', 'pid']
        NET_ARTRIBUTE = ['pfilepath', 'srcip', 'srcport', 'dstip', 'dstport', 'pcommand', 'pid']
        DNS_ARTRIBUTE = ['process_path', 'query_name', 'query_results', 'query_status', 'log_id']
        REG_ARTRIBUTE = ['process_path', 'target_object', 'log_id']
        SCHTASK_ARTRIBUTE = ['process_path', 'task_name', 'task_path', 'task_user', 'task_frequency', 'log_id']

class ANFU_KEY:
        FILE = "FILE"
        PROCESS = "PROCESS"
        NET = "NET"
        DNS = "DNS"
        REG = "REG"
        SCHTASK = "SCHTASK"

class NODE_TYPE:
    PROCESS = 0
    FILE = 1
    NET = 2