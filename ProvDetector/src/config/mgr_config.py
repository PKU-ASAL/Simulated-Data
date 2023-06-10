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


class COMPARE_KEY:
    event_id = "event_id"
    ppguid = "parent_pguid"
    pppath = "parent_ppath"
    ppmd5 = "parent_pmd5"
    ppcommand = "parent_pcmd_line"
    puser = "process_user"
    ppuser = "parent_puser"
    pguid = "process_guid"
    pfilepath = "process_path"
    pmd5 = "process_md5"
    pcommand = "process_cmd_line"
    pid = "process_id"
    protocol = "protocol"
    srcip = "src_ip"
    dstip = "dst_ip"
    srcport = "src_port"
    dstport = "dst_port"
    dnsqname = "query_name"
    dnsanswers = "query_results"
    dnsstatus = "query_status"
    filename = "file_name"


class EVENT_TYPE:
    FILE_OP = ['FILE_TIME_MODIFICATION', "FILE_CREATION", "FILE_DELETION", "FILE_RENAMING"]
    PROCESS_OP = ['PROCESS_CREATION']
    NET_OP = ['NETWORK_CONNECTION']
    DNS_OP = ['DNS_QUERY']
    REG_OP = ['REG_VALUE_SET', 'REG_CREATION']
    SCHTASK_OP = ['SCHTASK_CREATION']


class EVENT_ARTRIBUTE:
    FILE_ARTRIBUTE = ['process_path', 'file_name', 'log_id', 'is_warn']
    PROCESS_ARTRIBUTE = ['parent_ppath', 'process_path', 'log_id', 'is_warn']
    NET_ARTRIBUTE = ['process_path', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'log_id', 'is_warn']
    DNS_ARTRIBUTE = ['process_path', 'query_name', 'query_results', 'query_status', 'log_id', 'is_warn']
    REG_ARTRIBUTE = ['process_path', 'target_object', 'log_id', 'is_warn']
    SCHTASK_ARTRIBUTE = ['process_path', 'task_name', 'task_path', 'task_user', 'task_frequency', 'log_id', 'is_warn']


class EVENT_KEY:
    FILE = "FILE"
    PROCESS = "PROCESS"
    NET = "NET"
    DNS = "DNS"
    REG = "REG"
    SCHTASK = "SCHTASK"
