from core.Graph_Function_Library import *
from core.Data_Preprocessing import *
import json
from config.mgr_config import EVENT_TYPE, EVENT_ARTRIBUTE, EVENT_KEY
from config.realAPT_config import APTLOG_TYPE, APTLOG_ARTRIBUTE, APTLOG_KEY

def provenance_graph_train(filepath='', number_of_rareness_paths=''):
    # -------
    # Function definition: 'provenance_graph_train ()'
    # (1) a provenance graph of sysmon log with selected top-k rareness paths
    # -------
    # Required parameters:
    # (1) 'filepath': absolute path of the filepath that includes the sysmon log
    # (2) 'number_of_rareness_paths': the number of selected top k rareness paths
    # -------
    # Return: a list of rareness paths found in the provenance graph
    # -------
    # read sysmon log with selected attributes['...']
    sysmon_log = read_sysmon_log(filepath=filepath,
                                 attributes=['ParentProcessId', 'ParentProcessGuid', 'ParentImage',
                                             'ProcessId', 'ProcessGuid', 'Image'])

    # select unique records from sysmon log
    ParentProcessId = select_unique_records(sysmon_log=sysmon_log, attribute='ParentProcessId')
    ParentProcessGuid = select_unique_records(sysmon_log=sysmon_log, attribute='ParentProcessGuid')
    ParentImage = select_unique_records(sysmon_log=sysmon_log, attribute='ParentImage')
    ProcessId = select_unique_records(sysmon_log=sysmon_log, attribute='ProcessId')
    ProcessGuid = select_unique_records(sysmon_log=sysmon_log, attribute='ProcessGuid')
    Image = select_unique_records(sysmon_log=sysmon_log, attribute='Image')

    # Initial the provenance graph G
    G = graph_init()

    # add nodes to graph G from unique records to avoid creating duplicated nodes
    G = graph_add_node(graph=G, node_name=ParentProcessId)
    G = graph_add_node(graph=G, node_name=ParentProcessGuid)
    G = graph_add_node(graph=G, node_name=ParentImage)
    G = graph_add_node(graph=G, node_name=ProcessId)
    G = graph_add_node(graph=G, node_name=ProcessGuid)
    G = graph_add_node(graph=G, node_name=Image)

    # add paths to a graph G by traversing rows in the sysmon_log with selected attributes
    G = graph_add_path(graph=G, sysmon_log=sysmon_log)

    # convert to the directed acyclic graph (DAG: without cycles and self loops)
    DAG = directed_acyclic_graph(graph=G)

    # select top-k rareness paths from the DAG
    rareness_paths = top_k_rareness_paths(graph=DAG, k=number_of_rareness_paths)
    return rareness_paths


def provenance_graph_APT29(filepath='', number_of_rareness_paths=''):
    # -------
    # Function definition: 'provenance_graph_APT29 ()'
    # (1) a provenance graph of sysmon log with selected top-k rareness paths
    # -------
    # Required parameters:
    # (1) 'filepath': absolute path of the filepath that includes the sysmon log
    # (2) 'number_of_rareness_paths': the number of selected top k rareness paths
    # -------
    # Return: a list of rareness paths found in the provenance graph
    # -------
    # read sysmon log with selected attributes['...']
    sysmon_log = read_sysmon_log_APT29(filepath=filepath,
                                       attributes=['SourceAddress', 'SourcePort', 'ParentProcessId',
                                                   'ParentProcessGuid', 'ParentImage',
                                                   'ProcessId', 'ProcessGuid', 'Image', 'DestAddress', 'DestPort',
                                                   'CommandLine'])

    # select unique records from sysmon log
    CommandLine = select_unique_records(sysmon_log=sysmon_log, attribute='CommandLine')
    SourceAddress = select_unique_records(sysmon_log=sysmon_log, attribute='SourceAddress')
    SourcePort = select_unique_records(sysmon_log=sysmon_log, attribute='SourcePort')
    DestPort = select_unique_records(sysmon_log=sysmon_log, attribute='DestPort')
    DestAddress = select_unique_records(sysmon_log=sysmon_log, attribute='DestAddress')
    ParentProcessId = select_unique_records(sysmon_log=sysmon_log, attribute='ParentProcessId')
    ParentProcessGuid = select_unique_records(sysmon_log=sysmon_log, attribute='ParentProcessGuid')
    ParentImage = select_unique_records(sysmon_log=sysmon_log, attribute='ParentImage')
    ProcessId = select_unique_records(sysmon_log=sysmon_log, attribute='ProcessId')
    ProcessGuid = select_unique_records(sysmon_log=sysmon_log, attribute='ProcessGuid')
    Image = select_unique_records(sysmon_log=sysmon_log, attribute='Image')

    # Initial the provenance graph G
    G = graph_init()

    # add nodes to graph G from unique records to avoid creating duplicated nodes
    G = graph_add_node(graph=G, node_name=CommandLine)
    G = graph_add_node(graph=G, node_name=SourceAddress)
    G = graph_add_node(graph=G, node_name=SourcePort)
    G = graph_add_node(graph=G, node_name=DestPort)
    G = graph_add_node(graph=G, node_name=DestAddress)
    G = graph_add_node(graph=G, node_name=ParentProcessId)
    G = graph_add_node(graph=G, node_name=ParentProcessGuid)
    G = graph_add_node(graph=G, node_name=ParentImage)
    G = graph_add_node(graph=G, node_name=ProcessId)
    G = graph_add_node(graph=G, node_name=ProcessGuid)
    G = graph_add_node(graph=G, node_name=Image)

    # add paths to a graph G by traversing rows in the sysmon_log with selected attributes
    G = graph_add_path(graph=G, sysmon_log=sysmon_log)

    # convert to the directed acyclic graph (DAG: without cycles and self loops)
    DAG = directed_acyclic_graph(graph=G)

    # select top-k rareness paths from the DAG
    rareness_paths = top_k_rareness_paths(graph=DAG, k=number_of_rareness_paths)
    graph_visualization(DAG, rareness_paths)
    return rareness_paths


def read_sysmon_log_APT29(filepath='', attributes=[]):
    # -------
    # Function definition: 'read_sysmon_log_APT29':
    # (1) read 'sysmon_log'.json
    # (2) select required attributes of sysmon_log.json
    # (3) remove duplicated records
    # (4) padding missing records as 0
    # -------
    # Required parameters:
    # (1) 'filepath' (string): file path of a targeted sysmon_log.json
    # (2) 'attributes' (list): a list of selected attributes from sysmon_log,json, such as 'ProcessId','ProcessGuid'
    # -------
    # Return: a DataFrame of sysmon_log.json
    # --------

    Sysmon_Log = pd.read_json(filepath, orient='columns', lines=True)
    print('Completed: load', filepath)
    Sysmon_Log = pd.DataFrame(Sysmon_Log, columns=attributes)
    print('Selected attributes:', list(Sysmon_Log))
    Sysmon_Log = Sysmon_Log.applymap(lambda s: s.lower() if type(s) == str else s)
    Sysmon_Log = Sysmon_Log.drop_duplicates()
    print('Completed: drop duplicated records from sysmon log')
    Sysmon_Log = Sysmon_Log.fillna("None")
    print('Completed: padding missing records as None')
    return Sysmon_Log

def provenance_graph_mgr(org_log, md5_to_node:dict):

    file_op_logs = org_log[org_log['event_id'].isin(EVENT_TYPE.FILE_OP)]
    print('file logs count:', len(file_op_logs))
    process_op_logs = org_log[org_log['event_id'].isin(EVENT_TYPE.PROCESS_OP)]
    print('process logs count:', len(process_op_logs))
    net_op_logs = org_log[org_log['event_id'].isin(EVENT_TYPE.NET_OP)]
    print('net logs count:', len(net_op_logs))
    dns_op_logs = org_log[org_log['event_id'].isin(EVENT_TYPE.DNS_OP)]
    print('dns logs count:', len(dns_op_logs))
    reg_op_logs = org_log[org_log['event_id'].isin(EVENT_TYPE.REG_OP)]
    print('reg logs count:', len(reg_op_logs))
    schtask_op_logs = org_log[org_log['event_id'].isin(EVENT_TYPE.SCHTASK_OP)]
    print('schtask logs count:', len(schtask_op_logs))
    if len(file_op_logs) > 0:
        file_op_logs = file_op_logs[EVENT_ARTRIBUTE.FILE_ARTRIBUTE]
    if len(process_op_logs) > 0:
        process_op_logs = process_op_logs[EVENT_ARTRIBUTE.PROCESS_ARTRIBUTE]
    if len(net_op_logs) > 0:
        net_op_logs = net_op_logs[EVENT_ARTRIBUTE.NET_ARTRIBUTE]
    if len(dns_op_logs) > 0:
        dns_op_logs = dns_op_logs[EVENT_ARTRIBUTE.DNS_ARTRIBUTE]
    if len(reg_op_logs) > 0:
        reg_op_logs = reg_op_logs[EVENT_ARTRIBUTE.REG_ARTRIBUTE]
    if len(schtask_op_logs) > 0:
        schtask_op_logs = schtask_op_logs[EVENT_ARTRIBUTE.SCHTASK_ARTRIBUTE]

    G = graph_init()

    G = graph_add_node_mgr(G, file_op_logs, EVENT_KEY.FILE, md5_to_node)
    G = graph_add_node_mgr(G, process_op_logs, EVENT_KEY.PROCESS, md5_to_node)
    G = graph_add_node_mgr(G, net_op_logs, EVENT_KEY.NET, md5_to_node)
    G = graph_add_node_mgr(G, dns_op_logs, EVENT_KEY.DNS, md5_to_node)
    G = graph_add_node_mgr(G, reg_op_logs, EVENT_KEY.REG, md5_to_node)
    G = graph_add_node_mgr(G, schtask_op_logs, EVENT_KEY.SCHTASK, md5_to_node)


    # convert to the directed acyclic graph (DAG: without cycles and self loops)
    DAG = directed_acyclic_graph(graph=G)
    # select top-k rareness paths from the DAG
    all_paths = rareness_paths(graph=DAG)
    # graph_visualization(DAG, rareness_paths)
    return DAG, all_paths

def provenance_graph_realapt(org_log, md5_to_node:dict):

    file_op_logs = org_log[org_log['evt.type'].isin(APTLOG_TYPE.FILE_OP)]
    print('file logs count:', len(file_op_logs))
    process_op_logs = org_log[org_log['evt.type'].isin(APTLOG_TYPE.PROCESS_OP)]
    print('process logs count:', len(process_op_logs))
    net_op_logs = org_log[org_log['evt.type'].isin(APTLOG_TYPE.NET_OP)]
    print('net logs count:', len(net_op_logs))
    execve_op_logs = org_log[org_log['evt.type'].isin(APTLOG_TYPE.EXECVE_OP)]
    print('net logs count:', len(net_op_logs))

    if len(file_op_logs) > 0:
        file_op_logs = file_op_logs[APTLOG_ARTRIBUTE.FILE_ARTRIBUTE]
    if len(process_op_logs) > 0:
        process_op_logs = process_op_logs[APTLOG_ARTRIBUTE.PROCESS_ARTRIBUTE]
    if len(net_op_logs) > 0:
        net_op_logs = net_op_logs[APTLOG_ARTRIBUTE.NET_ARTRIBUTE]
    if len(net_op_logs) > 0:
        execve_op_logs = execve_op_logs[APTLOG_ARTRIBUTE.EXECVE_ARTRIBUTE]

    G = graph_init()

    G = graph_add_node_realapt(G, file_op_logs, APTLOG_KEY.FILE, md5_to_node)
    G = graph_add_node_realapt(G, process_op_logs, APTLOG_KEY.PROCESS, md5_to_node)
    G = graph_add_node_realapt(G, net_op_logs, APTLOG_KEY.NET, md5_to_node)
    G = graph_add_node_realapt(G, execve_op_logs, APTLOG_KEY.EXECVE, md5_to_node)


    # convert to the directed acyclic graph (DAG: without cycles and self loops)
    # DAG = directed_acyclic_graph(graph=G)
    # select top-k rareness paths from the DAG
    # all_paths = rareness_paths(graph=DAG)

    # graph_visualization(DAG, rareness_paths)
    return DAG, all_paths