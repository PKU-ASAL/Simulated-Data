import pandas as pd
import networkx as nx
from config import *
from hashlib import md5
import csv
from nostril import nonsense
import string 
import re
import json
def graph_init():
    # -------
    # Function definition: 'graph_init()':
    # (1) Initialize a directed graph as G
    # -------
    # Required parameters: None
    # -------
    # Return: an empty directed graph G
    # -------
    G = nx.DiGraph()
    return G

def get_md5(s):
    """
    get md5 hash value of String s
    :param s:
    :return:
    """
    return str(md5(s.encode('utf8')).hexdigest())
def read_org_log_from_json(file_path):
    # Sysmon_Log = pd.read_json(file_path, orient='columns', lines = True)
    Sysmon_Log = []
    for line in open(file_path):
        x = json.loads(line)
        Sysmon_Log.append(x)

    print('Completed: load', file_path)
    Sysmon_Log = pd.DataFrame(Sysmon_Log)
    # Sysmon_Log = Sysmon_Log[Sysmon_Log['EventName'].isin(EVENTS)]
    # print('Selected events in :', EVENTS)
    # Sysmon_Log = Sysmon_Log.applymap(lambda s: s.lower() if type(s) == str else s)
    Sysmon_Log = Sysmon_Log.drop_duplicates()
    print('Completed: drop duplicated records from sysmon log')
    Sysmon_Log = Sysmon_Log.fillna("None")
    print('Completed: padding missing records as None')
    return Sysmon_Log

def graph_add_node_realapt(g: nx.Graph, logs, key, md5_to_node:dict, node_to_type:dict):
    node_set = set()
    edge_set = set()
    anomaly_set = set()
    if key == APTLOG_KEY.FILE:
        # add file type node
        for index, row in logs.iterrows():
            s_node = get_md5(row['proc.cmdline'])
            t_node = get_md5(row['fd.name'])
            if s_node not in md5_to_node:
                md5_to_node[s_node] = row['proc.cmdline']
                node_to_type[s_node] = {'type':APTLOG_NODE_TYPE.PROCESS, 'is_warn':row['is_warn']}
            if t_node not in md5_to_node:
                md5_to_node[t_node] = row['fd.name']
                node_to_type[t_node] = {'type':APTLOG_NODE_TYPE.FILE, 'is_warn':False}
            # e_id = row['log_id']
            is_warn = row['is_warn']
            if is_warn:
                anomaly_set.add(s_node)
            node_set.add(s_node)
            node_set.add(t_node)
            edge_set.add((s_node, t_node, is_warn))
    elif key == APTLOG_KEY.PROCESS:
        # add process type node
        for index, row in logs.iterrows():
            s_node = get_md5(row['proc.pcmdline'])
            t_node = get_md5(row['proc.cmdline'])
            if s_node not in md5_to_node:
                md5_to_node[s_node] = row['proc.pcmdline']
                node_to_type[s_node] = {'type':APTLOG_NODE_TYPE.PROCESS, 'is_warn':row['is_warn']}
            if t_node not in md5_to_node:
                md5_to_node[t_node] = row['proc.cmdline']
                node_to_type[t_node] = {'type':APTLOG_NODE_TYPE.PROCESS, 'is_warn':row['is_warn']}
            # e_id = row['log_id']
            is_warn = row['is_warn']
            if is_warn:
                anomaly_set.add(s_node)
                anomaly_set.add(t_node)
            node_set.add(s_node)
            node_set.add(t_node)
            edge_set.add((s_node, t_node, is_warn))
    elif key == APTLOG_KEY.NET:
        # add net type node
        for index, row in logs.iterrows():
            s_node = get_md5(row['proc.cmdline'])
            t_node = get_md5(row['fd.name'])
            if s_node not in md5_to_node:
                md5_to_node[s_node] = row['proc.cmdline']
                node_to_type[s_node] = {'type':APTLOG_NODE_TYPE.PROCESS, 'is_warn':row['is_warn']}
            if t_node not in md5_to_node:
                md5_to_node[t_node] = row['fd.name']
                node_to_type[t_node] = {'type':APTLOG_NODE_TYPE.NET, 'is_warn':False}
            # e_id = row['log_id']
            is_warn = row['is_warn']
            if is_warn:
                anomaly_set.add(s_node)
            node_set.add(s_node)
            node_set.add(t_node)
            edge_set.add((s_node, t_node, is_warn))
    # elif key == APTLOG_KEY.EXECVE:
    #     # add execve type node
    #     for index, row in logs.iterrows():
    #         s_node = get_md5(row['proc.cmdline'])
    #         # t_node = get_md5((row['evt.args']).strip('filename='))
    #         t_node = get_md5(row['proc.pcmdline'])
    #         if s_node not in md5_to_node:
    #             md5_to_node[s_node] = row['proc.cmdline']
    #             node_to_type[s_node] = {'type':APTLOG_NODE_TYPE.PROCESS, 'is_warn':row['is_warn']}
    #         if t_node not in md5_to_node:
    #             # if 'filename=' not in row['evt.args']:
    #             #     md5_to_node[t_node] = 'unknown'
    #             # else:
    #             #     md5_to_node[t_node] = (row['evt.args']).strip('filename=')
    #             md5_to_node[t_node] = row['proc.pcmdline']
    #             node_to_type[t_node] = {'type':APTLOG_NODE_TYPE.PROCESS, 'is_warn':False}
    #         # e_id = row['log_id']
    #         is_warn = row['is_warn']
    #         node_set.add(s_node)
    #         node_set.add(t_node)
    #         edge_set.add((s_node, t_node, is_warn))

    # add node
    node_list = list(node_set)
    node_list.sort()
    for node in node_list:
        g.add_node(node)
        g.nodes[node]['label'] = md5_to_node[node]
        g.nodes[node]['type'] = node_to_type[node]['type']
        g.nodes[node]['is_warn'] = node_to_type[node]['is_warn']

    # add edge
    edge_list = list(edge_set)
    edge_list.sort()
    for edge in edge_list:
        g.add_edge(edge[0], edge[1], is_warn=edge[2])

    return g,anomaly_set


def graph_add_node_benign(g: nx.Graph, logs, key, md5_to_node:dict, node_to_type:dict):
    node_set = set()
    edge_set = set()
    anomaly_set = set()
    if key == APTLOG_KEY.FILE:
        # add file type node
        for index, row in logs.iterrows():
            s_node = get_md5(row['proc.cmdline'])
            t_node = get_md5(row['fd.name'])
            if s_node not in md5_to_node:
                md5_to_node[s_node] = row['proc.cmdline']
                node_to_type[s_node] = {'type':APTLOG_NODE_TYPE.PROCESS, 'is_warn':False}
            if t_node not in md5_to_node:
                md5_to_node[t_node] = row['fd.name']
                node_to_type[t_node] = {'type':APTLOG_NODE_TYPE.FILE, 'is_warn':False}
            # e_id = row['log_id']
            is_warn = False
            if is_warn:
                anomaly_set.add(s_node)
            node_set.add(s_node)
            node_set.add(t_node)
            edge_set.add((s_node, t_node, is_warn))
    elif key == APTLOG_KEY.PROCESS:
        # add process type node
        for index, row in logs.iterrows():
            s_node = get_md5(row['proc.pcmdline'])
            t_node = get_md5(row['proc.cmdline'])
            if s_node not in md5_to_node:
                md5_to_node[s_node] = row['proc.pcmdline']
                node_to_type[s_node] = {'type':APTLOG_NODE_TYPE.PROCESS, 'is_warn':False}
            if t_node not in md5_to_node:
                md5_to_node[t_node] = row['proc.cmdline']
                node_to_type[t_node] = {'type':APTLOG_NODE_TYPE.PROCESS, 'is_warn':False}
            # e_id = row['log_id']
            is_warn = False
            if is_warn:
                anomaly_set.add(s_node)
                anomaly_set.add(t_node)
            node_set.add(s_node)
            node_set.add(t_node)
            edge_set.add((s_node, t_node, is_warn))
    elif key == APTLOG_KEY.NET:
        # add net type node
        for index, row in logs.iterrows():
            s_node = get_md5(row['proc.cmdline'])
            t_node = get_md5(row['fd.name'])
            if s_node not in md5_to_node:
                md5_to_node[s_node] = row['proc.cmdline']
                node_to_type[s_node] = {'type':APTLOG_NODE_TYPE.PROCESS, 'is_warn':False}
            if t_node not in md5_to_node:
                md5_to_node[t_node] = row['fd.name']
                node_to_type[t_node] = {'type':APTLOG_NODE_TYPE.NET, 'is_warn':False}
            # e_id = row['log_id']
            is_warn = False
            if is_warn:
                anomaly_set.add(s_node)
            node_set.add(s_node)
            node_set.add(t_node)
            edge_set.add((s_node, t_node, is_warn))

    # add node
    node_list = list(node_set)
    node_list.sort()
    for node in node_list:
        g.add_node(node)
        g.nodes[node]['label'] = md5_to_node[node]
        g.nodes[node]['type'] = node_to_type[node]['type']
        g.nodes[node]['is_warn'] = node_to_type[node]['is_warn']

    # add edge
    edge_list = list(edge_set)
    edge_list.sort()
    for edge in edge_list:
        g.add_edge(edge[0], edge[1], is_warn=edge[2])

    return g,anomaly_set
def directed_acyclic_graph(graph=''):
    # -------
    # Function definition: 'directed_acyclic_graph()'
    # (1) check graph G is DAG or not
    # (2) remove cycles from G -> convert to DAG
    # -------
    # Required parameters:
    # (1) 'graph': a directed graph G
    # -------
    # Return: DAG
    # -------
    if nx.is_directed_acyclic_graph(graph) == True:
        print('Completed: DAG is True')
    else:
        print('Found: cycles in graph')
        while nx.is_directed_acyclic_graph(graph) == False:
            edge_list = list(nx.find_cycle(graph, orientation='original'))
            graph.remove_edges_from(edge_list)
        print('Completed: DAG is True')
    weight = nx.pagerank(graph, alpha=1)

    return graph

def get_filepath(file_logs, process_logs, net_logs):
    node_set = {}
    for index, row in file_logs.iterrows():
        s_node = get_md5(row['process_path'])
        t_node = get_md5(row['file_name'])
        node_set[s_node] = row['process_path']
        node_set[t_node] = row['file_name']
        p_node = get_md5(row['process_cmd_line'])
        node_set[p_node] = row['process_cmd_line']

    for index, row in process_logs.iterrows():
        s_node = get_md5(row['parent_ppath'])
        t_node = get_md5(row['process_path'])
        node_set[s_node] = row['parent_ppath']
        node_set[t_node] = row['process_path']
        p_node = get_md5(row['process_cmd_line'])
        node_set[p_node] = row['process_cmd_line']
        pp_node = get_md5(row['parent_pcmd_line'])
        node_set[pp_node] = row['parent_pcmd_line']

    for index, row in net_logs.iterrows():
        s_node = get_md5(row['process_path'])
        src_ip = row['src_ip']
        dst_ip = row['dst_ip']
        # src_port = row['src_port']
        dst_port = row['dst_port']
        protocol = row['protocol']
        x = '{},{},{},{}'.format(src_ip,dst_ip,int(dst_port),protocol.lower())
        t_node = get_md5(x)
        node_set[s_node] = row['process_path']

        node_set[t_node] = x
        p_node = get_md5(row['process_cmd_line'])
        node_set[p_node] = row['process_cmd_line']
    
    return node_set.values()

# _delete_nonalpha = str.maketrans('', '', _nonalpha)
def sanitize_string(s):
    # Translate non-ASCII character codes.
    s = s.strip().encode('ascii', errors='ignore').decode()
    if re.search(r'([0-9\.]*):([0-9]*)->([0-9\.]*):([0-9]*)',s):
        # s = s.replace('/32','')
        split_path = re.split('/|\.|,|:|-|>',s)
        split_path = [item for item in filter(lambda x:x != '',split_path)]
        split_path.pop(4)
        split_path.pop(8)
        return split_path
    # Lower-case the string & strip non-alpha.
    for i in s:
        if i in string.punctuation:
            s = s.replace(i," ")

    split_path = s.lower().split()
    # split_path = [item for item in filter(lambda x:x != '',split_path)]
    newline = []
    for item in split_path:
        if len(item) < 2 or item.isdigit():
            continue
        if len(item) <= 5 and len(item) >= 2:
            newline.append(item)
        else:
            try:
                if not nonsense(item):
                    newline.append(item)
                else:
                    newline.append('hash')
            except Exception as e:
                print(s)
    split_path = [item for item in filter(lambda x:x != '',newline)]
    return split_path