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

def graph_add_node_mgr(g, logs, key):
    node_set = set()
    node_attr = {}
    edge_set = set()
    attack_process = {}
    if key == EVENT_KEY.FILE:
        # add file type node
        for index, row in logs.iterrows():
            Process = str(row['PID']) + str(row['PName'])
            s_node = get_md5(Process)

            node_attr[s_node] = {'label': row['PName'].replace('\\','/'), 'cmd': '', 'type': NODE_TYPE.PROCESS, 'is_warn': False}
            t_node = get_md5(row['FileName'])
            node_attr[t_node] = {'label': row['FileName'].replace('\\','/'), 'type': NODE_TYPE.FILE}
            # e_id = row['log_id']
            node_set.add(s_node)
            node_set.add(t_node)
            edge_set.add((s_node, t_node))
    elif key == EVENT_KEY.PROCESS:
        # add process type node
        for index, row in logs.iterrows():
            Parentid = row['ParentID'].replace(',','') + str(row['PPName'])
            # print(Parentid)
            s_node = get_md5(Parentid)
            if not (s_node in node_attr):
                node_attr[s_node] = {'label': '', 'cmd': '' , 'type': NODE_TYPE.PROCESS}
            t_node = get_md5(str(row['PID'])+ str(row['PName']))
            if row['is_warn']=='True':
                attack_process[t_node] = row['CommandLine'] + ':' + t_node
            node_attr[t_node] = {'PID':row['PID'], 'label': row['PName'], 'type': NODE_TYPE.PROCESS, 'cmd': row['CommandLine'].replace('&quot;',' ').replace('\\','/'), 'is_warn': row['is_warn']=='True'}
            node_set.add(s_node)
            node_set.add(t_node)
            edge_set.add((s_node, t_node))
    elif key == EVENT_KEY.NET:
        # add net type node
        for index, row in logs.iterrows():
            s_node = get_md5(str(row['PID']) + str(row['PName']))
            node_attr[s_node] = {'label': row['PName'], 'type': NODE_TYPE.PROCESS, 'cmd': '', 'is_warn': False}
            src_ip = row['saddr']
            dst_ip = row['daddr']
            sport = row['sport']
            dport = row['dport']
            # protocol = row['protocol']
            # x = [src_ip,dst_ip,int(dst_port),protocol.upper()]
            # f = open('ip-test.csv','a',newline='')
            # writer = csv.writer(f)
            # writer.writerow(x)
            x = '{},{}/32'.format(src_ip,dst_ip)
            t_node = get_md5(x)
            node_attr[t_node] = {'label': x, 'type': NODE_TYPE.NET}
            node_set.add(s_node)
            node_set.add(t_node)
            edge_set.add((s_node, t_node))

    # add node
    node_list = list(node_set)
    node_list.sort()
    for node in node_list:
        g.add_node(node)

    nx.set_node_attributes(g, node_attr)

    # add edge
    edge_list = list(edge_set)
    edge_list.sort()
    for edge in edge_list:
        g.add_edge(edge[0], edge[1])

    # for node in g.nodes:
    #     if g.nodes[node]['type'] == NODE_TYPE.PROCESS:
    #         print(g.nodes[node]['is_warn'])
    print(len(attack_process))
    print(attack_process.keys())
    for i in attack_process:
        print(attack_process[i])
    return g
def benign_graph_add_node_mgr(g, logs, key):
    node_set = set()
    node_attr = {}
    edge_set = set()
    attack_process = {}
    if key == EVENT_KEY.FILE:
        # add file type node
        f = open('hw20/filename.txt', 'a')
        for index, row in logs.iterrows():
            Process = str(row['PID']) + str(row['PName'])
            s_node = get_md5(Process)
            node_attr[s_node] = {'label': row['PName'].replace('\\','/'), 'cmd':'', 'type': NODE_TYPE.PROCESS, 'is_warn': False}
            t_node = get_md5(row['FileName'])
            f.write(row['FileName'] + '\n')
            node_attr[t_node] = {'label': row['FileName'].replace('\\','/'), 'type': NODE_TYPE.FILE}
            # e_id = row['log_id']
            node_set.add(s_node)
            node_set.add(t_node)
            edge_set.add((s_node, t_node))
        f.close()
    elif key == EVENT_KEY.PROCESS:
        o = open('hw20/cmdline.txt','w')
        # add process type node
        for index, row in logs.iterrows():
            Parentid = row['ParentID'].replace(',','') + str(row['PPName'])
            # print(Parentid)
            s_node = get_md5(Parentid)
            if not (s_node in node_attr):
                node_attr[s_node] = {'label': '', 'cmd' : '','type': NODE_TYPE.PROCESS, 'is_warn': False}
            # node_attr[s_node] = {'name': row['PName'], 'type': NODE_TYPE.PROCESS, 'cmd': row['CommandLine']}
            t_node = get_md5(str(row['PID'])+ str(row['PName']))
            o.write(row['CommandLine'].replace('&quot;',' ') + '\n')
            node_attr[t_node] = {'label': row['PName'], 'type': NODE_TYPE.PROCESS, 'cmd': row['CommandLine'].replace('&quot;',' ').replace('\\','/'), 'is_warn': False}
            node_set.add(s_node)
            node_set.add(t_node)
            edge_set.add((s_node, t_node))
        o.close()
    elif key == EVENT_KEY.NET:
        # add net type node
        f = open('hw20/filename.txt', 'a')
        for index, row in logs.iterrows():
            s_node = get_md5(str(row['PID'])+ str(row['PName']))
            node_attr[s_node] = {'label': row['PName'], 'type': NODE_TYPE.PROCESS, 'cmd': '', 'is_warn': False}
            src_ip = row['saddr']
            dst_ip = row['daddr']
            sport = row['sport']
            dport = row['dport']
            # protocol = row['protocol']
            # x = [src_ip,dst_ip,int(dst_port),protocol.upper()]
            # f = open('ip-test.csv','a',newline='')
            # writer = csv.writer(f)
            # writer.writerow(x)
            x = '{},{}/32'.format(src_ip,dst_ip)
            f.write(x + '\n')
            t_node = get_md5(x)
            node_attr[t_node] = {'label': x, 'type': NODE_TYPE.NET}
            node_set.add(s_node)
            node_set.add(t_node)
            edge_set.add((s_node, t_node))
        f.close()
    # add node
    node_list = list(node_set)
    node_list.sort()
    for node in node_list:
        g.add_node(node)

    nx.set_node_attributes(g, node_attr)

    # add edge
    edge_list = list(edge_set)
    edge_list.sort()
    for edge in edge_list:
        g.add_edge(edge[0], edge[1])

    # for node in g.nodes:
    #     if g.nodes[node]['type'] == NODE_TYPE.PROCESS:
    #         print(g.nodes[node]['is_warn'])
    # print(len(attack_process))
    # for i in attack_process:
    #     print('{}:{}'.format(i,attack_process[i]))
    return g

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
    for e in graph.edges():
        graph[e[0]][e[1]]['weight'] = weight[e[0]]
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
    if s.endswith('/32'):
        s = s.replace('/32','')
        split_path = re.split('/|\.|,',s)
        split_path = [item for item in filter(lambda x:x != '',split_path)]
        # print(split_path)
        return split_path
    # Lower-case the string & strip non-alpha.
    for i in s:
        if i in string.punctuation:
            s = s.replace(i," ")

    split_path = s.lower().split()
    # split_path = [item for item in filter(lambda x:x != '',split_path)]
    newline = []
    for item in split_path:
        # print(item)
        if len(item) < 2 or item.isdigit():
            continue
        if len(item) <= 5 and len(item) >= 2:
            newline.append(item)
        else:
            # print(item)
            try:
                if not nonsense(item):
                    newline.append(item)
                else:
                # print(item)
                    newline.append('hash')
            except Exception as e:
                print(s)
    split_path = [item for item in filter(lambda x:x != '',newline)]
    return split_path