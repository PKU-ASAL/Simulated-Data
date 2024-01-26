import networkx as nx
import json
import pandas as pd
from config import *
from tools import *
from argparse import ArgumentParser
import random
def split_cmd_and_filename(file_path,dataset):
    f = open(file_path,'r')
    o1 = open(dataset+'/cmdline.txt','w')
    o2 = open(dataset+'/filename.txt','w')
    print('start graph')
    isprocess_file = True
    while True:
        line = f.readline()
        if line == '\n':
            isprocess_file = True
            continue
        if not line:
            break
        filepath = line.strip().lower()
        if filepath.endswith('$$$true'):
            filepath = filepath.replace('$$$true','')
        elif filepath.endswith('$$$false'):
            filepath = filepath.replace('$$$false','')

        split_path = sanitize_string(filepath)
        if len(split_path) == 0:
            continue

        if isprocess_file:
            o1.write(filepath + '\n')
            isprocess_file = False
        else:
            o2.write(filepath + '\n')
    o1.close()
    o2.close()

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--file",type = str, default='benign.json')
    parser.add_argument("--d",type = str, default = 'hw17')
    args = parser.parse_args()
    file_path = args.file
    dataset = args.d
    G = nx.DiGraph()
    org_log = read_org_log_from_json(dataset + '/' + file_path)

    file_op_logs = org_log[org_log['evt.type'].isin(APTLOG_TYPE.FILE_OP)]
    print('file logs count:', len(file_op_logs))
    process_op_logs = org_log[org_log['evt.type'].isin(APTLOG_TYPE.PROCESS_OP)]
    print('process logs count:', len(process_op_logs))
    net_op_logs = org_log[org_log['evt.type'].isin(APTLOG_TYPE.NET_OP)]
    print('net logs count:', len(net_op_logs))
    # execve_op_logs = org_log[org_log['evt.type'].isin(APTLOG_TYPE.EXECVE_OP)]
    # print('execve logs count:', len(execve_op_logs))

    if 'benign' in file_path:
        if len(file_op_logs) > 0:
            file_op_logs = file_op_logs[BENLOG_ARTRIBUTE.FILE_ARTRIBUTE]
        if len(process_op_logs) > 0:
            process_op_logs = process_op_logs[BENLOG_ARTRIBUTE.PROCESS_ARTRIBUTE]
        if len(net_op_logs) > 0:
            net_op_logs = net_op_logs[BENLOG_ARTRIBUTE.NET_ARTRIBUTE]
        G = graph_init()

        md5_to_node = {}
        node_to_type = {}
        
        G, _ = graph_add_node_benign(G, file_op_logs, APTLOG_KEY.FILE, md5_to_node, node_to_type)
        G, _ = graph_add_node_benign(G, process_op_logs, APTLOG_KEY.PROCESS, md5_to_node, node_to_type)
        G, _ = graph_add_node_benign(G, net_op_logs, APTLOG_KEY.NET, md5_to_node, node_to_type)

    else:
        if len(file_op_logs) > 0:
            file_op_logs = file_op_logs[APTLOG_ARTRIBUTE.FILE_ARTRIBUTE]
        if len(process_op_logs) > 0:
            process_op_logs = process_op_logs[APTLOG_ARTRIBUTE.PROCESS_ARTRIBUTE]
        if len(net_op_logs) > 0:
            net_op_logs = net_op_logs[APTLOG_ARTRIBUTE.NET_ARTRIBUTE]

        G = graph_init()

        md5_to_node = {}
        node_to_type = {}
        anomalyset = set()
        G, x = graph_add_node_realapt(G, file_op_logs, APTLOG_KEY.FILE, md5_to_node, node_to_type)
        anomalyset |= x
        G, x = graph_add_node_realapt(G, process_op_logs, APTLOG_KEY.PROCESS, md5_to_node, node_to_type)
        anomalyset |= x
        G, x = graph_add_node_realapt(G, net_op_logs, APTLOG_KEY.NET, md5_to_node, node_to_type)
        anomalyset |= x
        print(len(anomalyset))
    # G = graph_add_node_realapt(G, execve_op_logs, APTLOG_KEY.EXECVE, md5_to_node, node_to_type)

    # nx.drawing.nx_pydot.write_dot(G, 'test.dot')
    # DAG = directed_acyclic_graph(graph=G)

    # print(len(G.nodes))
    # for i,g in enumerate(nx.weakly_connected_components(G)):
    #     subgraph = G.subgraph(g)
    #     nx.drawing.nx_pydot.write_dot(subgraph, str(i) + '.dot')

    attack_process = set()
    # DAG = directed_acyclic_graph(graph=G)
    is_anomaly = True
    if 'benign' in file_path:
        is_anomaly = False
        event_file = dataset + '/process-event-benign.txt'
    else:
        event_file = dataset + '/process-event-anomaly.txt'
    data = open(event_file,'w')
    for node in G:
        if G.nodes[node]['type'] == APTLOG_NODE_TYPE.PROCESS:
            if G.nodes[node]['label'] != '':
                if is_anomaly:
                    data.write(G.nodes[node]['label'] + '$$$' + str(G.nodes[node]['is_warn']) +'\n')
                    if G.nodes[node]['is_warn']:
                        attack_process.add(node)

                else:
                    data.write(G.nodes[node]['label'] + '\n')
                # data.write(G.nodes[node]['label'] + '\n')
                
                for i in G.successors(node):
                    if G.nodes[i]['label'] != 'unknown' and G.nodes[i]['type'] != APTLOG_NODE_TYPE.PROCESS and G.nodes[i]['label'] != '':
                        data.write(G.nodes[i]['label'] + '\n')
                for i in G.predecessors(node):
                    if G.nodes[i]['label'] != 'unknown' and G.nodes[i]['type'] != APTLOG_NODE_TYPE.PROCESS and G.nodes[i]['label'] != '':
                        data.write(G.nodes[i]['label'] + '\n')
                data.write('\n')

    data.close()
    print(attack_process)
    if 'benign' in event_file:
        split_cmd_and_filename(event_file,dataset)