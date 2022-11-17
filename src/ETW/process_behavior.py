import networkx as nx
import json
import pandas as pd
from config import *
from tools import *
from argparse import ArgumentParser
import random

if __name__ == "__main__":
    parser = ArgumentParser()
    # parser.add_argument("--dataset",type=str,default='E3-cadets')
    parser.add_argument("--file",type = str, default='benign2G.json')
    parser.add_argument("--d",type = str, default = 'win10')
    args = parser.parse_args()
    # dataset = args.dataset
    file_path = args.file
    dataset = args.d
    G = nx.DiGraph()
    org_log = read_org_log_from_json(dataset + '/' + file_path)

    file_op_logs = org_log[org_log['EventName'].isin(EVENT_TYPE.FILE_OP)]
    print('file logs count:', len(file_op_logs))
    process_op_logs = org_log[org_log['EventName'].isin(EVENT_TYPE.PROCESS_OP)]
    print('process logs count:', len(process_op_logs))
    netrecv_op_logs = org_log[org_log['EventName'].isin(EVENT_TYPE.NETRec_OP)]
    print('netrec logs count:', len(netrecv_op_logs))
    netsend_op_logs = org_log[org_log['EventName'].isin(EVENT_TYPE.NETSend_OP)]
    print('netsend logs count:', len(netsend_op_logs))
    image_op_logs = org_log[org_log['EventName'].isin(EVENT_TYPE.IMAGE_OP)]
    print('image logs count:', len(image_op_logs))

    file_op_logs = file_op_logs[EVENT_ARTRIBUTE.FILE_ARTRIBUTE]
    process_op_logs = process_op_logs[EVENT_ARTRIBUTE.WITHPARENT_PROCESS_START_ARTRIBUTE]
    netrecv_op_logs = netrecv_op_logs[EVENT_ARTRIBUTE.NETRecv_ARTRIBUTE]
    netsend_op_logs = netsend_op_logs[EVENT_ARTRIBUTE.NETSend_ARTRIBUTE]
    image_op_logs = image_op_logs[EVENT_ARTRIBUTE.IMAGE_ARTRIBUTE]



    # dns_op_logs = dns_op_logs[EVENT_ARTRIBUTE.DNS_ARTRIBUTE]
    # reg_op_logs = reg_op_logs[EVENT_ARTRIBUTE.REG_ARTRIBUTE]
    # schtask_op_logs = schtask_op_logs[EVENT_ARTRIBUTE.SCHTASK_ARTRIBUTE]

    G = graph_init()
    if 'benign' in file_path:
        G = benign_graph_add_node_mgr(G, file_op_logs, EVENT_KEY.FILE)
        G = benign_graph_add_node_mgr(G, netsend_op_logs, EVENT_KEY.NET)
        G = benign_graph_add_node_mgr(G, netrecv_op_logs, EVENT_KEY.NET)
        G = benign_graph_add_node_mgr(G, image_op_logs, EVENT_KEY.FILE)
        G = benign_graph_add_node_mgr(G, process_op_logs, EVENT_KEY.PROCESS)
    else:
        G = graph_add_node_mgr(G, file_op_logs, EVENT_KEY.FILE)
        G = graph_add_node_mgr(G, netsend_op_logs, EVENT_KEY.NET)
        G = graph_add_node_mgr(G, netrecv_op_logs, EVENT_KEY.NET)
        G = graph_add_node_mgr(G, image_op_logs, EVENT_KEY.FILE)
        G = graph_add_node_mgr(G, process_op_logs, EVENT_KEY.PROCESS)

    # G = graph_add_node_mgr(G, dns_op_logs, EVENT_KEY.DNS)
    # G = graph_add_node_mgr(G, reg_op_logs, EVENT_KEY.REG)
    # G = graph_add_node_mgr(G, schtask_op_logs, EVENT_KEY.SCHTASK)

    # nx.drawing.nx_pydot.write_dot(G, 'test.dot')
    # DAG = directed_acyclic_graph(graph=G)

    # nx.drawing.nx_pydot.write_dot(G, str(i) + '.dot')


    is_anomaly = True
    if 'benign' in file_path:
        is_anomaly = False
        event_file = dataset + '/process-event-benign.txt'
    else:
        event_file = dataset + '/process-event-anomaly.txt'
    data = open(event_file,'w')
    cnt = 0
    hit = set()

    

    for node in G:
        if G.nodes[node]['type'] == NODE_TYPE.PROCESS:
            if G.nodes[node]['cmd'] == '' and G.nodes[node]['label'] == '':
                continue
            if G.nodes[node]['is_warn']:
                hit.add(node)
                
            if G.nodes[node]['cmd'] != '':
                data.write(G.nodes[node]['cmd'] + '$$$' + str(G.nodes[node]['label']) + '$$$' + str(G.nodes[node]['is_warn']) +'\n')

            elif G.nodes[node]['label'] != '':
                # if G.nodes[node]['label'] == 'exploer':
                # print(G.nodes[node]['label'])
                data.write(G.nodes[node]['label'] + '$$$'+ str(G.nodes[node]['label']) + '$$$' + str(G.nodes[node]['is_warn']) +'\n')
                
            for i in G.successors(node):
                if G.nodes[i]['label'] != '' and G.nodes[i]['type'] != NODE_TYPE.PROCESS:
                    data.write(G.nodes[i]['label'] + '\n')
            for i in G.predecessors(node):
                if G.nodes[i]['label'] != '' and G.nodes[i]['type'] != NODE_TYPE.PROCESS:
                    data.write(G.nodes[i]['label'] + '\n')
            data.write('\n')

    # nx.drawing.nx_pydot.write_dot(G, 'anomaly.dot')

    data.close()
    # print(len(hit))
    # x = ground_truth - hit
    # print(x)

    # for i in x:
    #     print(G.nodes[i])
    # print(pid)
    # for i in range(20):
    #     x = random.randint(1000,9999)
    #     if not (x in pid):
    #         print(x)
    # if 'benign' in event_file:
    #     split_cmd_and_filename(event_file,dataset)
            

