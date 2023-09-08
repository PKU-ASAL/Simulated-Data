from argparse import ArgumentParser
import networkx as nx
from streamz import Stream
from ProvGraph import *
import matplotlib.pyplot as plt
import json
import time,sched
import multiprocessing
from multiprocessing.managers import BaseManager
import schedule
from CacheGraph import *

from queue import Queue
from threading import Thread
import sys
sys.path.append('..')
from config import *


def get_keys(d, value):
    return [k for k,v in d.items() if v == value]

def extract_string(s):
    arr = []
    r = ''
    inside = True
    for n,i in enumerate(s):
        if i == '"' and (s[n-1] != '\\' or n == 0):
            arr.append(i)
            if len(arr) % 2 == 0:
                inside = False
            else:
                inside = True
        r += i
        if i == '}' and not inside:
            return r

def get_orgs(line):
    # match_obj = re.match(r'(.*)\\"org_log\\":(.*)',line)
    # org = extract_string(match_obj.group(2).replace('\\\\','\\').replace('\\*','\*').replace('\\$','\$').replace('\\"','\"'))
    org_logs = json.loads(line)
    # org_logs['log_id'] = cnt
    return org_logs


def log_parser(q,dataset,anomaly_cutoff):
    proGraph = ProvGraph(dataset)
    start_time = time.time()
    point_start = start_time
    thread_list = []
    # cnt = 0
    while True:
        log_line = q.recv()
        # cnt += 1
        if log_line == "end":
            proGraph.thread_lock.acquire()
            print("start_update")
            t = threading.Thread(target = proGraph.update,args=(anomaly_cutoff,))
            t.start()
            thread_list.append(t)
            break
        else:
            org_log = get_orgs(log_line)
            if org_log['EventName'] in EVENT_TYPE.FILE_OP or org_log['EventName'] in EVENT_TYPE.IMAGE_OP:
                proGraph.graph_add_node_mgr(org_log, EVENT_KEY.FILE, org_log['EventName'])
            elif org_log['EventName']in EVENT_TYPE.PROCESS_OP:
                proGraph.graph_add_node_mgr(org_log, EVENT_KEY.PROCESS, org_log['EventName'])
            elif org_log['EventName'] in EVENT_TYPE.NETSend_OP or org_log['EventName'] in EVENT_TYPE.NETRec_OP:
                # print(EVENT_KEY.NET)
                proGraph.graph_add_node_mgr(org_log, EVENT_KEY.NET, org_log['EventName'])
            
        end_time = time.time()
        if end_time - start_time >= 10:
            proGraph.thread_lock.acquire()
            print("start_update")
            t = threading.Thread(target = proGraph.update,args=(anomaly_cutoff,))
            t.start()
            thread_list.append(t)
            # proGraph.update()
            start_time = end_time
            # proGraph.TmpG.clear()

    for t in thread_list:
        t.join()

    point_end = time.time()
    print('cost time:', point_end - point_start)
####### analyze the result ########
####### you can rewrite this part ##########
####### 1. check if the anomaly grpah is highly ranked ########

    # print(cnt)
    cnt = 0
    for i in proGraph.node_set:
        if i in proGraph.attack_process and proGraph.nodes[i]['score']!=0 :
            cnt += 1
            print(i, proGraph.nodes[i]['score'])
    # for i in proGraph.attack_process:
    #     print('attack: ',i,proGraph.nodes[i]['score'])
    print('rate: ', cnt/len(proGraph.attack_process))


    cnt = 0
    for i, g in enumerate(proGraph.graph_cache):

        # g.graph = proGraph.final_graph_taylor(g.graph)

        for k in g.graph.nodes():
            # if (g.graph.in_degree(k) == 1 and g.graph.degree(k) == 1 ):
            #     removelist.append(k)
            if proGraph.GetNodeType(k) == NODE_TYPE.PROCESS:
                g.graph.nodes[k]['label'] = proGraph.GetNodeCmd(k)
                g.graph.nodes[k]['score'] = proGraph.GetNodeScore(k)
                g.graph.nodes[k]['shape'] = 'box'
            elif proGraph.GetNodeType(k) == NODE_TYPE.NET:
                g.graph.nodes[k]['label'] = proGraph.GetNodeName(k)
                g.graph.nodes[k]['shape'] = 'diamond'
                g.graph.nodes[k]['score'] = 0
            else:
                g.graph.nodes[k]['label'] = proGraph.GetNodeName(k)
                g.graph.nodes[k]['shape'] = 'ellipse'
                g.graph.nodes[k]['score'] = 0

        for i in proGraph.taylor_map:
            origion = i
            while i in proGraph.taylor_map:
                i = proGraph.taylor_map[i]
            proGraph.taylor_map[origion] = i

        flag = False
        tmp_hit = set()
        for node in g.graph.nodes():
            if node in proGraph.attack_process:
                flag = True
                tmp_hit.add(node)
            x = get_keys(proGraph.taylor_map,node)
            if len(x) != 0:
                for n in x:
                    if n in proGraph.attack_process:
                        flag = True
                        tmp_hit.add(n)   


        removelist = []
        for k in g.graph.nodes():
            if 'desktop.ini' in proGraph.GetNodeName(k):
                removelist.append(k)
            elif proGraph.GetNodeType(k) == NODE_TYPE.PROCESS:
                if 'log.txt' in proGraph.GetNodeCmd(k):
                    removelist.append(k)
                else:
                    g.graph.nodes[k]['label'] = proGraph.GetNodeCmd(k) + ' ' + str(proGraph.GetNodeScore(k))
            else:
                g.graph.nodes[k]['label'] = proGraph.GetNodeName(k) + ' ' + str(proGraph.GetNodeScore(k))
        g.graph.remove_nodes_from(removelist)

        if flag:
            print(g.GetGraphScore(),'attack',tmp_hit,len(g.graph.nodes()))
            proGraph.hit |= tmp_hit
        if not flag:
            # sort(key = lambda x: x.graph['score'],reverse = True)
            print(g.GetGraphScore(),'benign',len(g.graph.nodes()))
        
        result_graph = ''
        max_len = 0
        for x in nx.weakly_connected_components(g.graph):
            if len(x) > max_len:
                max_len = len(x)
                result_graph = g.graph.subgraph(x)
        
        for k in result_graph.nodes():
            result_graph.nodes[k]['label'] = result_graph.nodes[k]['label'].replace(':','')
        
        nx.drawing.nx_pydot.write_dot(result_graph, '../' + dataset + '/dot/' + str(cnt) + '.dot')
        cnt += 1
    
    # json.dump(proGraph.taylor_map,open('../' + dataset + '/dot/tailor-map.json','w'))
    print("recall: ",len(proGraph.hit)/len(proGraph.attack_process))
    print(len(proGraph.attack_process))
    x = set(proGraph.attack_process) - proGraph.hit
    for i in x:
        print(i, proGraph.GetNodeCmd(i))
    print(len(proGraph.node_set),len(proGraph.filtered))
    out_process = open('../' + dataset + '/detected-process.txt','w')
    for i in proGraph.filtered:
        if i in proGraph.attack_process:
            out_process.write(i + ',1,' + proGraph.GetNodeCmd(i) + '\n')
        else:
            out_process.write(i + ',0,' + proGraph.GetNodeCmd(i) + '\n')
    out_process.close()
        
    
def proc_send(q,event_file):
    for line in open(event_file):
        q.send(line)
    q.send("end")

if __name__ == "__main__":
    multiprocessing.set_start_method('spawn')


    parser = ArgumentParser(description="Multi arm bandits")
    parser.add_argument("--d", type=str, default="win10", help="dataset dict name")
    parser.add_argument("--t", type=float, help="threshold")
    args = parser.parse_args()
    dataset = args.d
    anomaly_cutoff = args.t
    stream_file = "../" + dataset + "/anomaly.json"


    pipe = multiprocessing.Pipe()
    t1 = multiprocessing.Process(target=proc_send, args=(pipe[0], stream_file,))
    t2 = multiprocessing.Process(target=log_parser, args=(pipe[1], dataset, anomaly_cutoff,))
    start_time = time.time()
    
    t1.start()
    t2.start()

    
    t1.join()
    t2.join()
    
    
    end_time = time.time()
    print(end_time-start_time)

