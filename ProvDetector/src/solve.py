from core.Provenance_Graph import *
from core.Local_Outlier_Detection import *
import json
import numpy
import os
from tqdm import tqdm
from config import ANFU_TYPE
from hashlib import md5
from concurrent.futures import ThreadPoolExecutor
import resource
import time
from time import sleep

def get_md5(s):
    """
    get md5 hash value of String s
    :param s:
    :return:
    """
    return str(md5(s.encode('utf8')).hexdigest())

def get_md5_process():
    src_file = '../data/anfu_data/attack_md5.txt'
    attack_list = list()
    with open(src_file, 'r') as rf:
        for line in rf:
            line = line.rstrip('\n')
            if line:
                attack_list.append(line)
    return attack_list

def build_graph(src_log, md5_to_node:dict):
    process_nodes = set()
    attack_nodes = set()
    g = nx.DiGraph()
    attack_set = get_md5_process()
    attack_set = set(attack_set)
    print(attack_set)
    event_num = 0
    with open(src_log, 'r') as rf:
        for line in tqdm(rf):
            line = line.rstrip('\n')
            log = json.loads(line)
            event_id = log['datatype']
            if event_id in ANFU_TYPE.FILE_OP:
                from_id = str(int(log['pid'])) + ':' + log['pcommand']
                to_id = log['filename']
                s_node = get_md5(from_id)
                # print("~~~~~~~~~~~~~~")
                # print(from_id)
                # print(s_node)
                # print("~~~~~~~~~~~~~~")
                # break

                t_node = get_md5(to_id)
                if s_node not in md5_to_node:
                    md5_to_node[s_node] = from_id
                if t_node not in md5_to_node:
                    md5_to_node[t_node] = to_id
                if s_node not in g.nodes().keys():
                    g.add_node(s_node)
                if t_node not in g.nodes().keys():
                    g.add_node(t_node)
                is_warn = False
                if s_node in attack_set or t_node in attack_set:
                    is_warn = True
                process_nodes.add(s_node)
                if is_warn:
                    attack_nodes.add(s_node)
                g.add_edge(s_node, t_node, e_id=event_num, is_warn=is_warn)
                event_num += 1
                pass
            if event_id in ANFU_TYPE.PROCESS_OP:
                from_id = str(int(log['ppid'])) + ':' + log['ppcommand']
                to_id = str(int(log['pid'])) + ':' + log['pcommand']
                s_node = get_md5(from_id)
                t_node = get_md5(to_id)
                if s_node not in md5_to_node:
                    md5_to_node[s_node] = from_id
                if t_node not in md5_to_node:
                    md5_to_node[t_node] = to_id
                if s_node not in g.nodes().keys():
                    g.add_node(s_node)
                if t_node not in g.nodes().keys():
                    g.add_node(t_node)
                process_nodes.add(s_node)
                process_nodes.add(t_node)
                is_warn = False
                if s_node in attack_set or t_node in attack_set:
                    is_warn = True
                if is_warn:
                    attack_nodes.add(s_node)
                    attack_nodes.add(t_node)
                g.add_edge(s_node, t_node, e_id=event_num, is_warn=is_warn)
                event_num += 1
                pass
            if event_id in ANFU_TYPE.NET_OP:
                src_ip = log['srcip']
                dst_ip = log['dstip']
                src_port = log['srcport']
                dst_port = log['dstport']
                to_id = '{},{},{},{}'.format(src_ip, dst_ip, int(src_port), int(dst_port))
                from_id = str(int(log['pid'])) + ':' + log['pcommand']
                s_node = get_md5(from_id)
                t_node = get_md5(to_id)
                if s_node not in md5_to_node:
                    md5_to_node[s_node] = from_id
                if t_node not in md5_to_node:
                    md5_to_node[t_node] = to_id
                if s_node not in g.nodes().keys():
                    g.add_node(s_node)
                if t_node not in g.nodes().keys():
                    g.add_node(t_node)
                process_nodes.add(s_node)
                is_warn = False
                if s_node in attack_set or t_node in attack_set:
                    is_warn = True
                if is_warn:
                    attack_nodes.add(s_node)
                g.add_edge(s_node, t_node, e_id=event_num, is_warn=is_warn)
                event_num += 1
                pass
    print("event_num is: ", event_num)
    print("attack node set", len(attack_nodes))
    # for node in g.nodes().keys():
    #     if node in attack_set:
    #         print("?????????????")
            # g.nodes[node]['is_warn'] = True
    weight = nx.pagerank(g, alpha=1)
    for e in g.edges():
        g[e[0]][e[1]]['weight'] = weight[e[0]]
    DAG = directed_acyclic_graph(graph=g)
    # select top-k rareness paths from the DAG
    all_paths = rareness_paths(graph=DAG)
    # graph_visualization(DAG, rareness_paths)
    return g, all_paths, process_nodes, attack_nodes

def get_graphsize(all_paths, process_nodes, attack_nodes):
    cnt_process = set()
    cnt_nodes = set()
    cnt_attacknodes = set()
    event_num = 0
    total_nodes = 0
    for path in all_paths:
        event_num += len(path) - 1
        total_nodes += len(path)
        for node in path:
            node = get_md5(node)
            cnt_nodes.add(node)
            if node in process_nodes:
                cnt_process.add(node)
                if node in attack_nodes:
                    cnt_attacknodes.add(node)
    return {"cnt_process":len(cnt_process), "cnt_nodes":len(cnt_nodes),
        "cnt_attacknodes":len(cnt_attacknodes), "event_num":event_num, 
        "total_nodes":total_nodes}


def train_anfu():
    benign_log = "../data/anfu_data/benign.json"
    anomaly_log = "../data/anfu_data/anomaly.json"
    k_values = [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000]
    train_md5_to_node = dict()
    test_md5_to_node = dict()
    train_g, train_all_paths, train_process, train_attacknodes = build_graph(benign_log, train_md5_to_node)
    test_g, test_all_paths, test_process, test_attacknodes = build_graph(anomaly_log, test_md5_to_node)
    all_ground_truth_path = get_ground_truth_paths(test_g, test_all_paths, test_md5_to_node)
    out_dict = dict()
    for k in k_values:
        result = dict()
        train_paths = train_all_paths[:k]
        test_paths = test_all_paths[:k]

        print("train", len(train_paths))
        print("test", len(test_paths))
        train = doc2vec(train_paths)
        test = doc2vec(test_paths)
        detect_result = local_outlier_factor(train, test)
        outliers_path_edge, outliers_paths = trace_back_analysis_log4j(test_g, detect_result, test_paths,
                                                                       test_md5_to_node)
        ground_truth_paths = get_ground_truth_paths(test_g, test_paths, test_md5_to_node)
        result['grapth_size'] = get_graphsize(outliers_paths,test_process, test_attacknodes)
        result['ground_truth_path'] = ground_truth_paths
        result['outlier_paths'] = outliers_paths
        metric, hit_paths, false_alarm_paths = get_metric(ground_truth_paths, outliers_paths)
        result['hit_paths'] = hit_paths
        result['false_alarm_paths'] = false_alarm_paths
        result['metric'] = metric
        out_dict[k] = metric
        result['top-k'] = k
        # outliers_log = black_log[black_log['log_id'].isin(outliers_edge)]
        with open(f"../data/anfu_data/anfu_result_{k}.json", 'w', encoding='utf8') as f:
            json.dump(result, f, indent=2)
        # print(outliers_paths)
    print(out_dict)

class MemoryMonitor:
    def __init__(self):
        self.keep_measuring = True
    def measure_usage(self):
        max_usage = 0
        min_usage = 99999999999999
        cnt_use = 0
        sum_usage = 0
        while self.keep_measuring:
            cnt_use += 1
            now_usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            sum_usage += now_usage
            max_usage = max(
                max_usage,
                now_usage
            )
            min_usage = min(
                min_usage,
                now_usage
            )
            sleep(0.1)
        return max_usage, min_usage, sum_usage / cnt_use

if __name__ == '__main__':

    with ThreadPoolExecutor() as executor:
        monitor = MemoryMonitor()
        mem_thread = executor.submit(monitor.measure_usage)
        try:
            fn_thread = executor.submit(train_anfu)
            result = fn_thread.result()
        finally:
            monitor.keep_measuring = False
            max_usage, min_usage, average_usage = mem_thread.result()
        print(f"Max memory usage: {max_usage}")
        print(f"Min memory usage: {min_usage}")
        print(f"Average memory usage: {average_usage}")