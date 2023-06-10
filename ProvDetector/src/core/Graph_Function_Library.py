import networkx
import networkx as nx
import pandas as pd
import matplotlib.pyplot as plt
from config.mgr_config import EVENT_KEY
from config.realAPT_config import APTLOG_KEY
from hashlib import md5
import queue
import copy

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


def graph_add_node(graph='', node_name=''):
    # -------
    # Function definition: 'graph_add_node()':
    # (1) add nodes to the graph G
    # -------
    # Required parameters:
    # (1) 'graph': a directed graph G
    # (2) 'node_name' (string): the name of node that is supposed to be added to a graph G
    # -------
    # Return: graph G
    # -------
    graph.add_nodes_from(node_name)
    print('Completed: add a node to graph G: node_name =', node_name)
    return graph


def graph_add_path(graph='', sysmon_log=''):
    # -------
    # Function definition: 'graph_add_path()':
    # (1) add paths to a graph G by traversing columns from each row in the sysmon_log
    # -------
    # Required parameters:
    # (1) 'graph': a directed graph G
    # (2) 'sysmon_log' (DataFrame): a DataFrame of sysmon_log.json
    # -------
    # Return: graph G
    # -------
    for index, row in pd.DataFrame.iterrows(sysmon_log):
        path = list(filter(None, row))
        if path != []:
            nx.add_path(graph, path)
    print('Completed: add paths to a graph G by traversing rows in the sysmon log')
    return graph


def graph_visualization(graph='', paths=''):
    # -------
    # Function definition: 'graph_visualization()':
    # (1) visualize a directed graph G
    # -------
    # Required parameters:
    # (1) 'graph': a directed graph G
    # -------
    # Return: fig.png
    # -------

    plt.figure(dpi=1200)
    pos = nx.spring_layout(graph)
    nx.draw_networkx_nodes(graph, pos, node_size=0.1, node_color='k')
    nx.draw_networkx_edges(graph, pos, width=0.01, arrowsize=1)
    for path in paths:
        path_edge = set(zip(path, path[1:]))
        nx.draw_networkx_nodes(graph, pos, nodelist=path, node_color='r', node_size=0.1)
        nx.draw_networkx_edges(graph, pos, edgelist=path_edge, edge_color='r', width=0.1, arrowsize=1)
    plt.axis('equal')
    plt.savefig('data/provenanceGraph.png')
    print('Completed: graph visualization')


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
    cnt = 0
    if nx.is_directed_acyclic_graph(graph) == True:
        print('Completed: DAG is True')
    else:
        print('Found: cycles in graph')
        while nx.is_directed_acyclic_graph(graph):# == False and cnt < 10000:
            print("remove ", cnt)
            edge_list = list(nx.find_cycle(graph, orientation='original'))
            graph.remove_edges_from(edge_list)
            cnt += 1
        print('Completed: DAG is True')
    weight = nx.pagerank(graph, alpha=1)
    for e in graph.edges():
        graph[e[0]][e[1]]['weight'] = weight[e[0]]
    print("testing")
    # nx.drawing.nx_pydot.write_dot(graph, 'realapt_data/dot/xxx' + '.dot')
    print("succese")
    return graph

def takefirst(elem):
    return elem[0]

def rareness_paths(graph=''):
    # -------
    # Function definition: 'top_k_rareness_paths()'
    # (1) find top k rareness paths in DAG
    # -------
    # Required parameters:
    # (1) 'graph': a directed aryclic graph DAG
    # (2) 'k': the number of rareness paths
    # -------
    # Return: top k rareness paths
    # -------
    print("nodes size ", len(graph.nodes()))
    all_paths = []
    
    roots = [v for v, d in graph.in_degree() if d == 0]
    print("root size is", len(roots))
    # for root in graph.nodes():
    for root in roots:
        que = queue.Queue()
        vis = set()
        # vis.add(root)
        que.put([root])
        while not que.empty():
            path = que.get()
            nex_node = path[-1]
            # print("~~~~~~~~~~~~~~~~~")
            # print(path)
            # print(nex_node)
            if nex_node in vis:
                # all_paths.append(path)
                continue
            vis.add(nex_node)
            # print(nex_node in graph.nodes())
            # print(graph.neighbors(nex_node))
            if len(list(graph.neighbors(nex_node))) == 0:
                if len(path) <5:
                    continue
                all_paths.append(path)
                # print(len(path))
                continue
            for nex in graph.neighbors(nex_node):
                # print(nex)
                # print(nex in graph.nodes())
                nex_path = copy.deepcopy(path)
                nex_path.append(nex)
                # nex_path[0] *= graph[nex_node][nex]['weight']
                # print(nex_path[0])
                que.put(nex_path)

            # print("~~~~~~~~~~~~~~~~~")
    all_paths.sort(key=len, reverse=True)

    # 由于新方法会导致groundTruth丢失，手动添加groundTruth
    st_pos = 0
    lim = 50
    for i, path in enumerate(all_paths):
        is_warn = False
        for j in range(1, len(path)):
            if graph[path[j-1]][path[j]]['is_warn']:
                is_warn = True
                break
        if is_warn and st_pos < lim:
            tmp_path = path
            all_paths[i] = all_paths[st_pos]
            all_paths[st_pos] = tmp_path
            st_pos += 1
    # all_paths = [path[1] for path in all_paths]
    # roots = [v for v, d in graph.in_degree() if d == 0]
    # print(len(roots))
    # leaves = [v for v, d in graph.out_degree() if d == 0]
    # print(len(leaves))
    # all_paths = []
    # for root in roots:
    #     for leaf in leaves:
    #         if nx.has_path(graph, root, leaf) == True:
    #             path = nx.dijkstra_path(graph, root, leaf, weight='weight')
    #             # print(path)
    #             all_paths.append(path)
    #         else:
    #             continue
    # all_paths.sort(key=len, reverse=True)
    # print("all_paths len:", len(all_paths))
    # print('Completed: top-k-rareness paths selection')
    return all_paths

def get_md5(s):
    """
    get md5 hash value of String s
    :param s:
    :return:
    """
    return str(md5(s.encode('utf8')).hexdigest())

def graph_add_node_mgr(g: networkx.Graph, logs, key, md5_to_node:dict):
    node_set = set()
    edge_set = set()
    if key == EVENT_KEY.FILE:
        # add file type node
        for index, row in logs.iterrows():
            s_node = get_md5(row['process_path'])
            t_node = get_md5(row['file_name'])
            if s_node not in md5_to_node:
                md5_to_node[s_node] = row['process_path']
            if t_node not in md5_to_node:
                md5_to_node[t_node] = row['file_name']
            e_id = row['log_id']
            is_warn = row['is_warn']
            node_set.add(s_node)
            node_set.add(t_node)
            edge_set.add((s_node, t_node, e_id, is_warn))
    elif key == EVENT_KEY.PROCESS:
        # add process type node
        for index, row in logs.iterrows():
            s_node = get_md5(row['parent_ppath'])
            t_node = get_md5(row['process_path'])
            if s_node not in md5_to_node:
                md5_to_node[s_node] = row['parent_ppath']
            if t_node not in md5_to_node:
                md5_to_node[t_node] = row['process_path']
            e_id = row['log_id']
            is_warn = row['is_warn']
            node_set.add(s_node)
            node_set.add(t_node)
            edge_set.add((s_node, t_node, e_id, is_warn))
    elif key == EVENT_KEY.NET:
        # add net type node
        for index, row in logs.iterrows():
            s_node = get_md5(row['process_path'])
            src_ip = row['src_ip']
            dst_ip = row['dst_ip']
            src_port = row['src_port']
            dst_port = row['src_port']
            protocol = row['protocol']
            t_node = get_md5(f'{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}')
            if s_node not in md5_to_node:
                md5_to_node[s_node] = row['process_path']
            if t_node not in md5_to_node:
                md5_to_node[t_node] = f'{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}'
            e_id = row['log_id']
            is_warn = row['is_warn']
            node_set.add(s_node)
            node_set.add(t_node)
            edge_set.add((s_node, t_node, e_id, is_warn))
    elif key == EVENT_KEY.DNS:
        # add dns type node
        for index, row in logs.iterrows():
            s_node = get_md5(row['process_path'])
            query_name = row['query_name']
            query_results = row['query_results']
            query_status = row['query_status']
            t_node = get_md5(f'{query_name}-{query_results}-{query_status}')
            if s_node not in md5_to_node:
                md5_to_node[s_node] = row['process_path']
            if t_node not in md5_to_node:
                md5_to_node[t_node] = f'{query_name}-{query_results}-{query_status}'
            e_id = row['log_id']
            is_warn = row['is_warn']
            node_set.add(s_node)
            node_set.add(t_node)
            edge_set.add((s_node, t_node, e_id, is_warn))
    elif key == EVENT_KEY.REG:
        # add reg type node
        for index, row in logs.iterrows():
            s_node = get_md5(row['process_path'])
            t_node = get_md5(row['target_object'])
            if s_node not in md5_to_node:
                md5_to_node[s_node] = row['process_path']
            if t_node not in md5_to_node:
                md5_to_node[t_node] = row['target_object']
            e_id = row['log_id']
            is_warn = row['is_warn']
            node_set.add(s_node)
            node_set.add(t_node)
            edge_set.add((s_node, t_node, e_id, is_warn))
    elif key == EVENT_KEY.SCHTASK:
        # add schtask type node
        for index, row in logs.iterrows():
            s_node = get_md5(row['process_path'])
            task_name = row['task_name']
            task_path = row['task_path']
            task_user = row['task_user']
            task_frequency = row['task_frequency']
            t_node = get_md5(f'{task_name}-{task_path}-{task_user}-{task_frequency}')
            if s_node not in md5_to_node:
                md5_to_node[s_node] = row['process_path']
            if t_node not in md5_to_node:
                md5_to_node[t_node] = f'{task_name}-{task_path}-{task_user}-{task_frequency}'
            e_id = row['log_id']
            is_warn = row['is_warn']
            node_set.add(s_node)
            node_set.add(t_node)
            edge_set.add((s_node, t_node, e_id, is_warn))

    # add node
    node_list = list(node_set)
    node_list.sort()
    for node in node_list:
        g.add_node(node)

    # add edge
    edge_list = list(edge_set)
    edge_list.sort()
    for edge in edge_list:
        g.add_edge(edge[0], edge[1], e_id=edge[2], is_warn=edge[3])

    return g

def graph_add_node_realapt(g: networkx.Graph, logs, key, md5_to_node:dict):
    node_set = set()
    edge_set = set()
    if key == APTLOG_KEY.FILE:
        # add file type node
        for index, row in logs.iterrows():
            s_node = get_md5(row['proc.cmdline'])
            t_node = get_md5(row['fd.name'])
            if s_node not in md5_to_node:
                md5_to_node[s_node] = row['proc.cmdline']
            if t_node not in md5_to_node:
                md5_to_node[t_node] = row['fd.name']
            e_id = row['log_id']
            is_warn = row['is_warn']
            node_set.add(s_node)
            node_set.add(t_node)
            edge_set.add((s_node, t_node, e_id, is_warn))
    elif key == APTLOG_KEY.PROCESS:
        # add process type node
        for index, row in logs.iterrows():
            s_node = get_md5(row['proc.pcmdline'])
            t_node = get_md5(row['proc.cmdline'])
            if s_node not in md5_to_node:
                md5_to_node[s_node] = row['proc.pcmdline']
            if t_node not in md5_to_node:
                md5_to_node[t_node] = row['proc.cmdline']
            e_id = row['log_id']
            is_warn = row['is_warn']
            node_set.add(s_node)
            node_set.add(t_node)
            edge_set.add((s_node, t_node, e_id, is_warn))
    elif key == APTLOG_KEY.NET:
        # add net type node
        for index, row in logs.iterrows():
            s_node = get_md5(row['proc.cmdline'])
            t_node = get_md5(row['fd.name'])
            if s_node not in md5_to_node:
                md5_to_node[s_node] = row['proc.cmdline']
            if t_node not in md5_to_node:
                md5_to_node[t_node] = row['fd.name']
            e_id = row['log_id']
            is_warn = row['is_warn']
            node_set.add(s_node)
            node_set.add(t_node)
            edge_set.add((s_node, t_node, e_id, is_warn))
    elif key == APTLOG_KEY.EXECVE:
        # add execve type node
        for index, row in logs.iterrows():
            s_node = get_md5(row['proc.cmdline'])
            t_node = get_md5((row['evt.args']).strip('filename='))
            if s_node not in md5_to_node:
                md5_to_node[s_node] = row['proc.cmdline']
            if t_node not in md5_to_node:
                md5_to_node[t_node] = (row['evt.args']).strip('filename=')
            e_id = row['log_id']
            is_warn = row['is_warn']
            node_set.add(s_node)
            node_set.add(t_node)
            edge_set.add((s_node, t_node, e_id, is_warn))

    # add node
    node_list = list(node_set)
    node_list.sort()
    for node in node_list:
        g.add_node(node)
        g.nodes[node]['label'] = md5_to_node[node]

    # add edge
    edge_list = list(edge_set)
    edge_list.sort()
    for edge in edge_list:
        g.add_edge(edge[0], edge[1], e_id=edge[2], is_warn=edge[3])

    return g
