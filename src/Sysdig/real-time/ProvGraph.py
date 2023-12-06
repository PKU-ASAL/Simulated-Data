
import networkx as nx
from collections import Counter, defaultdict
import threading
from VAE import AnomalyScore
from CacheGraph import *
import numpy as np
from gensim.models import FastText
import json
import re
# from main import thread_lock
from multiprocessing import Process,Lock
from matplotlib import pyplot as plt
from sklearn.neighbors import LocalOutlierFactor
from sklearn.covariance import EllipticEnvelope
from sklearn.svm import OneClassSVM
from nostril import nonsense
from collections import Counter
import smirnov_grubbs as grubbs
import string
import math
import os
import sys
from nearpy import Engine
import nearpy
from nearpy.hashes import RandomBinaryProjections
from nearpy.filters import NearestFilter, UniqueFilter
from nearpy.distances import CosineDistance

sys.path.append('..')
from config import *
from tools import *

class ProvGraph(object):
    def __init__(self,dataset):
        self.lock = threading.Lock()
        self.thread_lock = threading.Lock()
        self.G = nx.DiGraph()
        self.TmpG = nx.DiGraph()
        self.w2v = FastText.load('../' + dataset + '/filepath-embedding.model')
        self.c2v = FastText.load('../' + dataset + '/cmdline-embedding.model')
        self.tfidf = json.load(open('../' + dataset + '/tfidf.json'))
        self.taylor_map = dict()
        self.mean_tfidf = np.mean(list(self.tfidf.values()))
        self.AS = AnomalyScore(dataset)
        self.graph_cache = []
        self.node_set = set()
        self.filtered = set()
        self.hit = set()
        if dataset == 'hw17':
            self.attack_process = set(['fe46ff4b0dd67dc0a974430208331227', 'e14d9cbf5da65c007c4d8708f53b9c2f', '83fe3bf44cf67fb94e258c9396fbe188', 'cd100288b92b5e826dc7b79082398b29', 'c00408939cf270d5a3a29550fdba87d5', '5444a68c94bd0a75afb76cfdc07b14d2', 'e5e1285bbb6611731ccf18d2207a4aff', '7c87efd4610605689d6ba3c02ad75c8f', '5c09e49f4f790f73687a231103893d13', '5fcf1988f6ec204bed510491a9cff2fe', '9429bacd8424a21ec9df2a1b448252cc',\
            'f4c37a52e9572e89f86b0811b4fb326f','526f43c80ba193bc3dabc6374baad92a','b9ced8f1e981fe2b19ba4f0c74c8eaaa','eca0112ba004a46862c9d957b9dc2222','b8fa95f2d2d39924b045b41cf5991d3f','e0b19819ffbadb37ba779ebe29085e8b','cfcc3cb29e2e6cfa8ba1f48eeb40a69d','526f43c80ba193bc3dabc6374baad92a','894232a1faedaf12a553156f39aeb524','a897833c84ca38eb9d6c06553db9211f','dc17876a3a9ae7401065fc12c074089b','4dff1d0c21ffed9c41c460d43f855630','f1e2739b8c52073f9266a036aa93bd52','b35b4ffe25682ffd5899e5dffb39cb68','bc97cc66c3f4038cd0e9582f6a66ec69','07165d4a31e8d35df421c9d6c4ae450f','97db754defe078d12cd35d28de61c04a','c5d9be0fe1125565a14587328a25f06b','766c100383651fe8fb408dcaeabca2d0','ad7eb65e45d145446eafde6779d5695f'])
        self.nodes = defaultdict(dict)
        print(len(self.attack_process))
        #
    def graph_add_node_mgr(self, row, key, event_type):
        self.lock.acquire()
        node_attr = {}
        # print(row)
        if key == APTLOG_KEY.FILE:
            s_node = get_md5(row['proc.cmdline'])
            if not (s_node in self.nodes):
                self.nodes[s_node] = {'label': row['proc.cmdline'], 'type': APTLOG_NODE_TYPE.PROCESS, 'score': 0}
            t_node = get_md5(row['fd.name'])
            if not (t_node in self.nodes):
                self.nodes[t_node] = {'label': row['fd.name'], 'type': APTLOG_NODE_TYPE.FILE, 'score': 0}
            self.TmpG.add_node(s_node)
            self.TmpG.add_node(t_node)
            self.TmpG.add_edge(s_node,t_node,e_type = event_type)
        elif key == APTLOG_KEY.PROCESS:
            Parentid = row['proc.pcmdline']
            # print(Parentid)
            s_node = get_md5(Parentid)
            t_node = get_md5(str(row['proc.cmdline']))
            if not (s_node in self.nodes):
                self.nodes[s_node] = {'label': row['proc.pcmdline'],'type': APTLOG_NODE_TYPE.PROCESS, 'score': 0}
            if not (t_node in self.nodes):
                self.nodes[t_node] = {'label': row['proc.cmdline'], 'type': APTLOG_NODE_TYPE.PROCESS, 'score': 0}
            self.TmpG.add_node(s_node)
            self.TmpG.add_node(t_node)
            self.TmpG.add_edge(s_node,t_node,e_type = event_type)

        elif key == APTLOG_KEY.NET:
        # add net type node
            s_node = get_md5(row['proc.cmdline'])
            if not (s_node in self.nodes):
                self.nodes[s_node] = {'label': row['proc.cmdline'], 'type': APTLOG_NODE_TYPE.PROCESS, 'score': 0}
            t_node = get_md5(row['fd.name'])
            if not (t_node in self.nodes):
                self.nodes[t_node] = {'label': row['fd.name'], 'type': APTLOG_NODE_TYPE.NET, 'score': 0}
            self.TmpG.add_node(s_node)
            self.TmpG.add_node(t_node)
            self.TmpG.add_edge(s_node,t_node,e_type = event_type)
        self.lock.release()


    def GetNodeName(self,node):
        return self.nodes[node]['label']

    def GetNodeScore(self,node):
        return self.nodes[node]['score']

    def GetNodeType(self,node):
        return self.nodes[node]['type']

    def GetNodeNewName(self,node):
        try:
            x = self.nodes[node]['newname']
        except:
            x = -1
        return x
    def GetEmbedding(self, corpus, model):
        tmp = [model.wv[i] for i in corpus]
        r = np.mean(tmp,axis=0)
        return r.tolist()
    # def Gettfidf(self,node_attr_vec):
        
    #     cos = cosine_similarity([node_attr_vec],list(self.tfidf.values()))
    #     sim_list = []
    #     for i in cos[0]:
    #         if i > 0.9:
    #             sim_list.append()

    def update(self, anomaly_cutoff, topK = 20):
        self.lock.acquire()
#        self.G = nx.compose(self.G,self.TmpG)
        self.G = self.TmpG.copy()
        self.TmpG.clear()
        self.lock.release()
        # print('1')
        nodes = self.G.nodes()
        pnode = []
        for node in nodes:
            if self.GetNodeType(node) == APTLOG_NODE_TYPE.PROCESS and self.GetNodeName(node) != '':
                pnode.append(node)
        self.node_set |= set(pnode)
        update_node_list = self.caculate_anomaly_score(pnode,anomaly_cutoff)


        if update_node_list == -1:
            self.thread_lock.release()
            return
        relabel_dic = {}
        for node in self.G.nodes():
            origion = node
            while node in self.taylor_map:
                node = self.taylor_map[node]
            if origion != node:
                self.taylor_map[origion] = node
                relabel_dic[origion] = node
        print(len(relabel_dic))
        self.G = nx.relabel_nodes(self.G, relabel_dic,copy=False)
        update_node_list = list(update_node_list)
        for i,node in enumerate(update_node_list):
            if node in relabel_dic:
                update_node_list[i] = relabel_dic[node]
        update_node_list = set(update_node_list)

        # remove_edge_list = []

        # for e in self.G.edges:
        #     e_type = self.G.edges[e]['type']
        #     if ETYPE[e_type] in IGNTYPE:
        #         remove_edge_list.append(e)

        # self.G.remove_edges_from(remove_edge_list)

        # remove_node_list = []
        # cron_list = []
        # for node in self.G.nodes:
        #     attr = self.GetNodeName(node)
        #     if attr == "":
        #         remove_node_list.append(node)
            # if attr == "cron" or attr == "bash" or attr == "sh" or attr == "sshd":
            # if attr == "cron":
            #     cron_list.append(node)
        
        self.G = nx.DiGraph(self.G)
        # cron_process = set()
        # reserved_process = dict()
        # for cron in cron_list:
        #     for i in self.G.successors(cron):
        #         # print(i,self.GetNodeAttr(i))
        #         if self.GetNodeAttr(i) in reserved_process:
        #             if self.GetNodeScore(i) > reserved_process[self.GetNodeAttr(i)]['score']:
        #                 # cron_process.add(reserved_process[self.GetNodeAttr(i)]['id'])
        #                 self.nodes[reserved_process[self.GetNodeAttr(i)]['id']]['flag'] = False
        #                 reserved_process[self.GetNodeAttr(i)]['id'] = i
        #                 reserved_process[self.GetNodeAttr(i)]['score'] = self.GetNodeScore(i)
        #             else:
        #                 self.nodes[reserved_process[self.GetNodeAttr(i)]['id']]['flag'] = False
        #         else:
        #             reserved_process.update({self.GetNodeAttr(i):{'id':i,'score':self.GetNodeScore(i)}})

        # print(len(cron_list))
        # print(len(cron_process))
        # remove_list = cron_process | set(remove_node_list) ｜ cron_list
        # self.G.remove_nodes_from(remove_node_list)

        # #To handle firefox, find pattern
        # for node in self.G.nodes:
        #     predecessors = [self.GetNodeAttr(i) for i in self.G.predecessors(node)]
        #     if len(predecessors) != 0:
        #         d1 = dict(Counter(predecessors))
        #         for p in self.G.predecessors(node):
        #             self.nodes[p]['score'] /= d1[self.GetNodeAttr(p)]
        #     successors = [self.GetNodeAttr(i) for i in self.G.successors(node)]
        #     if len(successors) != 0:
        #         d2 = dict(Counter(successors))
        #         for p in self.G.successors(node):
        #             self.nodes[p]['score'] /= d2[self.GetNodeAttr(p)]


        # update_node_list = update_node_list - remove_list


        print('update_list ', len(update_node_list))
        
        self.filtered |= set(update_node_list)

        # node_centrality = nx.eigenvector_centrality(self.G,max_iter=200,tol = 1e-2)

        connected_graph_list = self.propagation(update_node_list)
        # for i in connected_graph_list:
        #     print(i.graph['score'],i.nodes())
        print('propagation finished')
        self.update_cache(connected_graph_list,topK)
        print('update finished')
        self.thread_lock.release()
    

    def merge_nodes(self,g,nodes, new_node,remove_nodes_list): 
        edge = list(g.edges(nodes,data=True))
        edge.extend(list(g.in_edges(nodes,data=True)))
        for n1,n2,data in edge:
        # For all edges related to one of the nodes to merge,
        # make an edge going to or coming from the `new gene`.
            # print(data)
            if n1 == new_node or n2 == new_node or n1 in remove_nodes_list or n2 in remove_nodes_list:
                continue
            if n1 in nodes:
                g.add_edge(new_node,n2,e_type = data['e_type'])
            elif n2 in nodes:
                g.add_edge(n1,new_node,e_type = data['e_type'])
    
        self.nodes[new_node]['score'] = max(max([self.GetNodeScore(i) for i in nodes]),self.nodes[new_node]['score'])
        for i in nodes:
            self.taylor_map[i] = new_node
        return g

    def if_file_node_merge(self,s,dic):
        keys = list(dic.keys())
        threshold = max(s.count('/') - 1, 1)
        for n in keys:
            t = os.path.commonprefix([s,n])
            if t.count('/') >= threshold or t.count('/') >= 3:
                return n
        # r = s.rfind('/')
        # if r == -1:
        #     return -1
        # else:
        #     subs = s[:r]
        # for n in keys:
        #     if subs in n:
        #         return n

        return -1
    def graph_taylor(self,g):
        cnt = 0
        remove_nodes_list = set()
        for node in g.nodes:
            if g.degree(node) < 5 or node in remove_nodes_list:
                continue
            merge_node = defaultdict(list)
            rbp = RandomBinaryProjections('rbp', 10)
            engine = Engine(256, lshashes=[rbp])            

            for i in g.successors(node):
                if i in remove_nodes_list:
                    continue
                name = self.GetNodeNewName(i)
                if name == -1:
                    continue
                v = np.array([])
                if self.GetNodeType(i) == APTLOG_NODE_TYPE.PROCESS:
                    v = self.GetEmbedding(name.split('/'), self.c2v)
                else:
                    v = self.GetEmbedding(name.split('/'), self.w2v)
                candidate = engine.neighbours(np.array(v))
                if len(candidate) != 0 and candidate[0][2] < 0.01:
                    c = candidate[0][1]
                else:
                    c = name
                    engine.store_vector(np.array(v), name)
                merge_node[c].append(i)
            for i in merge_node:
                if len(merge_node[i]) >= 5:
                    g = self.merge_nodes(g,merge_node[i][1:],merge_node[i][0],remove_nodes_list)
                    remove_nodes_list |= set(merge_node[i][1:])
            rbp = RandomBinaryProjections('rbp', 10)
            engine = Engine(256, lshashes=[rbp])                    
            merge_node = defaultdict(list)
            for i in g.predecessors(node):
                if i in remove_nodes_list:
                    continue
                name = self.GetNodeNewName(i)
                if name == -1:
                    continue                              
                v = np.array([])
                if self.GetNodeType(i) == APTLOG_NODE_TYPE.PROCESS:
                    v = self.GetEmbedding(name.split('/'), self.c2v)
                else:
                    v = self.GetEmbedding(name.split('/'), self.w2v)
                candidate = engine.neighbours(np.array(v))
                if len(candidate) != 0 and candidate[0][2] < 0.01:
                    c = candidate[0][1]
                else:
                    c = name
                    engine.store_vector(np.array(v), name)

                merge_node[c].append(i)                

                for i in merge_node:
                    if len(merge_node[i]) >= 5:
                        g = self.merge_nodes(g,merge_node[i][1:],merge_node[i][0],remove_nodes_list)
                        remove_nodes_list |= set(merge_node[i][1:])

        if len(remove_nodes_list) != 0:
            g.remove_nodes_from(remove_nodes_list)
        return g

    def final_graph_taylor(self,g):
        flag = True
        cnt = 0
        while flag:
            remove_nodes_list = set()
            flag = False
            for node in g.nodes:
                if g.degree(node) < 2 or node in remove_nodes_list:
                    continue
                rbp = RandomBinaryProjections('rbp', 10)
                engine = Engine(256, lshashes=[rbp])   
                merge_node = defaultdict(list)
                for i in g.successors(node):
                    if i in remove_nodes_list:
                        continue
                    # print(i,self.GetNodeAttr(i))
                    name = self.GetNodeNewName(i)
                    if name == -1:
                        continue
                    # if name in merge_node:
                    #     merge_node[name].append(i)
                    #     continue
                    # r = self.if_file_node_merge(name,merge_node)
                    # if r == -1:
                    #     merge_node[name].append(i)
                    # else:
                    #     merge_node[r].append(i)
                    v = np.array([])
                    if self.GetNodeType(i) == APTLOG_NODE_TYPE.PROCESS:
                        v = self.GetEmbedding(name.split('/'), self.c2v)
                    else:
                        v = self.GetEmbedding(name.split('/'), self.w2v)
                    candidate = engine.neighbours(np.array(v))
                    # print(candidate,v)
                    if len(candidate) != 0 and candidate[0][2] < 0.01:
                        c = candidate[0][1]
                    else:
                        c = name
                        engine.store_vector(np.array(v), name)
                # if name in merge_node:
                #     merge_node[name].append(i)
                #     continue
                    merge_node[c].append(i)     
                for i in merge_node:
                    if len(merge_node[i]) >= 2:
                        g = self.merge_nodes(g,merge_node[i][1:],merge_node[i][0],remove_nodes_list)
                        remove_nodes_list |= set(merge_node[i][1:])
                rbp = RandomBinaryProjections('rbp', 10)
                engine = Engine(256, lshashes=[rbp])   
                merge_node = defaultdict(list)
                for i in g.predecessors(node):
                    if i in remove_nodes_list:
                        continue
                    name = self.GetNodeNewName(i)
                    if name == -1:
                        continue
                    v = np.array([])
                    if self.GetNodeType(i) == APTLOG_NODE_TYPE.PROCESS:
                        v = self.GetEmbedding(name.split('/'), self.c2v)
                    else:
                        v = self.GetEmbedding(name.split('/'), self.w2v)
                    candidate = engine.neighbours(np.array(v))
                    # print(candidate,v)
                    if len(candidate) != 0 and candidate[0][2] < 0.01:
                        c = candidate[0][1]
                    else:
                        c = name
                        engine.store_vector(np.array(v), name)
                # if name in merge_node:
                #     merge_node[name].append(i)
                #     continue
                    merge_node[c].append(i)
                for i in merge_node:
                    if len(merge_node[i]) >= 2:
                        g = self.merge_nodes(g,merge_node[i][1:],merge_node[i][0],remove_nodes_list)
                        remove_nodes_list |= set(merge_node[i][1:])
            if len(remove_nodes_list) != 0:
                flag = True
                g.remove_nodes_from(remove_nodes_list)
            # self.nodes.pop(n)
            # for k in g.nodes():
            #     g.nodes[k]['label'] = self.GetNodeAttr(k) + ' ' + str(self.GetNodeState(k) == False)
            # nx.drawing.nx_pydot.write_dot(g, str(cnt) + 'p.dot')
            # cnt += 1
        return g
    def caculate_anomaly_score(self,pnode,anomaly_cutoff):
        need_to_caculate = defaultdict(list)
        # nodes = self.G.nodes()
        # have better way to find neighbor?
        undirected_G = self.G.to_undirected(as_view=True)
        print(len(pnode))
        for node in pnode:
            neibor = list(undirected_G[node])
            # print(node)
            if len(neibor) == 0:
                continue
            # tmp_dict = set()
            for nei in neibor:

                if self.GetNodeName(nei) is not None and self.GetNodeName(nei) != 'unknown' and self.GetNodeType(nei) != APTLOG_NODE_TYPE.PROCESS:
                    need_to_caculate[node].append((nei,self.GetNodeName(nei)))
                        # tmp_dict.add(self.GetNodeAttr(nei))
                # except Exception as e:
                #     print(nei,self.GetNodeAttr(nei))
        print('need_to_caculate',len(need_to_caculate))

        if len(need_to_caculate) == 0:
            return -1
        node_feature = defaultdict(list)
        
        for node in need_to_caculate.keys():
            flag = False
            cmdline = self.GetNodeName(node)
            split_path = sanitize_string(cmdline)
            if len(split_path) == 0:
                continue
            new_name = '/'.join(split_path)
            self.nodes[node]['newname'] = new_name
            tmp = []
            for l,i in enumerate(split_path):
                tmp += [self.c2v.wv[i]]
            r = np.mean(tmp,axis=0) * self.mean_tfidf

            node_feature[node] += [r.tolist()]
            tmp_dict = set()
            process_objects = set(need_to_caculate[node])
            for id,object_name in process_objects:
                split_path = sanitize_string(object_name)
                if len(split_path) == 0:
                    continue
                flag = True
                new_name = '/'.join(split_path)
                self.nodes[id]['newname'] = new_name

                tmp = []
                for l,i in enumerate(split_path):
                    tmp += [self.w2v.wv[i]]
                r = np.mean(tmp,axis=0)
                try:
                    t = self.tfidf[new_name.lower()]
                except:
                    t = self.mean_tfidf
                r = r * t
                node_feature[node] += [r.tolist()]
            if flag:
                node_feature[node] = np.mean(node_feature[node],axis=0).tolist()

            else:
                node_feature.pop(node)
        anomaly_score = self.AS.VAEInfer(node_feature,self.nodes)


        update_node_list = set()
        VAE_list = set()
        print(anomaly_cutoff)
        for node in anomaly_score:
            if anomaly_score[node] >= anomaly_cutoff:
                VAE_list.add(node)
        print('VAE: ',len(VAE_list))

        update_node_list = VAE_list
        for node in update_node_list:
            self.nodes[node]['score'] = max(anomaly_score[node],self.nodes[node]['score'])
        if len(update_node_list) == 0:
            return -1
        return update_node_list

    def GetbackSubgraph(self, node, depth,sense):
        subgraph = set()
        if depth == 0:
            return subgraph

        score = {}
        attr_list = {}
        for i in self.G.predecessors(node):
            score[i] = (self.GetNodeScore(i),self.G.out_degree(i)/ (self.G.in_degree(i) + 1))
        
        new_score = sorted(score.items(), key=lambda d: (d[1][0],d[1][1]), reverse=True)[:10]
        node_list = [i[0] for i in new_score]
        for i in node_list:
            if i in sense:
                continue
            sense.add(i)
            subgraph.add(i)
            x = self.GetbackSubgraph(i,depth - 1,sense)
            subgraph |= x

        return subgraph
        
    def GetforeSubgraph(self, node, depth,sense):
        subgraph = set()
        if depth == 0:
            return subgraph
        # score = {}
        # for i in self.G.successors(node):
        #     score[i] = self.G.out_degree(i)/self.G.in_degree(i)
        
        # score = sorted(score.items(), key=lambda d: d[1], reverse=True)[:5]
        # node_list = [i[0] for i in score]
        # score = {}
        # attr_list = {}
        # for i in self.G.successors(node):
        #     name = self.GetNodeAttr(i)
        #     if name in attr_list:
        #         s1 = self.G.out_degree(i)/(self.G.in_degree(i) + 1) + self.GetNodeScore(i)/10
        #         if s1 > score[attr_list[name]]:
        #             attr_list[name] = i
        #             score[i] = s1
        #     else:
        #         attr_list[name] = i
        #         score[i] = self.G.out_degree(i)/(self.G.in_degree(i) + 1) + self.GetNodeScore(i)/10
        # new_score = {k:score[k] for k in list(attr_list.values())}
        
        # new_score = sorted(new_score.items(), key=lambda d: d[1], reverse=True)[:5]
        # node_list = [i[0] for i in new_score]

        score = {}
        attr_list = {}
        for i in self.G.successors(node):
            score[i] = (self.GetNodeScore(i),self.G.out_degree(i)/ (self.G.in_degree(i) + 1))
        
        new_score = sorted(score.items(), key=lambda d: (d[1][0],d[1][1]), reverse=True)[:10]
        node_list = [i[0] for i in new_score]

        for i in node_list:
            if i in sense:
                continue
            sense.add(i)
            subgraph.add(i)
            x = self.GetforeSubgraph(i,depth - 1,sense)
            subgraph |= x

        return subgraph
        
    def propagation(self,update_node_list, f_depth = 5, b_depth = 5, alg = 'sum'):
        if alg == 'sum':
            subgraph_node = set(update_node_list)
            for node in update_node_list:
                sense = {node}
                local_subgraph = self.GetbackSubgraph(node,b_depth,sense)
                subgraph_node |= local_subgraph
                sense = {node}
                local_subgraph = self.GetforeSubgraph(node,f_depth,sense)
                subgraph_node |= local_subgraph
            subgraph = self.G.subgraph(list(subgraph_node)).copy()
            # subgraph = self.graph_taylor(subgraph)
            # for node in subgraph.nodes():
            #     if subgraph.in_degree(node) == 0 and self.GetNodeType(node) :
            #         remove_node.add(node)
            connected_graph = []
            for n in nx.weakly_connected_components(subgraph):
                g = subgraph.subgraph(n).copy()
                # assert(nx.is_weakly_connected(g))
                g.graph['score'] = np.sum([self.GetNodeScore(i) for i in g.nodes()])
                connected_graph.append(g)
            
            return connected_graph

    def GetSubset(self,mmap,x,y):
        mmap[x][y] = 0
        row = mmap[x]
        col = mmap[:,y]
        result = []
        if np.all(row==0) and np.all(col==0):
            return result
        for i,v in enumerate(row):
            if v == 1 :
                result.append(i + mmap.shape[0])
                result += self.GetSubset(mmap,x,i)
        for i,v in enumerate(col):
            if v == 1:
                result.append(i)
                result += self.GetSubset(mmap,i,y)

        return result
    
    def MergeGraph(self,graph_cache,graph_list):
        connection_map = np.zeros((len(graph_cache), len(graph_list)), dtype=int)
        for i,g1 in enumerate(graph_cache):
            g1 = g1.graph
            for k,g2 in enumerate(graph_list):
                node_l1 = set(g1.nodes())
                node_l2 = set(g2.nodes())
                common_node = node_l1 & node_l2
                if len(common_node) > 0:
                    connection_map[i][k] = 1

        merged_graph_list = []
        for x in range(connection_map.shape[0]):
            row = connection_map[x]
            if np.all(row == 0):
                merged_graph_list.append(graph_cache[x])
                graph_cache[x].timestamp += 1

        for y in range(connection_map.shape[1]):
            col = connection_map[:,y]
            if np.all(col == 0):
                # g = self.graph_taylor(graph_list[y])
                # g.graph['score'] = np.sum([self.GetNodeScore(node) for node in g.nodes])
                cache_graph = CacheGraph(graph_list[y])
                merged_graph_list.append(cache_graph)
         
        Merged_graph = []
        while not np.all(connection_map == 0):
            start_x, start_y = 0, 0
            find = False
            for i in range(connection_map.shape[0]):
                for j in range(connection_map.shape[1]):
                    if connection_map[i][j] == 1:
                        start_x = i
                        start_y = j
                        find = True
                        break
                if find:
                    break
            
            r = self.GetSubset(connection_map,start_x,start_y)
            r.append(start_x)
            r.append(start_y + connection_map.shape[0])
            Merged_graph.append(r)

        for l in Merged_graph:
            tmp_graph_list = []
            for idx in l:
                if idx >= connection_map.shape[0]:
                    tmp_graph_list.append(graph_list[idx - connection_map.shape[0]])
                else:
                    tmp_graph_list.append(graph_cache[idx].graph)
            G = nx.compose_all(tmp_graph_list)

            G = self.graph_taylor(G)

            # assert(nx.is_weakly_connected(G))
            G.graph['score'] = np.sum([self.nodes[node]['score'] for node in G.nodes])
            merged_graph_list.append(CacheGraph(G))
        
        return merged_graph_list    
        
            
    def update_cache(self,graph_list,topK):
        merged_graph_list = self.MergeGraph(self.graph_cache,graph_list)
        merged_graph_list = [g for g in merged_graph_list if g.GetGraphScore() > 0 and g.graph.number_of_nodes() > 10]
        score = [x.GetGraphScore() for x in merged_graph_list]
        if len(score) == 0:
            return 
        print(score)
        # if len(score) < 3:
        #     self.graph_cache = merged_graph_list[:topK]
        #     return 
        # cov = EllipticEnvelope(random_state=0).fit_predict(score)
        # clf = OneClassSVM(kernel="rbf",gamma='auto').fit(score)
        # cov = clf.predict(score)
        # for g in merged_graph_list:
        #     print(g.GetGraphScore())
        cov = grubbs.max_test_indices(score, alpha=0.01)
        # clf = OneClassSVM(kernel="rbf",gamma='auto').fit(score)
        # cov = clf.predict(score)
        # for g in merged_graph_list:
        #     print(g.GetGraphScore())
        for i in cov:
            g = merged_graph_list[i].graph
            # for k in g.nodes():
            #     g.nodes[k]['label'] = self.GetNodeName(k) + ' ' + str(self.GetNodeScore(k))
            # nx.drawing.nx_pydot.write_dot(g, str(i) + '.dot')
            print('[Alert]: ', score[i], len(g.nodes()),self.attack_node(g.nodes()))
            # node_l = {i:self.GetNodeScore(i) for i in g.nodes()}
            # sorted_l = sorted(node_l.items(), key=lambda d: d[1], reverse=True)
        merged_graph_list.sort(key = lambda x: x.GetGraphScore(),reverse = True)
        
        
        self.graph_cache = merged_graph_list[:topK]
        
    def attack_node(self,node_list):
        result = []
        for node in node_list:
            if node in self.attack_process:
                result.append(node)
        return result