import numpy as np
from numpy import tile
import pickle as pkl
import networkx as nx
import scipy.sparse as sp
from scipy.sparse.construct import random
from scipy.sparse.linalg.eigen.arpack import eigsh
import sys
import torch
import torch.nn as nn
from torch.autograd import Variable
from datetime import timedelta
import math
from tqdm import tqdm
from collections import Counter, defaultdict
import re
from gensim.models import FastText
import matplotlib.pyplot as plt
import json
import random
from sklearn.metrics.pairwise import cosine_similarity
import time
from multiprocessing.pool import Pool
import itertools
import string
import seaborn as sns
from tools import sanitize_string
from argparse import ArgumentParser
from gensim import corpora, models, similarities
from sklearn.cluster import *
from sklearn.metrics.pairwise import *


def extract_process_feature(file_path,w2v):
    process_map = {}
    f = open(file_path,'r')
    print('start graph')
    process_vec = defaultdict(list)
    id = 0
    isprocess_file = True
    file_freq = defaultdict(set)
    file_vec = []
    fileid2name = []
    
    while True:
        line = f.readline()
        if line == '\n':
            id += 1
        if not line:
            break
        filepath = line.strip().lower()
        if filepath.endswith('$$$true') or filepath.endswith('$$$false'):
            continue
        split_path = sanitize_string(filepath)

        newname = '/'.join(split_path)
        # print(newname)
        if len(split_path) == 0:
            continue
        if not (newname in fileid2name):
            tmp = []
            for l,i in enumerate(split_path):
                tmp += [w2v.wv[i]]
            r = np.mean(tmp,axis=0).tolist()
            file_vec.append(r)
            fileid2name.append(newname)

        file_freq[newname].add(id)

    return file_vec, fileid2name, file_freq, id

# def extract_process(file_path):
#     f = open(file_path)
#     process_vec = defaultdict(list)
#     isprocess_file = True
#     tmp_process_text = []
#     while True:
#         line = f.readline()
#         if line == '\n':
#             process_vec[newfilepath].append(tmp_process_text)
#             tmp_process_text = []
#             isprocess_file = True
#             continue
#         if not line:
#             break

#         filepath = line.strip().lower().replace('$$$false','')
#         if isprocess_file:
#             split_path = sanitize_string(filepath)
#             if len(split_path) == 0:
#                 newfilepath = 'None'
#             else:
#                 newfilepath = '/'.join(split_path)
#             isprocess_file = False
#         else:
#             split_path = sanitize_string(filepath)
#             if len(split_path) == 0:
#                 continue
#             tmp_process_text.extend(split_path)

#     print('finished graph')
#     return process_vec

def extract_process_vec(file_path,tfidf, w2v, c2v):
    process_map = {}
    f = open(file_path,'r')
    print('start graph')
    process_vec = defaultdict(list)
    id = 0
    mean_s = np.mean(list(tfidf.values()))
    max_s = np.max(list(tfidf.values()))
    isprocess_file = True
    tmp_process_vec = []
    ground_truth = {}
    new_cmd = ''
    while True:
        line = f.readline()
        if line == '\n':
            process_vec[pname].append(np.mean(tmp_process_vec,axis=0).tolist())
            id += 1
            tmp_process_vec = []
            isprocess_file = True
            continue
        if not line:
            break

        filepath = line.strip().lower()
        if filepath.endswith('$$$true'):
            filepath = filepath.replace('$$$true','')
            ground_truth[id] = filepath
        else:
            filepath = filepath.replace('$$$false','')
        
        if '$$$' in filepath:
            filepath, pname = filepath.split('$$$')[0], filepath.split('$$$')[1]
            # print(filepath, pname)

        split_path = sanitize_string(filepath)
        if len(split_path) == 0:
            continue
        if isprocess_file:
            # print(id)
            # print(filepath)
            # print(split_path)
            new_cmd = '/'.join(split_path)
            process_map[id] = new_cmd
            isprocess_file = False
            tmp = []
            for l,i in enumerate(split_path):
                tmp += [c2v.wv[i]]
            r = np.mean(tmp,axis=0)
            # if not (process_map[id] in stability):
            r = r * mean_s
            
        else:
            tmp = []
            for l,i in enumerate(split_path):
                tmp += [w2v.wv[i]]
            r = np.mean(tmp,axis=0)
            newname = '/'.join(split_path)
            if newname in tfidf:
                s = tfidf[newname]
            else:
                s = mean_s
            r = r * s

        tmp_process_vec.append(r.tolist())
    return process_vec, process_map, ground_truth


if __name__ == "__main__":
    parser = ArgumentParser()
    # parser.add_argument("--dataset",type=str,default='E3-cadets')
    parser.add_argument("--d",type = str, default='win10')
    args = parser.parse_args()
    dataset = args.d

    inputfile = dataset + '/process-event-benign.txt'

    w2v_dic = dataset + '/filepath-embedding.model'
    w2v = FastText.load(w2v_dic)
    c2v_dic = dataset + '/cmdline-embedding.model'
    c2v = FastText.load(c2v_dic)

    file_vec, fileid2name, file_freq, process_num = extract_process_feature(inputfile,w2v)
    threshold = 0.9
    cos = cosine_similarity(np.array(file_vec))

    tfidf_dic = {}
    for i in range(cos.shape[0]):
        index = np.where(cos[i] > threshold)[0]
        process_set = set()
        for j in index:
            process_set |= file_freq[fileid2name[j]]
        process_set |= file_freq[fileid2name[i]]

        tfidf_dic[fileid2name[i]] = math.log(process_num / len(process_set),2)

    json.dump(tfidf_dic, open(dataset + '/tfidf.json','w'))
    

    process_vec, process_map,ground_truth = extract_process_vec(inputfile,tfidf_dic,w2v,c2v)
    
    # stability = {}
    # keys = list(process_vec.keys())
    # for key in keys:
    #     if len(process_vec[key]) == 0:
    #         process_vec.pop(key)
    # process_vec.pop('None')
    # if '' in process_vec:
    #     process_vec.pop('')

    stability = {}
    for process in tqdm(process_vec.keys()):
    # if process == '/usr/bin/firefox':
    #     stability[process] = 20
    #     continue
        print(process,len(process_vec[process]))
        refer_words = process_vec[process]
        if len(np.array(refer_words).flatten()) == 0:
            continue
        if len(refer_words) > 20000:
            idx = np.random.choice(range(len(refer_words)),20000)
            refer_words = np.array(refer_words)[idx]
    # print(len(refer_words))
    #     dictionary = corpora.Dictionary(refer_words)
    #     doc_vectors = [dictionary.doc2bow(word) for word in refer_words]
    # # print(len(doc_vectors))
    #     tf_idf = models.TfidfModel(doc_vectors)
    #     tf_idf_vectors = tf_idf[doc_vectors]
    # # print(len(tf_idf_vectors))
    #     index = similarities.MatrixSimilarity(tf_idf_vectors, num_features=len(dictionary))

    # # print(refer_words[156])
    # # print(np.where(sim != 0))
    # # break
    #     cnt = 0
    #     have_compare = set()
    #     for i in range(len(doc_vectors)):
    #     # print(refer_words[i])
    #         if i in have_compare:
    #             continue
    #         sim = index[tf_idf[doc_vectors[i]]]
    #     # print(refer_words[i])
    #         x = set(np.where(sim > 0.8)[0])
    #         have_compare |= x
    #         cnt += 1
    #     print(cnt)
    #     stability[process] = cnt
        # sim = cosine_similarity(refer_words)
        # print(len(set(np.where(sim[0] > 0.9)[0])))
        clustering = DBSCAN(eps=0.05,metric='cosine',min_samples=5).fit(refer_words)

        # print(clustering.labels_)
        s = len(set(clustering.labels_.tolist()))
        stability[process] = s
        print(s)


    f = open(dataset +'/stability-embedding.json','w')
    print(sorted(stability.items(),key = lambda d:d[1], reverse = True))

    json.dump(stability,f)

    f.close()
    