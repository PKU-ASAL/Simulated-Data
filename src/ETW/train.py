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
from model import VariationalAutoencoder
from Loader import Train_Loader
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
from tools import *
from argparse import ArgumentParser
import smirnov_grubbs as grubbs


def extract_process_feature(file_path,tfidf, stability, w2v, c2v):
    process_map = {}
    f = open(file_path,'r')
    print('start graph')
    process_vec = defaultdict(list)
    id = 0
    mean_s = np.mean(list(tfidf.values()))
    max_s = np.max(list(tfidf.values()))
    isprocess_file = True
    tmp_process_vec = []
    cmdline_vec = []
    ground_truth = {}
    while True:
        line = f.readline()
        if line == '\n':
            process_vec[id] = np.mean(tmp_process_vec,axis=0).tolist()

            # if isinstance(x,float):
            #     process_vec[id] = np.mean([cmdline_vec],axis=0).tolist()
            # else:
            #     process_vec[id] = np.mean([x, cmdline_vec],axis=0).tolist()
            id += 1
            tmp_process_vec = []
            cmdline_vec = []
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


        split_path = sanitize_string(filepath)
        if len(split_path) == 0:
            continue
        if isprocess_file:
            process_map[id] = pname
            isprocess_file = False
            tmp = []
            for l,i in enumerate(split_path):
                tmp += [c2v.wv[i]]
            r = np.mean(tmp,axis=0)
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
    parser.add_argument("--epoch",type = int,default=50)
    parser.add_argument("--e",type = int, default=256)
    parser.add_argument("--d",type = str, default='hw20')
    args = parser.parse_args()
    epochs = args.epoch
    dataset = args.d
    w2v_dic = dataset + '/filepath-embedding.model'
    w2v = FastText.load(w2v_dic)
    c2v_dic = dataset + '/cmdline-embedding.model'
    c2v = FastText.load(c2v_dic)
    benign_data_file = dataset + '/process-event-benign.txt'
    tfidf_file = dataset + '/tfidf.json'
    tfidf_dic = json.load(open(tfidf_file))
    stability_file = dataset + '/stability-embedding.json'
    stability = json.load(open(stability_file))


    process_vec,process_map, x = extract_process_feature(benign_data_file, tfidf_dic, stability, w2v,c2v)

    print('len process vec: ', len(process_vec))
    print('len process map: ', len(process_map))


    #### split the benign data into train data and valid data
    data_len = len(list(process_vec.keys()))
    print(data_len)
    train_data = defaultdict(list)
    train_data2 = defaultdict(list)
    per = data_len
    cnt = 0
    keys = list(process_vec.keys())
    random.shuffle(keys)

    train_data = process_vec
        
    print('train:',len(list(train_data.keys())))
    out_embedd1 = 'process_embedding_train.json'
    out1 = open(out_embedd1,'w')
    json.dump(train_data, out1)
    out1.close()
    train_data.clear()
    # out2 = open('process_embedding_valid.json', 'w' )
    # json.dump(train_data2,out2)
    # out2.close()
    # print('valid:',len(list(train_data2.keys())))
    # train_data2.clear()

    ####################
    #VAE Train
    ####################

    print('start to train VAE')

    batch_size = 128
    lr = 0.001         # learning rate
    w_d = 1e-5        # weight decay
    momentum = 0.9

    train_file = 'process_embedding_train.json'
    train_set = Train_Loader(train_file)

    train_ = torch.utils.data.DataLoader(
            train_set,
            batch_size=batch_size,
            shuffle=True,
            pin_memory=False,
            # drop_last=True
        )

    metrics = defaultdict(list)
    device = 'cuda' if torch.cuda.is_available() else 'cpu'
    model = VariationalAutoencoder(32)
    model.to(device)
    criterion = nn.MSELoss(reduction='sum')
    optimizer = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=w_d)
    model.train()
    min_epoch_loss = 100
    start = time.time()
    for epoch in range(epochs):
        ep_start = time.time()
        running_loss = 0.0
        for bx, (data) in enumerate(train_):
            data = data.to(device)
            sample = model(data)
            loss = criterion(data.to(device), sample) + model.encoder.kl
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            running_loss += loss.item()
        epoch_loss = running_loss/len(train_set)
        metrics['train_loss'].append(epoch_loss)
        ep_end = time.time()
        print('-----------------------------------------------')
        print('[EPOCH] {}/{}\n[LOSS] {}'.format(epoch+1,epochs,epoch_loss))
        print('Epoch Complete in {}'.format(timedelta(seconds=ep_end-ep_start)))
        if epoch_loss < min_epoch_loss:
            torch.save(model,dataset + '/AE.model')
            min_epoch_loss = epoch_loss

    end = time.time()
    print('-----------------------------------------------')
    print('[System Complete: {}]'.format(timedelta(seconds=end-start)))


    model = torch.load(dataset + '/AE.model')



    # id2process = json.load(open('../real-time/pretrained-model/' + dataset+'/id2process.json'))
    # anom_weight = json.load(open('../real-time/pretrained-model/' + dataset+'/stability.json'))


##### get the threshold #####
    
    valid_data = json.load(open('process_embedding_train.json'))

    label = []
    process_name = []
    loss_dist = []

    model.eval()
    for i in valid_data:
        try:
            name = process_map[i]
        except:
            name = 'None' 
        data = torch.FloatTensor(valid_data[i])
        sample = model(data.to(device))
        loss = criterion(data.to(device),sample).item()
        if name in stability:
            loss = loss / (math.log(stability[name]) + 1)
        loss_dist.append(loss)



    anomaly_std = np.std(np.array(loss_dist))
    anomaly_mean = np.mean(np.array(loss_dist))
    # cov = grubbs.max_test_outliers(loss_dist, alpha=0.05)

    anomaly_cutoff = np.percentile(np.array(loss_dist),90)



    
    print(np.percentile(np.array(loss_dist),50))
    print(np.percentile(np.array(loss_dist),60))
    print(np.percentile(np.array(loss_dist),70))
    print(np.percentile(np.array(loss_dist),80))
    print(np.percentile(np.array(loss_dist),90))

    print(anomaly_mean,anomaly_std)
    print('anomaly threshold: ',anomaly_cutoff)

    test_data = defaultdict(list)
    anomaly_data_file = dataset + '/process-event-anomaly.txt'
    anom_vec, process_map, attack_process = extract_process_feature(anomaly_data_file,tfidf_dic,stability,w2v,c2v)
    for i in attack_process:
        print(i,attack_process[i])
    # print(anom_vec[285])
    loss_dist = []
    label = []
    process_name = []
    for i in anom_vec:
        try:
            data = torch.FloatTensor(anom_vec[i])
            label += [int(i)]
            try:
                name = process_map[i]
            except:
                name = 'None' 
            sample = model(data.to(device))
            loss = criterion(data.to(device), sample).item()
            if name in stability:
                loss = loss / (math.log(stability[name]) + 1)
            loss_dist.append(loss)
        except:
            continue

############# 
    # attack_process = [] #need to fill the id according to the ground truth
#############
    print('all the process: ', len(label))
    anom_score = []
    for i,v in enumerate(loss_dist):
        if label[i] in attack_process:
            anom_score.append(v)
            print(label[i],v)
    plt.figure(figsize=(12,8))
    X = loss_dist
    sns.set(font_scale = 2)
    ax = sns.kdeplot(X)
    ax.set_xlabel('Anomaly Score')
    SX = ax.lines[0].get_xdata()
    SY = ax.lines[0].get_ydata()

    idx = []
    for i in anom_score:
        t = np.searchsorted(SX,i)
        idx.append(t)

    idx = np.array(idx)
    scatter_x = SX[idx]
    scatter_y = SY[idx]
    
    plt.scatter(scatter_x,scatter_y,s=32,c='r')

    plt.savefig(dataset + '/loss distribution.png')


    anom_list = []

    for i,v in enumerate(loss_dist):
        if v > anomaly_cutoff:
            anom_list += [label[i]]
    cnt = 0
    detected_ano = set()
    print(len(anom_list))

    for i in anom_list:
        if i in attack_process:
            detected_ano.add(i)
            cnt += 1

    recall = cnt/len(list(set(attack_process)))
    precision = cnt/len(anom_list)
    print('recall: ', recall)
    print('precision: ', precision)
    print('ground truth:', len(attack_process))
    print('detected process:', len(anom_list))
    print(set(attack_process) - detected_ano)
