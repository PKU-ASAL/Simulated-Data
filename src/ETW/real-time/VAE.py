import torch.nn.functional as F
from numpy.core.fromnumeric import _ravel_dispatcher
import torch
import torch.nn as nn
from torch.autograd import Variable
import time
import random
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from collections import defaultdict
from datetime import timedelta
from sklearn import manifold, datasets
import json
import math

class VariationalEncoder(nn.Module):
    def __init__(self,latent_dims):
        super(VariationalEncoder,self).__init__()
        self.linear1 = nn.Linear(256,128)
        self.linear2 = nn.Linear(128,64)
        self.linear3 = nn.Linear(64,latent_dims)
        self.linear4 = nn.Linear(64,latent_dims)

        self.N = torch.distributions.Normal(0,1)
        #self.N.loc = self.N.loc.cuda()
        #self.N.scale = self.N.scale.cuda()
        self.kl = 0

    def forward(self,x):
        x = F.relu(self.linear1(x))
        x = F.relu(self.linear2(x))
        mu = self.linear3(x)
        sigma = torch.exp(self.linear4(x))
        z = mu + sigma*self.N.sample(mu.shape)
        self.kl = (sigma**2 + mu**2 - torch.log(sigma) - 1/2).sum()
        return z
class Decoder(nn.Module):
    def __init__(self,latent_dims):
        super(Decoder,self).__init__()
        self.linear1 = nn.Linear(latent_dims,64)
        self.linear2 = nn.Linear(64,128)
        self.linear3 = nn.Linear(128,256)

    def forward(self,z):
        z = F.relu(self.linear1(z))
        z = F.relu(self.linear2(z))
        z = self.linear3(z)
        return z

class VariationalAutoencoder(nn.Module):
    def __init__(self, latent_dims):
        super(VariationalAutoencoder,self).__init__()
        self.encoder = VariationalEncoder(latent_dims)
        self.decoder = Decoder(latent_dims)

    def forward(self,x):
        z = self.encoder(x)
        return self.decoder(z)


class AnomalyScore(object):
    def __init__(self,dataset):
        self.model = torch.load('../' + dataset + '/AE.model')
        self.criterion = nn.MSELoss(reduction='sum')
        self.dataset = dataset
        self.device = 'cuda' if torch.cuda.is_available() else 'cpu'
        self.anomaly_weight = json.load(open('../' + dataset + '/stability-embedding.json'))
        # self.id2process = json.load(open(p'../' + dataset + '/id2process.json'))
        self.mean_anomaly_weight = np.mean(list(self.anomaly_weight.values()))
        
    # def VAETrain(self,feature_z_dim = 32,batch_size = 256,lr = 0.001,w_d = 1e-5,epochs = 20):

    #     train_file = self.dataset+'/process_embedding-train-no.json'
    #     train_set = Train_Loader(train_file)
        
    #     train_ = torch.utils.data.DataLoader(
    #         train_set,
    #         batch_size=batch_size,
    #         shuffle=True,
    #         num_workers=20,
    #         pin_memory=False,
    #         drop_last=True
    #     )

    #     metrics = defaultdict(list)
    #     model = VariationalAutoencoder(feature_z_dim)
    #     model.to(device)
    #     criterion = nn.MSELoss(reduction='sum')
    #     optimizer = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=w_d)
    #     start = time.time()
    #     for epoch in range(epochs):
    #         ep_start = time.time()
    #         running_loss = 0.0
    #         for bx, (data) in enumerate(train_):
    #             data = data.to(self.device)
    #             sample = model(data)
    #     # loss = criterion(data.to(device), sample)
    #             loss = criterion(data.to(device), sample) + model.encoder.kl
    #             optimizer.zero_grad()
    #             loss.backward()
    #             optimizer.step()
    #             running_loss += loss.item()
    #         epoch_loss = running_loss/len(train_set)
    #         metrics['train_loss'].append(epoch_loss)
    #         ep_end = time.time()
    #         print('-----------------------------------------------')
    #         print('[EPOCH] {}/{}\n[LOSS] {}'.format(epoch+1,epochs,epoch_loss))
    #         print('Epoch Complete in {}'.format(timedelta(seconds=ep_end-ep_start)))
    #     end = time.time()
    #     print('-----------------------------------------------')
    #     print('[System Complete: {}]'.format(timedelta(seconds=end-start)))
    #     torch.save(model,self.dataset + '/AE.model')
    #     return model
        
    def VAEInfer(self,process_node,nodes):
        if self.model == None:
            self.model = self.VAETrain()
        loss_dict = defaultdict(float)
        # test_set = Test_Loader(process_node)
        
        # test_ = torch.utils.data.DataLoader(
        #     t_set,
        #     batch_size=batch_size,
        #     shuffle=True,
        #     num_workers=20,
        #     pin_memory=False,
        #     drop_last=True
        # )
        self.model.to(self.device)
        self.model.eval()
        # name = list(process_node.keys())
        # vec = list(process_node.values())
        # data = torch.FloatTensor(vec)
        # sample = self.model(data.to(self.device))
        # loss = self.criterion(data.to(self.device),sample)
        # for i,n in enumerate(name):
        #     if self.id2process[str(n)] in self.anomaly_weight:
        #         s_weight = math.log(self.anomaly_weight[name]) + 1
        #         loss_dict[n] = loss.item()/s_weight
        #     else:
        #         loss_dict[n] = loss.item()
        for node in process_node:
            data = torch.FloatTensor(process_node[node])
            sample = self.model(data.to(self.device))
            loss = self.criterion(data.to(self.device),sample)
            name = nodes[node]['label'].lower()
            # name = self.id2process[str(node)]
            if name in self.anomaly_weight:
                s_weight = math.log(self.anomaly_weight[name]) + 1
                loss_dict[node] = loss.item()/s_weight
            else:
                loss_dict[node] = loss.item()
            # loss_dict[node] = loss.item()


        return loss_dict
