import torch
import json
import numpy as np
class Loader(torch.utils.data.Dataset):
    def __init__(self):
        super(Loader, self).__init__()
        self.dataset = ''
        self.idx2processnum = []
    
    def __len__(self):
        return len(self.dataset)
    
    def __getitem__(self, idx):
        data = self.dataset[self.idx2processnum[idx]]
        return data
    
class Train_Loader(Loader):
    def __init__(self, path):
        super(Train_Loader, self).__init__()

        self.dataset = json.load(open(path,'r'))
        for i in self.dataset:
            self.idx2processnum += [i]
            # print(len(self.dataset[i]))
            self.dataset[i] = torch.FloatTensor(self.dataset[i])