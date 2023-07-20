import torch.nn as nn
import torch.nn.functional as F
import torch

class VariationalEncoder(nn.Module):
    def __init__(self,latent_dims):
        super(VariationalEncoder,self).__init__()
        self.linear1 = nn.Linear(256,128)
        self.linear2 = nn.Linear(128,64)
        self.linear3 = nn.Linear(64,latent_dims)
        self.linear4 = nn.Linear(64,latent_dims)

        self.N = torch.distributions.Normal(0,1)
        self.N.loc = self.N.loc.cuda()
        self.N.scale = self.N.scale.cuda()
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