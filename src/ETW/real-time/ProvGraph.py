
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
def get_size(obj, seen=None):
    """Recursively finds size of objects"""
    size = sys.getsizeof(obj)
    if seen is None:
        seen = set()
    obj_id = id(obj)
    if obj_id in seen:
        return 0
    # Important mark as seen *before* entering recursion to gracefully handle
    # self-referential objects
    seen.add(obj_id)
    if isinstance(obj, dict):
        size += sum([get_size(v, seen) for v in obj.values()])
        size += sum([get_size(k, seen) for k in obj.keys()])
    elif hasattr(obj, '__dict__'):
        size += get_size(obj.__dict__, seen)
    elif hasattr(obj, '__iter__') and not isinstance(obj, (str, bytes, bytearray)):
        size += sum([get_size(i, seen) for i in obj])
    return size
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
        if dataset == 'hw20':
            self.attack_process = set(['f4106fd012d36c419884c078bfa0d7d8', 'ba0c5316e6fa54216acc9110ce3fc5d8', '77d192d3aa3b53fa32ca4e97fa20733d', '0e881c511f479048c410c13ed48be35d', 'c88f5ef37edb18c47c1d5d0093d5f886', '34adc0f4600038b5490d2173d0d2e0b1', '19e5ea525891815fa367089bbc2d8c03', 'c21e17ba94c56d084eca6701a20c1aed', 'd9e6eb83c05eca89983adf15a60c922d', '72a13f545e5dfb5835365609045201a0', '224ed451937e268f150946b3ae48c27d', 'caf4d3e9fc825024591331fbda3e035d', 'ef5796fb4e863cfdae647ff52b1cdd5e', '9aee6c9fc4f7c217da01b791e7079abb', '6082b551cbe7e35fcb30bc6a9d81a48e', '2747d3b948ba7b25711cfa8ece998ff5', '04123a0c0bbbc0b2ded650454ed22d10', '76ae200b0a1a73aecf7a293da7f3552c', 'd37af5adfaa024e539b83e30191fcdec', '49e0b760ea287f477dacaf3c04ebb258', 'a6fc5bd669ef2dd46773e348aaa823de', '418af2182596f7b2499803e884692c11', '1bbe83746c4dc7bd98a5b1898d4e97a6', '2d4de7fc672e75dcafc44eddc3ba0ea8', 'fcfc065f34be653d80aaa6230a21af13', '1ab9d0e544961427073a276ee608b822', '53b7fcdc4bd446a42e1f7b68b0a70626', '7fae21d89b5e159cb4fb979bae23e5f7', 'e30a6deee197fdac89189022341f49c7', '7edf352f9fb1500fc7ad04c4e05ec912', 'ed92e432970a3b6641558b51bf3e4e6f', 'bb0628124210cb446ee755aa3ecb71ff', '3ba7410a631d244ac45b4971d30e57da', '4d8ecc01537a5fd45f02cefd2b57c84e', '84d0532fea30425eefa218baae1e0e8c', '41f34761393beeb4ab400c5aa4a3ab80'])
        elif dataset == 'win10':
            # self.attack_process = set(['d4400730035525bee626f9d4c4d8a152', '45406c0a85fccc20f2e4f7e10c64733b', '23d6f2b774e431f668df3c40bfc1a3e8', 'd64c5bb767d6a928e5db7abc73afbebe', '348559d271f57fb1b5ba2eded9940975', 'f0482ceaa72012536bea91076587bd6f', '764fca56fee5525bd098ae311e073bfb', '484f2e9e85b7e62dddd465a31198b585', 'be40b7b24c3f1cfd6679a4b01d056551', '65b6784bf0b757d8dda52d2b7c38db9e', '6aa4b847eacd92f5e2c681a0d3c54a03', '6d7355758464615200f7aa4b8743e16d', 'c8fec1ae0c091f3b6c091617ccc35f9b', 'fb7c3d30d2ede90d1b60f559145211b8', '747b302d0a5747497a39d11e41efbf82', 'ee89d7c76d0b239c6790833dabb32534', '3f11106677a3a7783e77278e987ceab0', '5408eff07b0a3aad30b46c484e5235b2', 'f62f117f72acc2bd9fc55fbf2551d586', 'dafb9acf62a3c17b609c217b9f6ebafd', '219d2dd9d2ee376588c24c26a711a6af', '24ebedb2c2f077bb2eeae7a6e6f6f5ca', '1e2f7d4afdedff6e4e0be8378bf059a2', '6ea1872984a507282fc609fa9b9a76ca', 'bd564e0db1992d4bc0fc7139a4b7d6a9', '4b1d560f1821ad43a18427b64366b8fa', 'e1af9edecf8a93ce10c5183a287ed85e', '5c1f1ec6667430a87316f608d94b08fb', '7fbf49bfe0c7cde8f5d0f5421c5b18eb', '7212353bbcf65925b2443858aeb64e9f', '1950e4c09a3c31d060119935a6b02815', '47ea676812bf207d3e3140c251b3ad50', '56d95db60864840b99515d883d2fad41', '59bda6cf1918b6b99ace321373b64dd1', 'd311c6ed3b0cf08455abd5b1cde72150', '2e92e8d07be2773dc1ba41cbf65916c6', 'ce2a88230e5215b520bd7f749e810671', 'd4ee1c99352260eaf83270ab10841e2c', '4b451debdfbe42f32fd5244a47d64b0c', '6142a5dca168d03a950e21b3a1f22d3b', '838dfffb7a13305b19bea3a8a072cafd', 'a82a277b7e120c9a7edccd78f5aeae08', '7584717085dba32fe5cb9137cdb5edeb', '01c0fc29bf327d156e8965ae3caee07b', '6f4214d38f991b8722648c02d50b675b', '3637266d9466dfb354c8772ff0f98641', 'd2eb3ad6a536c74d3c752b140426a45c', '15094515321e9a167576fb6c4f3c433f', 'b868af32b977dfa5011d88627c0af145', '56fe4a0466a3a3b63ab49e9247d2d655', '35539842b904d5cea2881cce0f9381a0', '461a96301fbef83bf800a37502ec3a31', 'ed7c8c83c0b6b1df0327e707903d52b6', '307da1fa3a178afd457660831860edf4', '44786c5c50d71bc00e04e633bdd0b831', '8edaac3d48eeeb2670fe9c624142e15f', '225c8f50794427b2fb461024dafdde54', '2d9fbaa11285195278b7628f2caaeb0f', '33de4b9ea8f1c9aafe92710419d95143', 'a1d429f5631699b1cbf90b607f610130', 'a1a9e4d537c611d0f04eb8d03d6ea45b', '2752bc2703e41eaf33a2301cfa1f5c1f', '04f5a5a45fdb50084ab3708c9c908fc0', 'a0f6003803e827608b224c04e364f438', '091a0c1f09e73353a6d8e8ba84f1cade', 'c048a7a0768926eb85be76c14142d6de', '9dedd3ea211f0390339381739d51dada', 'd473594f5acf4b329514538c244fabab', '3e8a8baf0b5590d91eba150688a32ab1', '17779c98dd6da8170a9de2d84aa835ba', '1b8326ac3bb130497a914bf3e61a32cc', '49d9f7376e5f19bf033f9e72a9cf34c6', '5bbea65f624ffa1f320b4d75fe1c7ea7', 'bd96749d1abf7e07bd8225a91174cda6', '008f14889fd6d6148f5e9c70432e663c', '9ede27e6212e0843fd5c4430232186b5', '0aee8656e0316f0dbabe10facde189e2', 'ada6869f41017e83953a5759261f96ea', '9dfd70b47f832afd018e7a46c46af448', 'cd02a7eeaf264d92d21c26f7e2a78d22', 'bfd740b8431d6b047b8da4c4c3eaf376', 'b04e523bfedd353c6e3bb7cc319d14b4', '2c6e292ad77c072b4c92b94914852d30', '52d0ca37a3c5fe8f3309e9fa0273634b', 'dbd5b344fb014d28a76ca731fcc57fff', '5c58da0b111b362defa12ab596180ddf', '6d413de3e4fe4bbdfe305e48d714c684', 'e1e39ca974158608166bff19f4ac42b1', '55298e9ae4d311fe243de9fc1e533f84', 'ec7689df116fdd392a2b24ad70dbb21a', '9396883177bd36660ae7c646114e0e5e', '14ae70dc18c9df9f78175d30ff483299', '84e12f6250d627d6ba1a12f3dddbd04c', '759704b886ac06733f8fc992bfc7de9c', '1505712c74b67f9e8ca5341f92dd7789', 'f852075be57d506c2e29fef909dd962f', '5715235bc2b02e9f34d890fa14953938', '5e12637dd830aed4f3cb549fac7dfd9b', 'fab3fff54cc4f783e5a72071af32cd3e', '4e70650635a98288f1f0cfe04b550dab', 'a57e634a28da5e4b8c25c7d9f5049fcc', 'a1c0efeff52b489a15804fc6a5ab38b0', '335df5a765478c1e1d31c1a0785ca3b0', '41c8b455a4240a973da19ca991fa9839', '4bb8eac1c8b25795e8982d445e1bf2dd', 'abf3516eb4f4caeb03ce2dfa19dbc2a7', 'a1e8de60e23e3f324c36b9378969ea08', '2ac870b17c92ab54a7ba9547aebcb305', 'e39d571f71d6292902c3c39a5e21c977', '52d7b261ba14c817842d0a2f9b538b0f', '634d5704dcd14f009ca08456182b5894', '22abd22bc65062edccf82f7f08d26ca5', '3ee4ec5a751ed1179f2d924769316085', 'feae24988ea5ba35e11a7724e44d526d', 'c36e2b63556a5ccfd5a78b59db63fed0', '3278c9a08abb6301d40971b04f878e27', '339308cb6bd88b55125faead9ace911c', 'c1d589e40a769447021fd2acc65a40c8', 'f0e4df06ae86e6c323d83ff3c072a879', 'bb41d6d66913ca90d48e9acac52689cc', '809e51ee3cbff21501be81c061738d1b', '94f097d8e1852aea3be6d1195f0d8076', 'cbe340e3ff67718ae324a5e4390237be', '367e77530bb8c7cb0f0b9d37244c8026', 'b55c667a37006e047e54e885b1eaf9fe', '9f5384bdc4cebf0cb642ba187a479ec0', 'a7282139cf9f0cbf076f55d4e7902ba6', '0cdaee25d0cd9116e3812f4e6d4fe9a4', '5587f150c0358f0ad3dcf9f84dd71ee6', 'b858a13262f386fbac41cd17374e1ac7', 'a3b86bada278894aa453d9c6bdbe1274', '25a14ba702abfec52c13f7e33b886299', '5eea79c6c531f29341ae4e25b6fe9d6b', '2d954ddcd0093da192abe80dd3f83e11', '278cc8115c77c430c1d14a2b744f88dc', '056defc1f6e65efdc8948ab4584f2ad4', '4c0321c901aea4317b5e5885757f9678', 'ad871f5f28c118f001437a52c9942b74', '9e479e55e049d8e03c4337f820fb8b7a', '2661adaa332a1c223922cd347dbfb7b5', 'd8f0ed902b7550668b57d563c541d0d1', '1ded9060df1fda735d79b550201b0c67', '2c6a2a71db489f4561e5a85ef8fd1482', 'e8d116b362495d29457270ee5ff37736', 'd7a9ad19052ee4098a8b5c735701e544', '3169ebd8b6031ce8956adb0ed2a3f858', '8b2f9b22ecfe6b2ddb52a77761619846', 'de4f9baea5244cdf958a623a2dd72028', 'e9d89963ab9fceb9ff089e2eaaf225eb', '2a60c3d87d451d150a37d0f31fa6911c', '1293b4c36abf3ac29e23d34d5080494e', 'edc8d14970aefa1c1e84642f33fdc42f', '1794137e79eb3e60f9cf016da4f4cc65', '142e4593aaff1ac32ff3862ec1b909ec', '12ab82714bc2019ee217691479c5bfe3', '9df1b94afc0353f76deb49d55190ae13', '1e7eb86b40f4c3f68f0f51e223070154', '3a259778269282e4a09b4a856797dc15', '0c3d74ba40536293c20233ac3cfb6720', '55a73d532f718229128ec346dbd4ee6b', '8249e89792dda0719d8582200659ad02', 'b4817b2046f2405316526a6b5e300ec1', '83e127dc8be666ec63b7ff6501b7a795', '12bd8ce84d10de9ca40a5299211aba0e', '4a57d81060bf4867ec40f15dd03b627e', '1a6207a184dfe65fa5ce8b6546ec962a', '67d9cae75a2d14696ab25a260cf0010e', 'dac0ed1dc93f2cb4ccecb2bae549acd8', '9194afceb5d8129dd23f83b6a04376d7', 'b8f7e64e9894d3804e099f4e141530d1', '44699200bc08dcb978c30ba671a609ca', 'bc69c69958320e3ca2e4968545d7b0c2', '095611649160d79b6e2fbd1e8ec21af2', 'b94d0583eb0e99d10df3aa3a2ce5a8c2', '89bf84dafc665b4bbbd07f618b4242fc', 'bdb8bdb62d428be491244ec8f5d1dbb8', '85d6e762c3b92380ba653e6f44637323', '371a17f7f42975fa3da87b974b267213', '9d0dafe13ade690edad4e0da3c968cd9', '786c5bdb18b5a11056a54759d5657969', '9fbad24cff99105de50031447920738b', '995a2aa04d7cf345fdbaaac71792cc30', 'aa7bac2c8ad523fd9cf42818540c1f63', 'e7b99b95470525851849a9e32794d9dc', '30e28b46330cd178c55a19a87dff5685', '21e1ec9b64ae172ec2ea8f59f62dce36', '3c18ac3ad23f5056d55b9ee508d9710a', 'b992ed0d615b066197e8c8caa3cd5ce2', 'e036be85de6c8d6a91d48b577e508c3c', '39574f9a5022bca38a1311f0d7241e77', '41763c7e00328748423ea7d80ed9dc79', '59341dca416c4f949c0994e65e2f2982', 'e19b64fbfd12a97cc150eb61db8ca60e', 'ffd9f1cb634eff0254ee323364d2c18a', '939fa1c205ab2074b644e9c474f8d278', 'e59436d33fe479afe5717e2c2281c1fc', '8819ad4e484e7252de2df0b31a41dcce', '969a027b2bcf1e638bc0d6d346a67e3c', '2f59412338daa45b9011a9e252568a40', '9eb942893ded97f1c0ddd00791761070', 'a8838e8ff703f1eda68ab14e86e08fe8', '750a8ef07d281b08f4c7b55ed7890b16', '3f35843b3c2c569f5f1dd0cc6accdddb', '9d0b76daf0dc735e79445647a6a2a782', 'c2e91ffba34f9362615d9a24ee215b37', '1690fcfe96013bee2b7c0e284e1b3242', '52d15e10f80c8bebdc64bf7b36a0b2fb'])
            self.attack_process = set(['764fca56fee5525bd098ae311e073bfb', '484f2e9e85b7e62dddd465a31198b585', 'be40b7b24c3f1cfd6679a4b01d056551', '6aa4b847eacd92f5e2c681a0d3c54a03', '6d7355758464615200f7aa4b8743e16d', 'c8fec1ae0c091f3b6c091617ccc35f9b', 'fb7c3d30d2ede90d1b60f559145211b8', '747b302d0a5747497a39d11e41efbf82', 'ee89d7c76d0b239c6790833dabb32534', '3f11106677a3a7783e77278e987ceab0', 'f62f117f72acc2bd9fc55fbf2551d586', 'dafb9acf62a3c17b609c217b9f6ebafd', '24ebedb2c2f077bb2eeae7a6e6f6f5ca', '1e2f7d4afdedff6e4e0be8378bf059a2', '6ea1872984a507282fc609fa9b9a76ca', 'bd564e0db1992d4bc0fc7139a4b7d6a9', '4b1d560f1821ad43a18427b64366b8fa', 'e1af9edecf8a93ce10c5183a287ed85e', '5c1f1ec6667430a87316f608d94b08fb', '7fbf49bfe0c7cde8f5d0f5421c5b18eb', '6f4214d38f991b8722648c02d50b675b', '3637266d9466dfb354c8772ff0f98641', 'd2eb3ad6a536c74d3c752b140426a45c', 'c2c7e73fd2cd1797ba62fa01ef623e84', '15094515321e9a167576fb6c4f3c433f', 'b868af32b977dfa5011d88627c0af145', 'ed7c8c83c0b6b1df0327e707903d52b6', '307da1fa3a178afd457660831860edf4', '44786c5c50d71bc00e04e633bdd0b831', '225c8f50794427b2fb461024dafdde54', '2d9fbaa11285195278b7628f2caaeb0f', '33de4b9ea8f1c9aafe92710419d95143', '2752bc2703e41eaf33a2301cfa1f5c1f', '04f5a5a45fdb50084ab3708c9c908fc0', 'a0f6003803e827608b224c04e364f438', '091a0c1f09e73353a6d8e8ba84f1cade', 'c048a7a0768926eb85be76c14142d6de', '9dedd3ea211f0390339381739d51dada', 'd473594f5acf4b329514538c244fabab', '3e8a8baf0b5590d91eba150688a32ab1', '17779c98dd6da8170a9de2d84aa835ba', '1b8326ac3bb130497a914bf3e61a32cc', '49d9f7376e5f19bf033f9e72a9cf34c6', '5bbea65f624ffa1f320b4d75fe1c7ea7', 'bd96749d1abf7e07bd8225a91174cda6', '008f14889fd6d6148f5e9c70432e663c', '9ede27e6212e0843fd5c4430232186b5', 'b04e523bfedd353c6e3bb7cc319d14b4', '2c6e292ad77c072b4c92b94914852d30', '52d0ca37a3c5fe8f3309e9fa0273634b', 'dbd5b344fb014d28a76ca731fcc57fff', '5c58da0b111b362defa12ab596180ddf', '55298e9ae4d311fe243de9fc1e533f84', '9396883177bd36660ae7c646114e0e5e', '84e12f6250d627d6ba1a12f3dddbd04c', '759704b886ac06733f8fc992bfc7de9c', '5715235bc2b02e9f34d890fa14953938', '5e12637dd830aed4f3cb549fac7dfd9b', 'fab3fff54cc4f783e5a72071af32cd3e', '4e70650635a98288f1f0cfe04b550dab', 'abf3516eb4f4caeb03ce2dfa19dbc2a7', 'a1e8de60e23e3f324c36b9378969ea08', '2ac870b17c92ab54a7ba9547aebcb305', 'e39d571f71d6292902c3c39a5e21c977', '52d7b261ba14c817842d0a2f9b538b0f', '3ee4ec5a751ed1179f2d924769316085', 'c36e2b63556a5ccfd5a78b59db63fed0', '339308cb6bd88b55125faead9ace911c', 'c1d589e40a769447021fd2acc65a40c8', 'f0e4df06ae86e6c323d83ff3c072a879', '809e51ee3cbff21501be81c061738d1b', 'cbe340e3ff67718ae324a5e4390237be', 'b55c667a37006e047e54e885b1eaf9fe', '9f5384bdc4cebf0cb642ba187a479ec0', 'a7282139cf9f0cbf076f55d4e7902ba6', '0cdaee25d0cd9116e3812f4e6d4fe9a4', '5587f150c0358f0ad3dcf9f84dd71ee6', 'b858a13262f386fbac41cd17374e1ac7', 'a3b86bada278894aa453d9c6bdbe1274', '25a14ba702abfec52c13f7e33b886299', '5eea79c6c531f29341ae4e25b6fe9d6b', '2d954ddcd0093da192abe80dd3f83e11', '278cc8115c77c430c1d14a2b744f88dc', '2661adaa332a1c223922cd347dbfb7b5', 'd8f0ed902b7550668b57d563c541d0d1', '1ded9060df1fda735d79b550201b0c67', '2c6a2a71db489f4561e5a85ef8fd1482', 'd7a9ad19052ee4098a8b5c735701e544', '3169ebd8b6031ce8956adb0ed2a3f858', '8b2f9b22ecfe6b2ddb52a77761619846', 'de4f9baea5244cdf958a623a2dd72028', 'e9d89963ab9fceb9ff089e2eaaf225eb', '2a60c3d87d451d150a37d0f31fa6911c', '9df1b94afc0353f76deb49d55190ae13', '1e7eb86b40f4c3f68f0f51e223070154', '3a259778269282e4a09b4a856797dc15', '0c3d74ba40536293c20233ac3cfb6720', '55a73d532f718229128ec346dbd4ee6b', '8249e89792dda0719d8582200659ad02', '4a57d81060bf4867ec40f15dd03b627e', '67d9cae75a2d14696ab25a260cf0010e', 'dac0ed1dc93f2cb4ccecb2bae549acd8', '9194afceb5d8129dd23f83b6a04376d7', '44699200bc08dcb978c30ba671a609ca', 'bc69c69958320e3ca2e4968545d7b0c2', 'b94d0583eb0e99d10df3aa3a2ce5a8c2', '89bf84dafc665b4bbbd07f618b4242fc', 'bdb8bdb62d428be491244ec8f5d1dbb8', '85d6e762c3b92380ba653e6f44637323', '371a17f7f42975fa3da87b974b267213', '9d0dafe13ade690edad4e0da3c968cd9', '786c5bdb18b5a11056a54759d5657969', '9fbad24cff99105de50031447920738b', '995a2aa04d7cf345fdbaaac71792cc30', 'aa7bac2c8ad523fd9cf42818540c1f63', 'e7b99b95470525851849a9e32794d9dc', 'e036be85de6c8d6a91d48b577e508c3c', '39574f9a5022bca38a1311f0d7241e77', '41763c7e00328748423ea7d80ed9dc79', '59341dca416c4f949c0994e65e2f2982', 'e19b64fbfd12a97cc150eb61db8ca60e', 'ffd9f1cb634eff0254ee323364d2c18a', '939fa1c205ab2074b644e9c474f8d278', 'a72132b3a4fe293868d34fe8c355c86d', '62b14810ae5b30e790fd6dba0c4a984b', 'e59436d33fe479afe5717e2c2281c1fc', 'c76b8591b1015a9be42ea9821efd3785', 'ecfe951c4581a5ec041a1e5dd55243f9', '8819ad4e484e7252de2df0b31a41dcce', '969a027b2bcf1e638bc0d6d346a67e3c', '2f59412338daa45b9011a9e252568a40', '9eb942893ded97f1c0ddd00791761070', 'a8838e8ff703f1eda68ab14e86e08fe8', '750a8ef07d281b08f4c7b55ed7890b16', '3f35843b3c2c569f5f1dd0cc6accdddb'])
        self.nodes = defaultdict(dict)
        print(len(self.attack_process))
         
        
    def graph_add_node_mgr(self, row, key, event_type):
        self.lock.acquire()
        node_attr = {}
        if key == EVENT_KEY.FILE:
            Process = str(row['PID']) + str(row['PName'])
            s_node = get_md5(Process)
            if not (s_node in self.nodes):
                self.nodes[s_node] = {'label': row['PName'].replace('\\','/'), 'cmd':'', 'type': NODE_TYPE.PROCESS, 'score': 0}
            t_node = get_md5(row['FileName'])
            if not (t_node in self.nodes):
                self.nodes[t_node] = {'label': row['FileName'].replace('\\','/'), 'type': NODE_TYPE.FILE, 'score': 0}
            self.TmpG.add_node(s_node)
            self.TmpG.add_node(t_node)
            self.TmpG.add_edge(s_node,t_node,e_type = event_type)
        elif key == EVENT_KEY.PROCESS:
            Parentid = row['ParentID'].replace(',','') + str(row['PPName'])
            # print(Parentid)
            s_node = get_md5(Parentid)
            if not (s_node in self.nodes):
                self.nodes[s_node] = {'label': '', 'cmd':'', 'type': NODE_TYPE.PROCESS, 'score': 0}
            t_node = get_md5(str(row['PID']) + str(row['PName']))
            if not (t_node in self.nodes):
                self.nodes[t_node] = {'label': row['PName'], 'type': NODE_TYPE.PROCESS, 'cmd': row['CommandLine'].replace('&quot;',' ').replace('\\','/'), 'score': 0}
            self.TmpG.add_node(s_node)
            self.TmpG.add_node(t_node)
            self.TmpG.add_edge(s_node,t_node,e_type = event_type)

        elif key == EVENT_KEY.NET:
        # add net type node
            s_node = get_md5(str(row['PID']) + str(row['PName']))
            if not (s_node in self.nodes):
                self.nodes[s_node] = {'label': row['PName'], 'type': NODE_TYPE.PROCESS, 'cmd': '', 'score': 0}
            src_ip = row['saddr']
            dst_ip = row['daddr']
            sport = row['sport']
            dport = row['dport']
            x = '{},{}/32'.format(src_ip,dst_ip)
            t_node = get_md5(x)
            if not (t_node in self.nodes):
                self.nodes[t_node] = {'label': x, 'type': NODE_TYPE.NET, 'score': 0}
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

    def GetNodeCmd(self,node):
        if self.nodes[node]['cmd'] != '':
            x = self.nodes[node]['cmd']
        else:
            x = self.nodes[node]['label']
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

        nodes = self.G.nodes()
        pnode = []
        for node in nodes:
            if self.GetNodeType(node) == NODE_TYPE.PROCESS and self.GetNodeCmd(node) != '':
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
        self.G = nx.relabel_nodes(self.G, relabel_dic, copy=False)
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
        #     if attr == "cron" or attr == "bash" or attr == "sh" or attr == "sshd":
        #     if attr == "cron":
        #         cron_list.append(node)
        
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
        # remove_list = cron_process | set(remove_node_list) | cron_list
        # self.G.remove_nodes_from(remove_node_list)

        #To handle firefox, find pattern
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
        
        # node_centrality = nx.eigenvector_centrality(self.G,max_iter=200,tol = 1e-2)

        connected_graph_list = self.propagation(update_node_list)

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
        return -1
    
    def graph_taylor(self,g):
        cnt = 0
        remove_nodes_list = set()
        for node in g.nodes:
            if g.degree(node) < 5 or node in remove_nodes_list:
                continue
            rbp = RandomBinaryProjections('rbp', 10)
            engine = Engine(256, lshashes=[rbp])    
            merge_node = defaultdict(list)
            for i in g.successors(node):
                if i in remove_nodes_list:
                    continue
                name = self.GetNodeNewName(i)
                if name == -1:
                    continue
                v = np.array([])
                if self.GetNodeType(i) == NODE_TYPE.PROCESS:
                    v = self.GetEmbedding(name.split('/'), self.c2v)
                else:
                    v = self.GetEmbedding(name.split('/'), self.w2v)
                candidate = engine.neighbours(np.array(v))
                if len(candidate) != 0 and candidate[0][2] < 0.05:
                    c = candidate[0][1]
                else:
                    c = name
                    engine.store_vector(np.array(v), name)
                merge_node[c].append(i)

            for i in merge_node:
                if len(merge_node[i]) >= 5:
                    g = self.merge_nodes(g,merge_node[i][1:],merge_node[i][0],remove_nodes_list)
                    remove_nodes_list |= set(merge_node[i][1:])
            merge_node = defaultdict(list)
            rbp = RandomBinaryProjections('rbp', 10)
            engine = Engine(256, lshashes=[rbp]) 
            for i in g.predecessors(node):
                if i in remove_nodes_list:
                    continue
                name = self.GetNodeNewName(i)
                if name == -1:
                    continue                              
                v = np.array([])
                if self.GetNodeType(i) == NODE_TYPE.PROCESS:
                    v = self.GetEmbedding(name.split('/'), self.c2v)
                else:
                    v = self.GetEmbedding(name.split('/'), self.w2v)
                candidate = engine.neighbours(np.array(v))
                if len(candidate) != 0 and candidate[0][2] < 0.05:
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
                    if self.GetNodeType(i) == NODE_TYPE.PROCESS:
                        v = self.GetEmbedding(name.split('/'), self.c2v)
                    else:
                        v = self.GetEmbedding(name.split('/'), self.w2v)
                    candidate = engine.neighbours(np.array(v))
                    # print(candidate,v)
                    if len(candidate) != 0 and candidate[0][2] < 0.05:
                        c = candidate[0][1]
                    else:
                        c = name
                        engine.store_vector(np.array(v), name)
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
                    if self.GetNodeType(i) == NODE_TYPE.PROCESS:
                        v = self.GetEmbedding(name.split('/'), self.c2v)
                    else:
                        v = self.GetEmbedding(name.split('/'), self.w2v)
                    candidate = engine.neighbours(np.array(v))
                    if len(candidate) != 0 and candidate[0][2] < 0.05:
                        c = candidate[0][1]
                    else:
                        c = name
                        engine.store_vector(np.array(v), name)

                    merge_node[c].append(i)                        
                for i in merge_node:
                    if len(merge_node[i]) >= 2:
                        g = self.merge_nodes(g,merge_node[i][1:],merge_node[i][0],remove_nodes_list)
                        remove_nodes_list |= set(merge_node[i][1:])
            if len(remove_nodes_list) != 0:
                flag = True
                g.remove_nodes_from(remove_nodes_list)
        return g
    def caculate_anomaly_score(self,pnode,anomaly_cutoff):
        need_to_caculate = defaultdict(list)
        undirected_G = self.G.to_undirected(as_view=True)
        print(len(pnode))
        for node in pnode:
            neibor = list(undirected_G[node])
            # print(node)
            if len(neibor) == 0:
                continue
            # tmp_dict = set()
            for nei in neibor:
                if self.GetNodeName(nei) is not None and self.GetNodeName(nei) != 'unknown' and self.GetNodeType(nei) != NODE_TYPE.PROCESS:
                    need_to_caculate[node].append((nei,self.GetNodeName(nei)))
        print('need_to_caculate',len(need_to_caculate))

        if len(need_to_caculate) == 0:
            return -1
        node_feature = defaultdict(list)
        f = True
        for node in need_to_caculate.keys():
            flag = False
            cmdline = self.GetNodeCmd(node)
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
        self.filtered |= VAE_list
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
            score[i] = (self.GetNodeScore(i), self.G.out_degree(i)/ (self.G.in_degree(i) + 1))
        
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

        score = {}
        attr_list = {}
        for i in self.G.successors(node):
            score[i] = (self.GetNodeScore(i),self.G.out_degree(i)/ (self.G.in_degree(i) + 1))
        
        new_score = sorted(score.items(), key=lambda d:(d[1][0],d[1][1]), reverse=True)[:10]
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
                # print(local_subgraph)
                subgraph_node |= local_subgraph
                sense = {node}
                local_subgraph = self.GetforeSubgraph(node,f_depth,sense)
                subgraph_node |= local_subgraph
            subgraph = self.G.subgraph(list(subgraph_node)).copy()

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
            # for k in G.nodes():
            #         # print(k)
            #     G.nodes[k]['label'] = self.GetNodeNewName(k) + ' ' + str(self.GetNodeState(k) == False)

            # nx.drawing.nx_pydot.write_dot(G, 'debug1.dot')

            # G = self.graph_taylor(G)
            # for k in G.nodes():
            #         # print(k)
            #     G.nodes[k]['label'] = self.GetNodeNewName(k) + ' ' + str(self.GetNodeState(k) == False)

            # nx.drawing.nx_pydot.write_dot(G, 'debug2.dot')
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
        if len(score) < 3:
            self.graph_cache = merged_graph_list[:topK]
            return 
        # Different method
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
            print('[Alert]: ', score[i], len(g.nodes()),self.attack_node(g.nodes()))
        merged_graph_list.sort(key = lambda x: x.GetGraphScore(),reverse = True)
        
        
        self.graph_cache = merged_graph_list[:topK]
        print('size of cache:',get_size(self.graph_cache))
        
    def attack_node(self,node_list):
        result = []
        for node in node_list:
            if node in self.attack_process:
                result.append(node)
        return result