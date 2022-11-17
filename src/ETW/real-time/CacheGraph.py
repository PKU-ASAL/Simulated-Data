class CacheGraph(object):
    def __init__(self,graph):

        self.graph = graph
        self.timestamp = 0
        self.update = 0

    def GetGraphScore(self):
        return self.graph.graph['score']

    def GetGraphTS(self):
        return self.timestamp
        
        