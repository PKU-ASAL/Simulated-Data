# NodLink

## Setup the Enviroment

### install Nostril
sudo pip install git+https://github.com/casics/nostril.git

### install sklearn
pip install scikit-learn

### install networkx
pip install networkx

## Usage
### offline model training
``` 
$ python filename-embedding.py
$ python cmdline-embedding.py
$ python caculate-weight.py
$ python train.py --epoch 50
```
get threshold from the log of train.py: 'anomaly threshold: xxx'
### online detection
```
$ cd real-time/
$ python main.py --threshold xxx
```

