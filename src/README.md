# NodLink

## Setup the Environment

### install Nostril
sudo pip install git+https://github.com/casics/nostril.git

### install sklearn
pip install scikit-learn

### install networkx
pip install networkx

## Usage
### Preprocessing the data
```
$ python process_behavior.py --file benign_file
$ python process_behavior.py --file anomaly_file
```
### Offline model training
``` 
$ python filename-embedding.py
$ python cmdline-embedding.py
$ python caculate-weight.py
$ python train.py --epoch 50
```
get threshold from the log of train.py: 'anomaly threshold: xxx'
### Online detection
```
$ cd real-time/
$ python main.py --threshold xxx
```

