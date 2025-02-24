# [NDSS 2024] NODLINK: An Online System for Fine-Grained APT Attack Detection and Investigation
This is an implementation of NodLink and the public Simulated datasets described in NDSS 2024 paper: [NODLINK: An Online System for Fine-Grained APT Attack Detection and Investigation](https://arxiv.org/abs/2311.02331).
## Simulated-Data
We carried out 5 attacks on three different hosts. The attack description and annotation are listed in the _doc_ folder.

### Simulate on Ubuntu
We carried out an attack on Ubuntu 20.04.

![image](doc/img/ubuntu.png)

SimulatedUbuntu.zip  
$\qquad$ - hw17.zip  
$\qquad\qquad$ - benign.json  
$\qquad\qquad$ - anomaly.json  


### Simulate on Windows server 2012
We carried out an attack on Windows server 2012.
![image](doc/img/WS12.png)

SimulatedWS12.zip  
$\qquad$ - hw20.zip  
$\qquad\qquad$ - benign.json  
$\qquad\qquad$ - anomaly.json  


### Simulate on Windows 10
We carried out three attacks on Windows 10.

#### APT29
![image](doc/img/APT29.png)
#### Sidewinder
![image](doc/img/Sidewinder.png)
#### FIN6
![image](doc/img/FIN6.png)

SimulatedW10.zip  
$\qquad$ - win10.zip  
$\qquad\qquad$ - benign.json  
$\qquad\qquad$ - anomaly.json 

## NodLink
The prototype of NodLink is in the `src` directory. The `README.md` in it describes how to run our tool.

## ProvDetector
The prototype of our reimplementation of ProvDetector that is described in paper [You Are What You Do: Hunting Stealthy Malware via Data Provenance Analysis](https://kangkookjee.io/wp-content/uploads/2021/06/provdetector-ndss2020.pdf).


## Citations
If you use any of our tools or datasets in your research for publication, please kindly cite the following paper:
```
@inproceedings{Li_2024, series={NDSS 2024},
   title={NODLINK: An Online System for Fine-Grained APT Attack Detection and Investigation},
   url={http://dx.doi.org/10.14722/ndss.2024.23204},
   DOI={10.14722/ndss.2024.23204},
   booktitle={Proceedings 2024 Network and Distributed System Security Symposium},
   publisher={Internet Society},
   author={Li, Shaofei and Dong, Feng and Xiao, Xusheng and Wang, Haoyu and Shao, Fei and Chen, Jiedong and Guo, Yao and Chen, Xiangqun and Li, Ding},
   year={2024},
   collection={NDSS 2024} 
}
```

## Feedback
Should you have any questions, please post to [the issue page]([Issues · Nodlink/Simulated-Data (github.com)](https://github.com/Nodlink/Simulated-Data/issues)), or email Shaofei Li via lishaofei@pku.edu.cn.

## Acknowledgments
We would like to thank the anonymous reviewers for their valuable feedback and suggestions.

