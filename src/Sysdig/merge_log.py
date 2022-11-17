import random
dataset = 'hw17'

o = open(dataset + '/benign-polluted.json','w')

with open(dataset + '/benign-labeled.json', errors='ignore') as f1, open(dataset + '/case17-labeled.json', errors='ignore') as f2:
    l = '1'
    while l:
        i = random.random()
        if i < 0.1:
            l = f2.readline()
        else:
            l = f1.readline()
        o.write(l)
    l = f2.readline()
    while l:
        o.write(l)
        l = f2.readline()
    l = f1.readline()
    cnt = 0
    while l:
        o.write(l)
        l = f1.readline()
        if cnt > 10000000:
            break
        cnt += 1
o.close()

dataset = 'hw17'
# f = open(dataset + '/benign3.txt',errors='ignore')

# o = open(dataset + '/labeled-benign3.txt','w')

# for line in f:
#     if 'Process/Start' in line:
#         x = line.rfind('/')
#         s_list = list(line)
#         s_list.insert(x,' is_warn=False')
#         s = ''.join(s_list)
#         o.write(s)
#     else:
#         o.write(line)

# f1 = open(dataset + '/test-labeled.json', errors='ignore')
# o = open(dataset + '/test-labeled4:1.json','w')
# cnt = 0
# for i in f1:
#     if cnt < 6702995 / 2:
#         o.write(i)
#     cnt += 1
# print(cnt) 

# f1 = open(dataset + '/anomaly.txt', errors='ignore')
# cnt = 0
# for i in f1:
#     cnt += 1
# print('anomaly:',cnt) 
# f1 = open(dataset + '/anomaly.json')
# cnt1= 0
# for i in f1:
#     cnt1 += 1
# print(cnt1) 

# cnt2 = 0
# f2 = open(dataset + '/benign-labeled.json')
# for i in f2:
#     cnt2 += 1
# print(cnt2) 

# print(cnt1 + cnt2)


