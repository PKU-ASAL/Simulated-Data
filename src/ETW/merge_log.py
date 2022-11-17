import random
dataset = 'hw20'

o = open(dataset + '/anomaly.json','w')

with open(dataset + '/labeled-benign-add.json', errors='ignore') as f1, open(dataset + '/attack.json', errors='ignore') as f2:
    l = '1'
    while l:
        i = random.random()

        if i < 0.01:
            l = f2.readline()
        else:
            l = f1.readline()
        o.write(l)
    l = f2.readline()
    while l:
        o.write(l)
        l = f2.readline()
    l = f1.readline()
    while l:
        o.write(l)
        l = f1.readline()

o.close()

# dataset = 'win10'
# f = open(dataset + '/apt.txt',errors='ignore')

# o = open(dataset + '/labeled-apt.txt','w')

# keyword = ['chromeRemoteServices.ps1','124.223.85.207:8082/a','Invoke-AtomicTest','T1059.006.py','1053.005.bat','computersystem','certutil.exe','HookSSLX64.dll',\
#             'timestomp','spolsv.exe','rundll32','advfirewall','mimikatz2.exe','domain_trusts','systemdrive','mimikatz.exe',\
#             'C:\%HOMEPATH%\Desktop\T1022','Invoke-WebRequest','Import-Module','portproxy','T1059.003_script.bat','cscript.exe','HKEY_LOCAL_MACHINE', \
#             'HookSSLX64.dll','test.exe','lazagne1.exe','procdump.exe','domain admins','T1022.zip','mshta.exe','T1059_003note.txt']

#             # 'test.bin','AtomicRedTeam.exe','T1547.009_modified_shortcut.url','osk.exe','sethc.exe','utilman.exe','magnify.exe','narrator.exe','DisplaySwitch.exe','atbroker.exe',\
#             # 'eventvwr.msc','HKCU:\software\classes\mscfile\shell\open\command','HKCU:\software\classes\mscfile\shell\open\command','T1547.009_modified_shortcut.url','hkcu\software\classes\mscfile\shell\open\command',\
#             # 'T1059.007.vbs','raw.githubusercontent.com','vssadmin.exe','Device\HarddiskVolumeShadowCopy1','ntds_T1003','shadowcopy','ntds.dit','vssstore','T1119_command_prompt_collection','T1119_1.txt',\
#             # 'T1119_2.txt','T1119_3.txt','T1119_4.txt','sys_info.vbs'
# for line in f:
#     if 'Process/Start' in line:
#         flag = False
#         for key in keyword:
#             if key in line and 'cmd.exe /C' not in line and 'wordpad' not in line:
#                 flag = True
#                 break
#         x = line.rfind('/')
#         s_list = list(line)
#         s_list.insert(x,' is_warn=' + str(flag))
#         s = ''.join(s_list)
#         o.write(s)
#     else:
#         o.write(line)

# o.close()

# dataset = 'hw20'


# f = open(dataset + '/benign-add.txt',errors='ignore')

# o = open(dataset + '/labeled-benign-add.txt','w')


# for line in f:
#     if 'Process/Start' in line:
#         x = line.rfind('/')
#         s_list = list(line)
#         s_list.insert(x,' is_warn=False')
#         s = ''.join(s_list)
#         o.write(s)
#     else:
#         o.write(line)

# o.close()
# f1 = open(dataset + '/labeled-benign3.txt', errors='ignore')
# cnt = 0
# for i in f1:
#     cnt += 1
# print('benign3:',cnt) 

# f1 = open(dataset + '/anomaly.txt', errors='ignore')
# cnt = 0
# for i in f1:
#     cnt += 1
# print('anomaly:',cnt) 
# f1 = open(dataset + '/benign.json')
# f1 = open(dataset + '/benign2G.json')
# cnt1 = 0
# for i in f1:
#     cnt1 += 1
# print(cnt1) 
# f2 = open(dataset + '/anomaly.json')
# cnt2 = 0
# for i in f2:
#     cnt2 += 1
# print(cnt2) 

# print(cnt1 + cnt2)




