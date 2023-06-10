import pandas as pd
import json
from config.mgr_config import EVENTS, COMPARE_KEY
from config.realAPT_config import APTLOG


def read_jsonline_as_json_list(path):
    """
    read a file where every line is a json into a json list
    :param path: file path of file(.json or .txt)
    :return: json list
    """
    json_list = []

    with open(path, 'r', encoding='utf8') as f:

        while True:
            line = f.readline()
            if line:
                json_list.append(json.loads(line))
            else:
                break
    return json_list


def get_one_host_org_log(file_path, ips):
    json_list = read_jsonline_as_json_list(file_path)
    org_logs = []
    log_id = 0
    for j in json_list:
        if j['host_ip'] not in ips:
            continue
        if 'message' not in j and 'org_log' not in j['message']:
            print("log have no org log ！")
            continue
        j['message']['org_log']['log_id'] = log_id
        j['message']['org_log']['is_warn'] = False
        org_logs.append(j['message']['org_log'])
        log_id += 1
    return org_logs

def get_compare_org(org):
    if isinstance(org, list):
        c_org_list = []
        for o in org:
            c_org = get_compare_org(o)
            c_org_list.append(c_org)
        return c_org_list
    if isinstance(org, dict):
        c_org = dict()
        o = org
        if COMPARE_KEY.event_id in o:
            c_org[COMPARE_KEY.event_id] = o[COMPARE_KEY.event_id]
        # if COMPARE_KEY.ppguid in o:
        #     c_org[COMPARE_KEY.ppguid] = o[COMPARE_KEY.ppguid]
        if COMPARE_KEY.pppath in o:
            c_org[COMPARE_KEY.pppath] = o[COMPARE_KEY.pppath]
        # if COMPARE_KEY.ppmd5 in o:
        #     c_org[COMPARE_KEY.ppmd5] = o[COMPARE_KEY.ppmd5]
        if COMPARE_KEY.ppcommand in o:
            c_org[COMPARE_KEY.ppcommand] = o[COMPARE_KEY.ppcommand]
        # if COMPARE_KEY.puser in o:
        #     c_org[COMPARE_KEY.puser] = o[COMPARE_KEY.puser]
        # if COMPARE_KEY.ppuser in o:
        #     c_org[COMPARE_KEY.ppuser] = o[COMPARE_KEY.ppuser]
        # if COMPARE_KEY.pguid in o:
        #     c_org[COMPARE_KEY.pguid] = o[COMPARE_KEY.pguid]
        if COMPARE_KEY.pfilepath in o:
            c_org[COMPARE_KEY.pfilepath] = o[COMPARE_KEY.pfilepath]
        # if COMPARE_KEY.pmd5 in o:
        #     c_org[COMPARE_KEY.pmd5] = o[COMPARE_KEY.pmd5]
        if COMPARE_KEY.pcommand in o:
            c_org[COMPARE_KEY.pcommand] = o[COMPARE_KEY.pcommand]
        # if COMPARE_KEY.pid in o:
        #     c_org[COMPARE_KEY.pid] = o[COMPARE_KEY.pid]
        if COMPARE_KEY.protocol in o:
            c_org[COMPARE_KEY.protocol] = o[COMPARE_KEY.protocol]
        if COMPARE_KEY.srcip in o:
            c_org[COMPARE_KEY.srcip] = o[COMPARE_KEY.srcip]
        if COMPARE_KEY.srcport in o:
            c_org[COMPARE_KEY.srcport] = o[COMPARE_KEY.srcport]
        if COMPARE_KEY.dstip in o:
            c_org[COMPARE_KEY.dstip] = o[COMPARE_KEY.dstip]
        if COMPARE_KEY.dstport in o:
            c_org[COMPARE_KEY.dstport] = o[COMPARE_KEY.dstport]
        if COMPARE_KEY.dnsqname in o:
            c_org[COMPARE_KEY.dnsqname] = o[COMPARE_KEY.dnsqname]
        if COMPARE_KEY.dnsanswers in o:
            c_org[COMPARE_KEY.dnsanswers] = o[COMPARE_KEY.dnsanswers]
        if COMPARE_KEY.dnsstatus in o:
            c_org[COMPARE_KEY.dnsstatus] = o[COMPARE_KEY.dnsstatus]
        if COMPARE_KEY.filename in o:
            c_org[COMPARE_KEY.filename] = o[COMPARE_KEY.filename]
        return c_org


def get_apt_org_log_and_label_warn(org_path, warn_path, attacked_ip):
    json_list = read_jsonline_as_json_list(org_path)
    org_logs = []
    for j in json_list:
        if j['host_ip'] not in attacked_ip:
            continue
        if 'message' not in j and 'org_log' not in j['message']:
            print("log have no org log ！")
            continue
        org_logs.append(j['message']['org_log'])
    org_json_list = org_logs
    warn_json_list = read_jsonline_as_json_list(warn_path)
    warn_json_list = [j['org_log'] for j in warn_json_list]
    warn_json_list = get_compare_org(warn_json_list)
    warn_json_list = [str(org)for org in warn_json_list]
    log_id = 0
    org_logs = []
    for org in org_json_list:
        if str(get_compare_org(org)) in warn_json_list:
            org["is_warn"] = True
        else:
            org["is_warn"] = False
        org["log_id"] = log_id
        org_logs.append(org)
        log_id += 1
    return org_logs

def get_log4j_org_log_and_label_warn(org_path, warn_path):
    org_json_list = read_jsonline_as_json_list(org_path)
    org_json_list = [org['org_log'] for org in org_json_list]
    warn_json_list = read_jsonline_as_json_list(warn_path)
    warn_json_list = [org['org_log'] for org in warn_json_list]
    warn_json_list = get_compare_org(warn_json_list)
    warn_json_list = [str(j) for j in warn_json_list]
    log_id = 0
    org_logs = []
    for org in org_json_list:
        if str(get_compare_org(org)) in warn_json_list:
            org["is_warn"] = True
        else:
            org["is_warn"] = False
        org["log_id"] = log_id
        org_logs.append(org)
        log_id += 1
    return org_logs


def write_org_log_to_json(org_logs, out_file):
    with open(out_file, 'w', encoding='utf8') as f:
        for log in org_logs:
            f.write(json.dumps(log) + '\n')


def read_org_log_from_json(file_path):
    Sysmon_Log = pd.read_json(file_path, orient='columuns', lines=True)
    print('Completed: load', file_path)
    # Sysmon_Log = pd.DataFrame(Sysmon_Log, columns=attributes)
    Sysmon_Log = Sysmon_Log[Sysmon_Log['event_id'].isin(EVENTS)]
    print('Selected events in :', EVENTS)
    # Sysmon_Log = Sysmon_Log.applymap(lambda s: s.lower() if type(s) == str else s)
    Sysmon_Log = Sysmon_Log.drop_duplicates()
    print('Completed: drop duplicated records from sysmon log')
    Sysmon_Log = Sysmon_Log.fillna("None")
    print('Completed: padding missing records as None')
    return Sysmon_Log

def read_realapt_log_from_json(file_path):
    Sysmon_Log = pd.read_json(file_path, orient='columuns', lines=True)
    print('Completed: load', file_path)
    # print(Sysmon_Log)
    # Sysmon_Log = pd.DataFrame(Sysmon_Log, columns=attributes)
    Sysmon_Log = Sysmon_Log[Sysmon_Log['evt.type'].isin(APTLOG)]
    print('Selected events in :', APTLOG)
    # print(Sysmon_Log)
    # Sysmon_Log = Sysmon_Log.applymap(lambda s: s.lower() if type(s) == str else s)
    Sysmon_Log = Sysmon_Log.drop_duplicates()
    print('Completed: drop duplicated records from sysmon log')
    # print(Sysmon_Log)
    Sysmon_Log = Sysmon_Log.fillna("None")
    print('Completed: padding missing records as None')
    # print(Sysmon_Log)
    return Sysmon_Log


def read_sysmon_log(filepath='', attributes=[]):
    # -------
    # Function definition: 'read_sysmon_log':
    # (1) read 'sysmon_log'.json
    # (2) select required attributes of sysmon_log.json
    # (3) remove duplicated records
    # (4) padding missing records as 0
    # -------
    # Required parameters:
    # (1) 'filepath' (string): file path of a targeted sysmon_log.json
    # (2) 'attributes' (list): a list of selected attributes from sysmon_log,json, such as 'ProcessId','ProcessGuid'
    # -------
    # Return: a DataFrame of sysmon_log.json
    # --------
    Sysmon_Log = pd.read_json(filepath, orient='columuns')
    print('Completed: load', filepath)
    Sysmon_Log = pd.DataFrame(Sysmon_Log, columns=attributes)
    print('Selected attributes:', list(Sysmon_Log))
    Sysmon_Log = Sysmon_Log.applymap(lambda s: s.lower() if type(s) == str else s)
    Sysmon_Log = Sysmon_Log.drop_duplicates()
    print('Completed: drop duplicated records from sysmon log')
    Sysmon_Log = Sysmon_Log.fillna(0)
    print('Completed: padding missing records as 0')
    return Sysmon_Log


def select_unique_records(sysmon_log='', attribute=''):
    # -------
    # Function definition: 'select_unique_records':
    # (1) select unique records that only appeare once under an attribute (sysmon_log['attribute'])
    # -------
    # Required parameters:
    # (1) 'sysmon_log' (DataFrame): a DataFrame of sysmon_log.json
    # (2) 'attribute' (string): an attribute from the input sysmon_log
    # -------
    # Return: a list of unique records
    # -------
    return list(filter(None, sysmon_log[attribute].unique()))
