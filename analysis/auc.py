#!/usr/bin/env python3

import json
import os
import socket
import struct
import math
import argparse
from typing import List

import matplotlib.pyplot as plt
from sklearn.metrics import roc_curve, auc
from datetime import datetime
import numpy as np

save_path = '../eval/'
save_graph_path = '../eval/figure/'

ts_datetime = datetime.now().strftime('%Y-%m-%d-%H-%M-%S-%f')[:-3]

def f_action(label, loss, sampl):
    from sklearn.metrics import f1_score, fbeta_score, precision_recall_curve
    # print(loss)
    res = [1 if sc > 6 else 0 for sc in loss]

    f1 = f1_score(label, res, average='macro')
    f2 = fbeta_score(label, res, average='macro', beta=2)
    p, r, _ = precision_recall_curve(label, res)

    sorted_index = np.argsort(p)
    p_sorted =  np.array(p)[sorted_index]
    r_sorted = np.array(r)[sorted_index]
    pr_auc = auc(p_sorted, r_sorted)

    # plt.figure()
    # plt.plot(p, r, color='firebrick',
    #          lw=1.5, label=f'AUC: {pr_auc:7.6f}')
    # plt.plot([0, 1], [0, 1], color='royalblue', lw=1, linestyle='--')
    # plt.xlim([0.0, 1.0])
    # plt.ylim([0.0, 1.05])
    # plt.xlabel('Precision')
    # plt.ylabel('Recall')
    # plt.title(f'{args.target} RoC')
    # plt.legend(loc="lower right")
    # plt.savefig(save_graph_path + tag + '_PRC.png')

    # print(f'F1-score={f1:7.6f}')
    # print(f'F2-score={f2:7.6f}')
    # print(f'AU_PRC={pr_auc:7.6f}')
    print(f'{f1:7.6f}, {f2:7.6f}, {pr_auc:7.6f}')

    f = open(f'{save_path}/{tag}-{sampl}-{ts_datetime}.txt', 'a+')
    f.write(f'F1 Score: {f1:7.6f}\n')



def analyze_action(tag: str, malicious_addr: List[str], sampl: int) -> None:

    int_malicious_addr = []
    traget_files = os.listdir(save_path + '/' + tag)

    normal = []
    abnormal = []

    for addr in malicious_addr:
        print(str(struct.unpack('!I', socket.inet_aton(addr))[0]))
        int_malicious_addr.append(struct.unpack('!I', socket.inet_aton(addr))[0])

    print('Read files from: ' + save_path + tag)
    for file in traget_files:
        with open(save_path + tag + '/' + file, 'r') as f:
            ls = json.load(f)['Results']
            try:
                for entery in ls:
                    if entery[0] in int_malicious_addr:
                        # print([*(entery[1] for _ in range(entery[2]))])
                        # print(len([*(entery[1] for _ in range(entery[2]))]))
                        abnormal.extend([*(entery[1] for _ in range(entery[2]))])
                    else:
                        normal.extend([*(entery[1] for _ in range(entery[2]))])
            except TypeError:
                continue

    print(f'Normal packets: {len(normal)}, Abnormal packets: {len(abnormal)}.')


    fpr, tpr, _ = roc_curve([*(0 for _ in range(len(normal))),
                             *(1 for _ in range(len(abnormal)))],
                            [*normal, *abnormal])
    # print(*(0 for _ in range(len(normal))))
    # print(*(1 for _ in range(len(abnormal))))
    # print([*abnormal])


    sorted_index = np.argsort(fpr)
    fpr_sorted =  np.array(fpr)[sorted_index]
    tpr_sorted = np.array(tpr)[sorted_index]
    roc_auc = auc(fpr_sorted, tpr_sorted)


    plt.figure()
    plt.plot(fpr, tpr, color='firebrick',
             lw=1.5, label=f'AUC: {roc_auc:7.6f}')
    plt.plot([0, 1], [0, 1], color='royalblue', lw=1, linestyle='--')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title(f'{tag} RoC')
    plt.legend(loc="lower right")
    plt.savefig(save_graph_path + tag + '-' + str(sampl) + '.png')

    deta = 1
    deta_fpr = 1
    deta_tpr = 1

    err = 0
    r_fpr = 0
    r_tpr = 0
    for a, b in zip(fpr, tpr):
        d = math.fabs((1 - a) - b)
        if d < deta:
            deta = d
            err = a

        d = math.fabs(a - 0.1)
        if d < deta_fpr:
            deta_fpr = d
            r_tpr = b

        d = math.fabs(b - 0.9)
        if d < deta_tpr:
            deta_tpr = d
            r_fpr = a

    print(f'[{tag}]')
    print(f'TPR={r_tpr:7.6f} (FPR=0.1)\nFPR={r_fpr:7.6f} (TPR=0.9)')
    print(f'AUC={roc_auc:7.6f}\nEER={err:7.6f}')

    print(f'{roc_auc:7.6f}, {err:7.6f}, ', end='')

    f = open(f'{save_path}/{tag}-{sampl}-{ts_datetime}.txt', 'a+')
    f.write(f'AuC: {roc_auc:7.6f}\n')

    f_action([*(0 for _ in range(len(normal))), *(1 for _ in range(len(abnormal)))], [*normal, *abnormal], sampl)

    print(r_tpr, r_fpr, roc_auc, err)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('-t', '--target', type=str, default='ALL', help='target for analysis')
    parser.add_argument('-a', '--attack', type=str, default='ALL', help='attack name')
    parser.add_argument('-s', '--sampl', type=int, default='ALL', help='sampling rate')

    args = parser.parse_args()

    if not os.path.isdir(save_path):
        os.mkdir(save_path)

    if not os.path.isdir(save_graph_path):
        os.mkdir(save_graph_path)

    with open('./address.json') as f:
        j = json.load(f)
        tag = args.target
        if tag == 'ALL':
            for tag, addr in j.items():
                if not str.isdigit(tag):
                    analyze_action(tag, addr, args.sampl)

        else:
            if tag in j:
                malicious_addr = j[tag]
            else:
                print("Target Not found.")
                exit(1)

            analyze_action(tag, malicious_addr, args.sampl)

