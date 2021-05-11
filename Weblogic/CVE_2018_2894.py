#!/usr/bin/env python3
# _*_ coding:utf-8 _*_
'''
 ____       _     _     _ _   __  __           _
|  _ \ __ _| |__ | |__ (_) |_|  \/  | __ _ ___| | __
| |_) / _` | '_ \| '_ \| | __| |\/| |/ _` / __| |/ /
|  _ < (_| | |_) | |_) | | |_| |  | | (_| \__ \   <
|_| \_\__,_|_.__/|_.__/|_|\__|_|  |_|\__,_|___/_|\_\

'''
import logging
import sys
import requests


VUL=['CVE-2018-2894']
headers = {'user-agent': 'ceshi/0.0.1'}

def islive(url,port):
    url='http://' + str(url)+':'+str(port)+'/ws_utc/resources/setting/options/general'
    r = requests.get(url, headers=headers)
    return r.status_code

def run(url,port,index):
    if islive(url,port)!=404:
        url='http://' + str(url)+':'+str(port)+'/ws_utc/begin.do'
        url1='http://' + str(url)+':'+str(port)+'/ws_utc/config.do'
        print('[?]The target weblogic maybe has a JAVA deserialization vulnerability:{}'.format(VUL[index]))
        print('[+]URL links：{}'/format(url))
        print('[+]URL links：{}'/format(url1))
    else:
        print('[-]Target weblogic not detected {}'.format(VUL[index]))

if __name__=="__main__":
    url = sys.argv[1]
    port = int(sys.argv[2])
    run(url,port,0)
