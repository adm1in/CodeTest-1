import random,requests,datetime,time,binascii,subprocess,re
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
from lxml import etree

class Dnslog:  # Dnslog判断
    def __init__(self):
        #该网站是通过PHPSESSID来判断dns归属谁的所以可以随机一个
        h = "abcdefghijklmnopqrstuvwxyz0123456789"
        salt_cookie = ""
        for i in range(26):
            salt_cookie += random.choice(h)
        self.headers = {
            "Cookie": "PHPSESSID="+salt_cookie
        }
        H = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        salt = ""
        for i in range(15):
            salt += random.choice(H)
        try:
            self.host = str(salt + "." + self.get_dnslog_url())
        except Exception as e:
            print(e)
            self.host=""

    def dns_host(self) -> str:
        #return test.dnslog.cn
        return str(self.host)

    def get_dnslog_url(self):
        try:
            self.dnslog_cn=requests.get("http://www.dnslog.cn/getdomain.php",headers=self.headers,timeout=6).text
            return self.dnslog_cn
        except Exception as e:
            print("[-]获取DOSLOG域名出错%s"%e)

    def result(self) -> bool:
        # DNS判断后续会有更多的DNS判断，保持准确性
        return self.dnslog_cn_dns()


    def dnslog_cn_dns(self) -> bool:
        try:
            status = requests.get("http://www.dnslog.cn/getrecords.php?t="+self.dnslog_cn,headers=self.headers,  timeout=6)
            self.dnslog_cn_text = status.text
            if self.dnslog_cn_text.find('dnslog') != -1:  # 如果找到Key
            #if self.host in self.dnslog_cn_text:  # 如果找到Key
                return True
            else:
                return False
        except Exception as e:
            print("[-]寻找%s请求记录时出错"%self.dnslog_cn, e)

    def dns_text(self):
        return self.dnslog_cn_text

class Sql_scan:# sql判断
    rules_dict = {}
    def __init__(self, headers, TIMEOUT):
        self.conn = requests.session()
        self.headers = headers
        self.TIMEOUT = TIMEOUT
        self._init_rules()

    def urlopen_get(self, url):
        try:
            self.request = self.conn.get(url, headers=self.headers, timeout=self.TIMEOUT, verify=False, allow_redirects=False)
            html = self.request.text
        except requests.exceptions.Timeout as error:
            html = ''
            #CodeTest.verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            html = ''
            #CodeTest.verify.connection_output(self.pocname)
        except Exception as error:
            html = ''
            #CodeTest.verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)
        finally:
            return html

    def urlopen_post(self, url, data):
        try:
            self.request = self.conn.post(url, headers=self.headers, data=data, timeout=self.TIMEOUT, verify=False, allow_redirects=False)
            html = self.request.text
        except requests.exceptions.Timeout as error:
            html = ''
            #CodeTest.verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            html = ''
            #CodeTest.verify.connection_output(self.pocname)
        except Exception as error:
            html = ''
            #CodeTest.verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)
        finally:
            return html

    def _init_rules(self):
        #Sql_scan.rules_dict = {}
        self.tree = ET.parse('./data/error.xml')
        self.root = self.tree.getroot()
        for child in self.root:
            temp_list = []
            temp_dict = {}
            temp_list.append(child.attrib['value'])
            #child.attrib['value']
            for neighbor in child.iter('error'):
                temp_list.append(neighbor.attrib['regexp'])
                #print(neighbor.attrib['regexp'])
            temp_dict[child.attrib['value']] = temp_list
            Sql_scan.rules_dict = {**Sql_scan.rules_dict, **temp_dict}

    def check_sql_exis(self, html, regx_list):
        for regx in regx_list:
            try:
                p_status = re.compile(regx)
                _ = p_status.search(html)
                if _:
                    return 1
            except Exception as e:
                continue
        return 0

def _urlparse(url):
    return url.strip('/')
    try:
        getipport = urlparse(url)
        hostname = getipport.hostname
        port = getipport.port

        if port == None and r"https://" in url:
            port = 443

        elif port == None and r"http://" in url:
            port = 80

        if r"https://" in url:
            url = "https://"+hostname+":"+str(port)

        elif r"http://" in url:
            url = "http://"+hostname+":"+str(port)
        return url
    except Exception as e:
        return url

def random_name(index):
    h = "abcdefghijklmnopqrstuvwxyz0123456789"
    salt_cookie = ""
    for i in range(index):
        salt_cookie += random.choice(h)
    return salt_cookie

def byte_to_hex(pw):
    #pw = b'111111'
    temp = b''
    for x in pw:
        temp += binascii.a2b_hex('%02x' % int('{:08b}'.format(x)[::-1], 2))
    return temp

#使用ysoserial.jar 生成 payload
# return 'aced'
def ysoserial_payload(java_class, java_cmd, java_type='-jar'):
    command = "java {} ysoserial.jar {} \"{}\"".format(java_type,java_class,java_cmd)
    popen = subprocess.Popen(command, stdout=subprocess.PIPE ,shell=True,close_fds=True)
    out,drr = popen.communicate()
    return out
    #return binascii.hexlify(out).decode()

#github登录功能函数
def login_github(username,password):#登陆Github
    #初始化参数
    login_url = 'https://github.com/login'
    session_url = 'https://github.com/session'
    try:
        #获取session
        s = requests.session()
        resp = s.get(login_url).text
        dom_tree = etree.HTML(resp)
        key = dom_tree.xpath('//input[@name="authenticity_token"]/@value')
        user_data = {
            'commit': 'Sign in',
            'utf8': '✓',
            'authenticity_token': key,
            'login': username,
            'password': password
        }
        #发送数据并登陆
        s.post(session_url,data=user_data)
        s.get('https://github.com/settings/profile')
        return s
    except Exception as e:
        print('[-]产生异常，请检查网络设置及用户名和密码')
        #error_Record(str(e), traceback.format_exc())