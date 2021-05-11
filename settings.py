from tkinter import StringVar,IntVar
import threading,os,sys

###获取项目路径###
curPath = os.path.dirname(os.path.realpath(sys.executable))#当前执行路径
scriptPath = os.getcwd()

#代理界面_Proxy
Proxy_type = StringVar(value='SOCKS5')#代理界面_代理类型_SOCKS5
Proxy_CheckVar1 = IntVar()#代理界面_控制代理开关1
Proxy_CheckVar2 = IntVar()#代理界面_控制代理开关0
Proxy_addr = StringVar(value='127.0.0.1')#代理界面_代理IP
Proxy_port = StringVar(value='8080')#代理界面_代理端口

#漏洞扫描界面_A
Ent_A_Top_thread = StringVar(value='3')#漏洞扫描界面_顶部_线程_3
Ent_A_Top_Text = '''[*]请输入正确的网址,比如 [http://www.baidu.com]
[*]请注意有些需要使用域名, 有些需要使用IP!
[*]漏洞扫描模块是检测漏洞的, 命令执行需要在漏洞利用模块使用!
[-]有处BUG, 在读取py文件时, 如果引号前面有字母存在会出错, 如 f'', r''
'''

#漏洞利用界面_B
Ent_B_Top_url = StringVar(value='')#漏洞利用界面_顶部_目标地址
Ent_B_Top_cookie = StringVar(value='暂时无用')#漏洞利用界面_顶部_Cookie
Ent_B_Top_vulname = StringVar(value='请选择漏洞名称')#漏洞利用界面_顶部_漏洞名称_请选择漏洞名称
Ent_B_Top_vulmethod = StringVar(value='ALL')#漏洞利用界面_顶部_调用方法_ALL
Ent_B_Top_funtype = StringVar(value='False')#漏洞利用界面_顶部_exp功能_False
Ent_B_Top_timeout = StringVar(value='3')#漏洞扫描界面_顶部_超时时间_3
Ent_B_Bottom_Left_cmd = StringVar()#漏洞利用界面_底部_CMD命令输入框

#漏洞测试界面_C
Ent_C_Top_url = StringVar(value='http://www.baidu.com')#漏洞测试界面_顶部_目标地址
Ent_C_Top_reqmethod = StringVar(value='GET')#漏洞测试界面_顶部_请求方法类型_GET
Ent_C_Top_vulname = StringVar(value='用作类名, 不能包含空格')#漏洞测试界面_顶部_脚本名称
Ent_C_Top_cmsname = StringVar(value='')#漏洞测试界面_顶部_CMS名称
Ent_C_Top_cvename = StringVar(value='cve_')#漏洞测试界面_顶部_CVE编号
Ent_C_Top_version = StringVar(value='202104_hww_')#漏洞测试界面_顶部_版本信息
Ent_C_Top_info = StringVar(value='命令执行描述')#漏洞测试界面_顶部_info_命令执行描述
Ent_C_Top_template = StringVar(value='请选择模板')#漏洞测试界面_顶部_template_请选择模板

#测试
Ent_Cmds_Top_type = StringVar()#命令控制台界面_顶部_漏洞类型
Ent_Cmds_Top_typevar = StringVar(value='yy yang haha 1 2 3 4 5 7 8 0')#命令控制台界面_顶部_漏洞类型值

#
Ent_yso_Top_type = StringVar(value='-jar')#ysoserial代码生成界面_顶部_类型
Ent_yso_Top_class = StringVar(value='利用链类')#ysoserial代码生成界面_顶部_利用链类
Ent_yso_Top_cmd = StringVar(value='whoami')#ysoserial代码生成界面_顶部_命令

#其他变量
variable_dict = {"Proxy_CheckVar1":Proxy_CheckVar1, "Proxy_CheckVar2":Proxy_CheckVar2, "PROXY_TYPE":Proxy_type, "Proxy_addr":Proxy_addr,"Proxy_port":Proxy_port}