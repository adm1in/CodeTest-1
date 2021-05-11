import sys,importlib,glob,os
sys.path.append('../')
#from concurrent.futures import ThreadPoolExecutor,wait,as_completed,ALL_COMPLETED
from ClassCongregation import _urlparse
from CodeTest import color,now

vuln_scripts = []
exp_scripts = []
for _ in glob.glob('EXP/*.py'):
    script_name = os.path.basename(_).replace('.py', '')
    if script_name != 'ALL' and script_name != '__init__':
        vuln_name = importlib.import_module('.%s'%script_name,package='EXP')
        exp_scripts.append(script_name)
        vuln_scripts.append(vuln_name)

def check(**kwargs):
    now.timed(de = 0)
    color ("[+] Scanning target domain "+kwargs['url'], 'green')
    #批量调用
    for index in range(len(vuln_scripts)):
        try:
            vuln_scripts[index].check(**kwargs)
        except Exception as e:
            now.timed(de=0)
            color ("[-] Running {} occured error!!!".format(exp_scripts[index]), 'yellow')
            continue
    #executor = ThreadPoolExecutor(max_workers = 3)
    #for data in executor.map(lambda kwargs: check(**kwargs),vuln_scripts):
    #    pass