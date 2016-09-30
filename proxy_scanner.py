#!/usr/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'leohuang'
__date__ = '2016/9/21'
__version__ = '0.1-dev'

import sys
import time
import signal
import threading
from multiprocessing.dummy import Pool
import requesocks as requests

lock = threading.Lock()
threadpool = Pool(processes=40)
TIMEOUT = 3
scan_results = []

def signal_handler(signal, frame):
    print "Ctrl+C pressed.. aborting..."
    threadpool.terminate()
    threadpool.done = True

def handle_result(host, port, result):
    tm = time.time()
    with lock:
        scan_results.append([host, port, result])

def proxy_scan(*kw):
    if len(*kw) == 2:
        proxy_type, proxy_netloc = kw[0][0], kw[0][1]
    else:
        return

    ip_url = "http://ipinfo.io/ip"
    proxy_str = "%s://%s" %(proxy_type, proxy_netloc)
    set_proxies = {'http': proxy_str,}

    try:
        r = requests.get(ip_url, proxies=set_proxies, timeout=TIMEOUT)
        ip_length = 0
        rtn_ip = str(r.text).strip()
        if len(rtn_ip)>0 and rtn_ip==proxy_netloc.split(":")[0]:
            desc = "curl %s %s %s" %("-x" if proxy_type=='http' else "--socks5-hostname", proxy_netloc, ip_url)
            handle_result(proxy_netloc, proxy_type, desc)
            #print [True, 'OK']
        #else:
        #    print [False, ["Not Match"] + rtn_ip]

    except Exception,e:
        pass
        #print [False, "[Request Error]" + str(e) ]


def proxy_file_scan(check_file, result_file="result_proxy.txt"):
    check_type_list = ["http", "socks5"]
    scan_list = []

    print "[-]Begin Proxy Scan"
    with open(check_file) as f:
        for line in f:
            netloc = line.strip()
            if not netloc:
                continue

            for check_type in check_type_list:
                scan_list.append([check_type, netloc])

    task = threadpool.map(proxy_scan, scan_list)
    threadpool.close()
    threadpool.join()

    if result_file:
        with open(result_file, 'w') as f:
            for x in scan_results:
                proxy_netloc, proxy_type, desc = x
                rs = "%s\t%s\t%s" %(proxy_netloc, proxy_type, desc)
                print rs
                f.write("%s\n" %(rs))


if __name__ == "__main__":
    netlocfile = "netloc.txt"
    if len(sys.argv)<2:
        print """Usage:%s netlocfile(default:netloc.txt) resultfile(default:result_proxy.txt)""" % (sys.argv[0])
        proxy_file_scan(netlocfile)
        sys.exit()
    proxy_file_scan(sys.argv[1])
