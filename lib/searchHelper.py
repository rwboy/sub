import httplib
import sys
import myparser
import time
from base import Base
import  requests
import os

from tasks import ThreadPool
from lib.dnshelper import DnsHelper

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
result_path = os.path.join(BASE_DIR, 'result')

class searchBase(Base):

    def __init__(self, word=None, limit=1000,start=None,proxy=None):
        self.word = word
        self.limit = int(limit)
        self.total_results = ""
        self.proxy = proxy
        self.userAgent = "(Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6"
        self.counter = 0
        self.server = "www.baidu.com"
        self.hostname = "www.baidu.com"
        self.baseurl = "/s?wd=%40"
        self.engine = 'baidu'
        self.per_page_num=10
        self.error=None
        self.url = None

    def init_url(self):
        pass

    def do_search(self):
        try:
            self.init_url()
            r = requests.get(self.url, timeout=3)
            self.results = r.content
            self.total_results += self.results
        except Exception,e:
            self.error = e
            return 'error'
            pass

    def process(self):
        while self.counter <= self.limit and self.counter <= 1000:
            tmp=self.do_search()
            if tmp == 'error':
                self.print_error("\tSearching " + str(self.counter) + " results time out in %s" % self.engine)
                self.counter += self.per_page_num
                continue
            time.sleep(0.1)
            self.print_info( "\tSearching " + str(self.counter) + " results...in %s"%self.engine)
            self.counter += self.per_page_num

    def get_emails(self):
        rawres = myparser.parser(self.total_results, self.word)
        self.print_good("%s email(s) found in %s" % (len(rawres.emails()),self.engine))
        #print "%s email(s) found in %s" % (len(rawres.emails()),self.engine)
        return rawres.emails()

    def get_hostnames(self):
        rawres = myparser.parser(self.total_results, self.word)
        self.print_good("%s domain(s) found in %s" %(len(rawres.hostnames()),self.engine))
        #print "%s domain(s) found in %s" %(len(rawres.hostnames()),self.engine)
        return rawres.hostnames()

class search_baidu(searchBase):

    def init_url(self):
        self.url = "http://" + self.server + "/s?wd=%40" + self.word + "&pn=" + str(
            self.counter)

class search_bing(searchBase):

    def __init__(self, word=None, limit=1000):
        self.word = word.replace(' ', '%20')
        self.results = ""
        self.total_results = ""
        self.server = "cn.bing.com"
        self.hostname = "cn.bing.com"
        self.userAgent = "(Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6"
        self.quantity = "10"
        self.limit = int(limit)
        self.counter = 0
        self.engine='bing'
        self.per_page_num = 50
        self.error=None

    def init_url(self):
        self.url = "http://" + self.server + "/search?q=%40" + self.word + "&count=50&first=" + str(self.counter)

class search_yahoo(searchBase):

    def __init__(self, word=None, limit=500):
        self.word = word
        self.total_results = ""
        self.server = "search.yahoo.com"
        self.hostname = "search.yahoo.com"
        self.userAgent = "(Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6"
        self.limit = limit
        self.counter = 0
        self.engine='yahoo'
        self.per_page_num = 50
        self.error=None

    def init_url(self):
        self.url = "http://" + self.server + "/search?p=\"%40" + self.word + "\"&b=" + str(self.counter)+"&pz=50"


class search_google(searchBase):
    def __init__(self, word=None, limit=1000, start=0, proxy=None):
        self.word = word
        self.results = ""
        self.total_results = ""
        self.server = "www.google.com"
        self.userAgent = "(Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6"
        self.quantity = "100"
        self.limit = limit
        self.counter = start
        self.proxies = proxy
        self.per_page_num = 100
        self.engine='google'

    def init_url(self):
        self.url = "http://" + self.server + "/search?num=" + self.quantity + "&start=" + str(
                self.counter) + "&hl=en&meta=&q=%40\"" + self.word + "\""



class check:
    def test_baidu(self):
        tmp = search_baidu(word='cuit.edu.cn')
        tmp.process()
        all_emails = tmp.get_emails()
        all_hosts = tmp.get_hostnames()
        print all_hosts
        print all_emails
        pass
    def test_bing(self):
        tmp = search_bing(word='cuit.edu.cn')
        tmp.process()
        all_emails = tmp.get_emails()
        all_hosts = tmp.get_hostnames()
        print all_hosts
        print all_emails
        pass
    def test_yahoo(self):
        tmp = search_yahoo(word='cuit.edu.cn')
        tmp.process()
        all_emails = tmp.get_emails()
        all_hosts = tmp.get_hostnames()
        print all_hosts
        print all_emails
    def test_google(self):
        tmp = search_google(word='cuit.edu.cn')
        tmp.process()
        all_emails = tmp.get_emails()
        all_hosts = tmp.get_hostnames()
        print all_hosts
        print all_emails

class searchSub(Base):

    def __init__(self,domain=None,filename=None,verbose=True,thread_num=20):
        self.domain=domain
        if filename is None:
            self.filename=self.domain+'.csv'
        else:
            self.filename=filename
        self.pool=ThreadPool(thread_num,filename)
        self.task = None
        self.verbose = verbose
        self.res = DnsHelper(domain)
        self.thread_num = thread_num
        self.pool = ThreadPool(self.thread_num,self.filename)
        self.error=None
        self.result_hosts=[]
        self.result_email=[]

    def do_search(self):
        try:
            #baidu
            tmp =search_baidu(word=self.domain)
            tmp.process()
            all_hosts=tmp.get_hostnames()
            self.result_hosts.extend(all_hosts)
            all_email=tmp.get_emails()
            self.result_email.extend(all_email)

            #bing
            tmp = search_bing(word=self.domain)
            tmp.process()
            all_hosts = tmp.get_hostnames()
            self.result_hosts.extend(all_hosts)
            all_email = tmp.get_emails()
            self.result_email.extend(all_email)

            #google
            tmp = search_google(word=self.domain)
            tmp.process()
            all_hosts = tmp.get_hostnames()
            self.result_hosts.extend(all_hosts)
            all_email = tmp.get_emails()
            self.result_email.extend(all_email)

            #yahoo
            tmp = search_yahoo(word=self.domain)
            tmp.process()
            all_hosts = tmp.get_hostnames()
            self.result_hosts.extend(all_hosts)
            all_email = tmp.get_emails()
            self.result_email.extend(all_email)

            self.result_hosts=self.unique(self.result_hosts)
            self.result_email=self.unique(self.result_email)
            email=self.filename+'_email.csv'
            email_name=os.path.join(result_path,email)
            with open(email_name,'wb') as f:
                for x in self.result_email:
                    f.write(x)
                    f.write('\n')
                    pass
            try:
                for x in self.result_hosts:
                    target=x.strip()
                    self.pool.add_task(self.res.get_ip,target)
                self.pool.wait_completion()
            except (KeyboardInterrupt):
                self.exit_search(self.pool)
        except Exception,e:
            self.error=e
            pass
    def unique(self,list):
        self.new = []
        for x in list:
            if x not in self.new:
                self.new.append(x)
        return self.new

    def exit_search(self, pool):
        self.print_error("You have pressed Ctrl-C. Saving found records.")
        self.print_info("Waiting for {0} remaining threads to finish.".format(pool.count()))
        pool.wait_completion()
def test_search(domain,filename=None):
    tmp = searchSub(domain=domain,filename=filename)
    tmp.do_search()


if __name__ == '__main__':
    tmp = searchSub(domain='cuit.edu.cn')
    tmp.do_search()
    tmp=check()
    tmp.test_google()


