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
        self.counter = 0
        self.server = "www.baidu.com"
        self.engine = 'baidu'
        self.per_page_num=10
        self.error=None
        self.url = None

    def init_url(self):
        pass

    def do_search(self):
        try:
            self.init_url()
            r = requests.get(self.url, timeout=10)
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
        self.limit = limit
        self.counter = start
        self.proxies = proxy
        self.per_page_num = 100
        self.engine='google'

    def init_url(self):

        self.url = "http://" + self.server + "/search?num=" + str(self.per_page_num) + "&start=" + str(
                self.counter) + "&hl=en&meta=&q=%40\"" + self.word + "\""

class search_crt(searchBase):
    def __init__(self, word=None, limit=1, start=1, proxy=None):
        self.word = word
        self.results = ""
        self.total_results = ""
        self.server = "crt.sh"
        self.limit = limit
        self.counter = start
        self.proxies = proxy
        self.per_page_num = 1
        self.engine='crt'

    def init_url(self):
        self.url = "https://" + self.server + "/?q=%25." + str(self.word)

class search_so(searchBase):
    def __init__(self, word=None, limit=1000, start=0, proxy=None):
        self.word = word
        self.results = ""
        self.total_results = ""
        self.server = "www.so.com"
        self.limit = limit
        self.counter = start
        self.proxies = proxy
        self.per_page_num = 10
        self.engine = 'so.com'

    def init_url(self):
        self.url = "http://" + self.server + "/s?q=%40" + self.word + "&pn=" + str(
            self.counter/self.per_page_num)

class search_process(Base):
    def __init__(self,num_threads,doamin):
        self.pool=ThreadPool(num_threads)
        self.domain=doamin
        self.results=""
        self.hosts=None
        self.email=None
        pass

    def get_emails(self):
        rawres = myparser.parser(self.results, self.domain)
        # self.print_good("%s email(s) found in %s" % (len(rawres.emails()),self.engine))
        #print "%s email(s) found in %s" % (len(rawres.emails()),self.engine)
        return rawres.emails()

    def get_hostnames(self):
        rawres = myparser.parser(self.results, self.domain)
        # self.print_good("%s domain(s) found in %s" %(len(rawres.hostnames()),self.engine))
        #print "%s domain(s) found in %s" %(len(rawres.hostnames()),self.engine)
        return rawres.hostnames()

    def do_search(self,url,timeout=3):
        try:
            results=[]
            self.print_info('search in %s' % url)
            r = requests.get(url, timeout=timeout)
            results.append(r.content)
            return results

        except Exception,e:
            self.print_error(str(e.message))
            return None
    def exit_brute(self,pool):
        self.print_error("You have pressed Ctrl-C. Saving found records.")
        self.print_info("Waiting for {0} remaining threads to finish.".format(pool.count()))
        pool.wait_completion()

    def run(self):
        try:
            urls=self.create_url(self.domain)
            for u in urls:
                self.pool.add_task(self.do_search,u,10)
            self.pool.wait_completion()
            self.results=""
            while (self.pool.result.empty() is not True):
                self.results+=self.pool.result.get()
                pass
            self.hosts=self.unique(self.get_hostnames())
            self.email=self.unique(self.get_emails())
            print self.hosts
            print self.email

        except (KeyboardInterrupt):
            self.exit_brute(self.pool)


    def create_url(self,word):
        try:
            urls=[]
            #baidu
            counter = 0
            while (counter <=500):
                url = "http://www.baidu.com"  + "/s?wd=%40" + word + "&pn=" + str(
                counter)
                counter+=10
                urls.append(url)
            #bing
            counter = 0
            while (counter<=500):
                url = "http://cn.bing.com"  + "/search?q=%40" + word + "&count=50&first=" + str(counter)
                counter += 50
                urls.append(url)
            #yahoo
            counter = 0
            while (counter <= 500):
                url = "http://search.yahoo.com" +"/search?p=\"%40" + word + "\"&b=" + str(counter)+"&pz=50"
                counter += 50
                urls.append(url)
            #google
            counter = 0
            while (counter <= 500):
                url = "http://www.google.com"  + "/search?num=50" + "&start=" + str(
                    counter) + "&hl=en&meta=&q=%40\"" + word + "\""
                counter += 50
                urls.append(url)
            #so.com
            counter = 0
            while (counter <= 500):
                url = "http://www.so.com" + "/s?q=%40" + word + "&pn=" + str(
                counter/10)
                counter += 10
                urls.append(url)
            url = "https://crt.sh/?q=%25." + str(word)
            urls.append(url)
            return urls
        except Exception,e:
            self.print_error(e.message)
            return 'error'


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
    tmp=search_process(20,'baidu.com')
    tmp.run()
    # tmp =search_crt(word='baidu.com')
    # tmp.process()
    # results = tmp.get_hostnames()
    # print results

