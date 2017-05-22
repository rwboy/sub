from lib.searchHelper import test_search,searchSub
from lib.subBrute import test_sub,subBruteBase
from lib.subBrute import test_ds_walk
import os
from lib.base import Base
import csv
import argparse
import sys
import optparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
dict_path = os.path.join(BASE_DIR, 'dict')
result_path = os.path.join(BASE_DIR, 'result')




class Begin(Base):

    def __init__(self):
        self.option={}
        self.domain = None
        self.dict = None
        self.verbose = None
        self.filename = None
        self.thread = None
        pass

    def init_file(self):
        with open(self.file_result,'wb') as f:
            list=['Type','Name','Address','Target','Port','String']
            writer=csv.writer(f)
            writer.writerow(list)
            f.close()

    def GetCmdOptions(self):
        parser = optparse.OptionParser(usage="%prog [options] args", version=r"%prog 1.0")
        try:

            parser.add_option("-d", "--domain", dest="domain",
                              help="the target domain")
            parser.add_option('-D',"--dictionary", dest="dictionary", help="the dictionary includes subdomain that we want to brute")
            parser.add_option("-o", "--result-file", dest="result_filename", help="the file that saving my results ")
            parser.add_option("-v", "--verbose", action="store_true", dest="verbose", help="detail output mode")
            parser.add_option("-t", "--thread", dest="thread", help="define the thread num of brute", default=20)
            (options, args) = parser.parse_args()
            self.option['domain'] = options.domain
            self.option['dict'] = options.dictionary
            self.option['filename'] = options.result_filename
            self.option['verbose'] = options.verbose
            self.option['thread'] = options.thread
            self.domain = self.option['domain']
            self.dict = self.option['dict']
            self.verbose = self.option['verbose']
            self.filename = self.option['filename']
            self.thread = int(self.option['thread'])
            if self.is_domain(self.domain):
                pass
            else:
                self.print_error('please check the domain args!')
                parser.print_help()
                sys.exit(0)
        except Exception,e:
            self.print_error(e.message)
            parser.print_help()
            sys.exit(0)

    def run(self):
        try:
            self.GetCmdOptions()
            if self.is_domain(self.domain):
                if self.dict is None:
                    self.dict = os.path.join(dict_path, 'subnames_full.txt')
                if self.filename is None:
                    self.filename = self.domain + '.csv'
                self.file_result = os.path.join(result_path, self.filename)
                self.init_file()
                tmp = searchSub(domain=self.domain, filename=self.filename,verbose=self.verbose,thread_num=self.thread)
                tmp.do_search()
                tmp = subBruteBase(self.domain, dict=self.dict, filename=self.filename,verbose=self.verbose,thread_num=self.thread)
                tmp.run()
                self.print_info('starting removing duplicate records')
                tmp=self.unique_file()
                if tmp !='error':
                    self.print_good('removing duplicate records sucessful!')
                    self.print_info('saving {0} records the result at {1}' % (tmp,self.file_result))
                else:
                    self.print_error('removing duplicate records error!')
            else:
                self.print_error('please check the domain args!')
        except Exception,e:
            self.print_error(e.message)
            pass

    def unique_file(self):
        try:
            csvfile=open(self.file_result,'rb')
            reader = csv.reader(csvfile)
            new =[]
            for line in reader:
                if line not in new:
                    new.append(line)
            csvfile.close()
            csvfile=open(self.file_result,'wb')
            writer = csv.writer(csvfile)
            for line in new:
                writer.writerow(line)
            csvfile.close()
            return len(new)
        except Exception,e:
            self.print_error(e.message)
            return 'error'


if __name__=="__main__":
    tmp=Begin()
    tmp.run()