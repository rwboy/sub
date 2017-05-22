
from __future__ import print_function


import random
import re

import string

from printers import print_green, print_pink,print_red,print_blue


class Base:

    def __init__(self):
        self.target=None
        self.result=None
        self.error=None
        self.time_out=None

    def print_info(self, msg):
        print_blue(msg)

    def print_error(self, msg):
        print_red(msg)

    def print_good(self, msg):
        print_green(msg)

    def print_debug(self,msg):
        print_pink(msg)

    def to_unicode_str(self, obj, encoding='utf-8'):
        # checks if obj is a string and converts if not
        if not isinstance(obj, basestring):
            obj = str(obj)
        obj = self.to_unicode(obj, encoding)
        return obj

    def to_unicode(self, obj, encoding='utf-8'):
        # checks if obj is a unicode string and converts if not
        if isinstance(obj, basestring):
            if not isinstance(obj, unicode):
                obj = unicode(obj, encoding)
        return obj

    def is_hash(self, hashstr):
        hashdict = [
            {'pattern': '[a-fA-F0-9]', 'len': 32, 'type': 'MD5'},
            {'pattern': '[a-fA-F0-9]', 'len': 16, 'type': 'MySQL'},
            {'pattern': '^\*[a-fA-F0-9]', 'len': 41, 'type': 'MySQL5'},
            {'pattern': '[a-fA-F0-9]', 'len': 40, 'type': 'SHA1'},
            {'pattern': '[a-fA-F0-9]', 'len': 56, 'type': 'SHA224'},
            {'pattern': '[a-fA-F0-9]', 'len': 64, 'type': 'SHA256'},
            {'pattern': '[a-fA-F0-9]', 'len': 96, 'type': 'SHA384'},
            {'pattern': '[a-fA-F0-9]', 'len': 128, 'type': 'SHA512'},
            {'pattern': '^\$[PH]{1}\$', 'len': 34, 'type': 'phpass'},
        ]
        for hashitem in hashdict:
            if len(hashstr) == hashitem['len'] and re.match(hashitem['pattern'], hashstr):
                return hashitem['type']
        return False

    def get_random_str(self, length):
        return ''.join(random.choice(string.lowercase) for i in range(length))

    def is_domain(self,string):
        pat="(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}\.?$)"
        if string is None:
            return False
        tmp=re.match(pat,string)
        if tmp is not None:
            return True
        else:
            return False

    def unique(self, list):
        self.new = []
        for x in list:
            if x not in self.new:
                self.new.append(x)
        return self.new