#!/usr/bin/env python
# -*- coding: utf-8 -*-

__version__ = '1.0'
__author__ = 'hacker'

__doc__ = """
DNSRecon http://www.darkoperator.com

 by Carlos Perez, Darkoperator

requires dnspython http://www.dnspython.org/
requires netaddr https://github.com/drkjam/netaddr/

import argparse
"""
import os
import string
import sqlite3
import datetime

import netaddr

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

import csv
# Manage the change in Python3 of the name of the Queue Library
try:
    from Queue import Queue
except ImportError:
    from queue import Queue

from random import Random
import sys
from tasks import ThreadPool
from threading import Lock, Thread
from xml.dom import minidom
from xml.etree import ElementTree
from xml.etree.ElementTree import Element

import dns.message
import dns.query
import dns.rdatatype
import dns.resolver
import dns.reversename
import dns.zone
import dns.message
import dns.rdata
import dns.rdatatype
import dns.flags
import json
from dns.dnssec import algorithm_to_text

from lib.whois import *
from lib.dnshelper import DnsHelper
import urllib2
from base import Base

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
dict_path = os.path.join(BASE_DIR, 'dict')
result_path = os.path.join(BASE_DIR, 'result')



class subBruteBase(Base):

    def __init__(self,domain,filename=None,dict=None,verbose=True,thread_num=20):
        self.domain = domain
        self.result = []
        self.dict = dict
        self.task = None
        self.verbose=verbose
        self.res=DnsHelper(domain)
        self.thread_num=thread_num
        if filename is None:
            filename=self.domain+'.csv'
        self.pool=ThreadPool(self.thread_num,filename)
        self.result_dict = os.path.join(result_path, filename)
        pass

    def run(self):
        try:
            self.general_enum()
            self.brute_domain()

        except Exception,e:
            pass

    def init_dict(self):
        tmp_dict = {}
        tmp_dict['Type'] = 'NULL'
        tmp_dict['Name'] = 'NULL'
        tmp_dict['Address'] = 'NULL'
        tmp_dict['Target'] = self.domain
        tmp_dict['Port'] = 'NULL'
        tmp_dict['String'] = 'NULL'
        return tmp_dict

    def check_wildcard(self, domain_trg):
        """
        Function for checking if Wildcard resolution is configured for a Domain
        """
        wildcard = None
        test_name = ''.join(Random().sample(string.hexdigits + string.digits,
                                            12)) + '.' + domain_trg
        ips = self.res.get_a(test_name)

        if len(ips) > 0:
            if self.verbose:
                self.print_info('Wildcard resolution is enabled on this domain')
                self.print_info('It is resolving to {0}'.format(''.join(ips[0][2])))
                self.print_info("All queries will resolve to this address!!")
            wildcard = ''.join(ips[0][2])

        return wildcard

    def brute_tlds(self):
        """
        This function performs a check of a given domain for known TLD values.
        prints and returns a dictionary of the results.
        """
        brtdata = []

        # tlds taken from http://data.iana.org/TLD/tlds-alpha-by-domain.txt
        gtld = ['co', 'com', 'net', 'biz', 'org']
        tlds = ['ac', 'ad', 'ae', 'aero', 'af', 'ag', 'ai', 'al', 'am', 'an', 'ao', 'aq', 'ar',
                'arpa', 'as', 'asia', 'at', 'au', 'aw', 'ax', 'az', 'ba', 'bb', 'bd', 'be', 'bf', 'bg',
                'bh', 'bi', 'biz', 'bj', 'bm', 'bn', 'bo', 'br', 'bs', 'bt', 'bv', 'bw', 'by', 'bz', 'ca',
                'cat', 'cc', 'cd', 'cf', 'cg', 'ch', 'ci', 'ck', 'cl', 'cm', 'cn', 'co', 'com', 'coop',
                'cr', 'cu', 'cv', 'cx', 'cy', 'cz', 'de', 'dj', 'dk', 'dm', 'do', 'dz', 'ec', 'edu', 'ee',
                'eg', 'er', 'es', 'et', 'eu', 'fi', 'fj', 'fk', 'fm', 'fo', 'fr', 'ga', 'gb', 'gd', 'ge',
                'gf', 'gg', 'gh', 'gi', 'gl', 'gm', 'gn', 'gov', 'gp', 'gq', 'gr', 'gs', 'gt', 'gu', 'gw',
                'gy', 'hk', 'hm', 'hn', 'hr', 'ht', 'hu', 'id', 'ie', 'il', 'im', 'in', 'info', 'int',
                'io', 'iq', 'ir', 'is', 'it', 'je', 'jm', 'jo', 'jobs', 'jp', 'ke', 'kg', 'kh', 'ki', 'km',
                'kn', 'kp', 'kr', 'kw', 'ky', 'kz', 'la', 'lb', 'lc', 'li', 'lk', 'lr', 'ls', 'lt', 'lu',
                'lv', 'ly', 'ma', 'mc', 'md', 'me', 'mg', 'mh', 'mil', 'mk', 'ml', 'mm', 'mn', 'mo',
                'mobi', 'mp', 'mq', 'mr', 'ms', 'mt', 'mu', 'museum', 'mv', 'mw', 'mx', 'my', 'mz', 'na',
                'name', 'nc', 'ne', 'net', 'nf', 'ng', 'ni', 'nl', 'no', 'np', 'nr', 'nu', 'nz', 'om',
                'org', 'pa', 'pe', 'pf', 'pg', 'ph', 'pk', 'pl', 'pm', 'pn', 'pr', 'pro', 'ps', 'pt', 'pw',
                'py', 'qa', 're', 'ro', 'rs', 'ru', 'rw', 'sa', 'sb', 'sc', 'sd', 'se', 'sg', 'sh', 'si',
                'sj', 'sk', 'sl', 'sm', 'sn', 'so', 'sr', 'st', 'su', 'sv', 'sy', 'sz', 'tc', 'td', 'tel',
                'tf', 'tg', 'th', 'tj', 'tk', 'tl', 'tm', 'tn', 'to', 'tp', 'tr', 'travel', 'tt', 'tv',
                'tw', 'tz', 'ua', 'ug', 'uk', 'us', 'uy', 'uz', 'va', 'vc', 've', 'vg', 'vi', 'vn', 'vu',
                'wf', 'ws', 'ye', 'yt', 'za', 'zm', 'zw']
        found_tlds = []
        domain_main = self.domain.split(".")[0]

        # Let the user know how long it could take
        self.print_info("The operation could take up to: {0}".format(time.strftime('%H:%M:%S',
                                                                                time.gmtime(len(tlds) / 4))))

        try:
            for t in tlds:
                if self.verbose:
                    self.print_info("Trying {0}".format(domain_main + "." + t))
                self.pool.add_task(self.res.get_ip, domain_main + "." + t)
                for g in gtld:
                    if self.verbose:
                        self.print_info("Trying {0}".format(domain_main + "." + g + "." + t))
                    self.pool.add_task(self.res.get_ip, domain_main + "." + g + "." + t)

            # Wait for threads to finish.
            self.pool.wait_completion()

        except (KeyboardInterrupt):
            self.exit_brute(self.pool)

        # Process the output of the threads.
        for rcd_found in brtdata:
            for rcd in rcd_found:
                if re.search(r'^A', rcd[0]):
                    found_tlds.extend([{'type': rcd[0], 'name': rcd[1], 'address': rcd[2]}])

        self.print_good("{0} Records Found".format(len(found_tlds)))

        return found_tlds

    def brute_srv(self):
        """
        Brute-force most common SRV records for a given Domain. Returns an Array with
        records found.
        """
        brtdata = []
        returned_records = []
        srvrcd = [
            '_gc._tcp.', '_kerberos._tcp.', '_kerberos._udp.', '_ldap._tcp.',
            '_test._tcp.', '_sips._tcp.', '_sip._udp.', '_sip._tcp.', '_aix._tcp.',
            '_aix._tcp.', '_finger._tcp.', '_ftp._tcp.', '_http._tcp.', '_nntp._tcp.',
            '_telnet._tcp.', '_whois._tcp.', '_h323cs._tcp.', '_h323cs._udp.',
            '_h323be._tcp.', '_h323be._udp.', '_h323ls._tcp.', '_https._tcp.',
            '_h323ls._udp.', '_sipinternal._tcp.', '_sipinternaltls._tcp.',
            '_sip._tls.', '_sipfederationtls._tcp.', '_jabber._tcp.',
            '_xmpp-server._tcp.', '_xmpp-client._tcp.', '_imap.tcp.',
            '_certificates._tcp.', '_crls._tcp.', '_pgpkeys._tcp.',
            '_pgprevokations._tcp.', '_cmp._tcp.', '_svcp._tcp.', '_crl._tcp.',
            '_ocsp._tcp.', '_PKIXREP._tcp.', '_smtp._tcp.', '_hkp._tcp.',
            '_hkps._tcp.', '_jabber._udp.', '_xmpp-server._udp.', '_xmpp-client._udp.',
            '_jabber-client._tcp.', '_jabber-client._udp.', '_kerberos.tcp.dc._msdcs.',
            '_ldap._tcp.ForestDNSZones.', '_ldap._tcp.dc._msdcs.', '_ldap._tcp.pdc._msdcs.',
            '_ldap._tcp.gc._msdcs.', '_kerberos._tcp.dc._msdcs.', '_kpasswd._tcp.', '_kpasswd._udp.',
            '_imap._tcp.', '_imaps._tcp.', '_submission._tcp.', '_pop3._tcp.', '_pop3s._tcp.',
            '_caldav._tcp.', '_caldavs._tcp.', '_carddav._tcp.', '_carddavs._tcp.',
            '_x-puppet._tcp.', '_x-puppet-ca._tcp.']

        try:
            for srvtype in srvrcd:
                if self.verbose:
                    self.print_info("Trying {0}".format(srvtype + self.domain))
                self.pool.add_task(self.res.get_srv, srvtype + self.domain)

            # Wait for threads to finish.
            self.pool.wait_completion()

        except (KeyboardInterrupt):
            self.exit_brute(self.pool)

        # Make sure we clear the variable
        if len(brtdata) > 0:
            for rcd_found in brtdata:
                for rcd in rcd_found:
                    returned_records.append(rcd)
                    # returned_records.extend([{'type': rcd[0],
                    #                           'name': rcd[1],
                    #                           'target': rcd[2],
                    #                           'address': rcd[3],
                    #                           'port': rcd[4]}])

        else:
            self.print_error("No SRV Records Found for {0}".format(self.domain))

        self.print_good("{0} Records Found".format(len(returned_records)))

        return returned_records

    def brute_reverse(self, ip_list):
        """
        Reverse look-up brute force for given CIDR example 192.168.1.1/24. Returns an
        Array of found records.
        """
        brtdata = []

        returned_records = []
        self.print_info("Performing Reverse Lookup from {0} to {1}".format(ip_list[0], ip_list[-1]))

        # Resolve each IP in a separate thread.
        try:
            ip_range = xrange(len(ip_list) - 1)
        except NameError:
            ip_range = range(len(ip_list) - 1)

        try:
            for x in ip_range:
                ipaddress = str(ip_list[x])
                if self.verbose:
                    self.print_info("Trying {0}".format(ipaddress))
                self.pool.add_task(self.res.get_ptr, ipaddress)

            # Wait for threads to finish.
            self.pool.wait_completion()

        except (KeyboardInterrupt):
            self.exit_brute(self.pool)

        for rcd_found in brtdata:
            for rcd in rcd_found:
                returned_records.append(rcd)
                # returned_records.extend([{'type': rcd[0],
                #                           "name": rcd[1],
                #                           'address': rcd[2]}])

        self.print_good("{0} Records Found".format(len(returned_records)))

        return returned_records

    def brute_domain(self):
        """
        Main Function for domain brute forcing
        """
        brtdata = []
        found_hosts = []
        continue_brt = 'y'

        # Check if wildcard resolution is enabled
        wildcard_ip = self.check_wildcard(self.domain)
        if wildcard_ip:
            self.print_info('Do you wish to continue? y/n ')
            continue_brt = str(sys.stdin.readline()[:-1])
        if re.search(r'y', continue_brt, re.I):
            # Check if Dictionary file exists

            if os.path.isfile(self.dict):
                with open(self.dict) as f:

                    # Thread brute-force.
                    try:
                        for line in f:
                            if self.verbose:
                                self.print_info("Trying {0}".format(line.strip() + '.' + self.domain.strip()))
                            target = line.strip() + '.' + self.domain.strip()
                            self.pool.add_task(self.res.get_ip, target)

                        # Wait for threads to finish
                        self.pool.wait_completion()

                    except (KeyboardInterrupt):
                        self.exit_brute(self.pool)

            # Process the output of the threads.
            for rcd_found in brtdata:
                for rcd in rcd_found:
                    if re.search(r'^A', rcd[0]):
                        # Filter Records if filtering was enabled
                        if filter:
                            if not wildcard_ip == rcd[2]:
                                found_hosts.extend([{'type': rcd[0], 'name': rcd[1], 'address': rcd[2]}])
                        else:
                            found_hosts.extend([{'type': rcd[0], 'name': rcd[1], 'address': rcd[2]}])
                    elif re.search(r'^CNAME', rcd[0]):
                        found_hosts.extend([{'type': rcd[0], 'name': rcd[1], 'target': rcd[2]}])

            # Clear Global variable
            brtdata = []

        self.print_good("{0} Records Found".format(len(found_hosts)))
        return found_hosts

    def exit_brute(self,pool):
        self.print_error("You have pressed Ctrl-C. Saving found records.")
        self.print_info("Waiting for {0} remaining threads to finish.".format(pool.count()))
        pool.wait_completion()

    def get_nsec_type(self):
        target = "0." + self.domain

        answer = self.get_a_answer(target, self.res._res.nameservers[0], self.res._res.timeout)
        for a in answer.authority:
            if a.rdtype == 50:
                return "NSEC3"
            elif a.rdtype == 47:
                return "NSEC"

    def dns_sec_check(self):
        """
        Check if a zone is configured for DNSSEC and if so if NSEC or NSEC3 is used.
        """
        try:
            answer = self.res._res.query(self.domain, 'DNSKEY')
            self.print_info("DNSSEC is configured for {0}".format(self.domain))
            nsectype = self.get_nsec_type()
            self.print_info("DNSKEYs:")
            for rdata in answer:
                if rdata.flags == 256:
                    key_type = "ZSK"

                if rdata.flags == 257:
                    key_type = "KSk"

                self.print_info("\t{0} {1} {2} {3}".format(nsectype, key_type, algorithm_to_text(rdata.algorithm),
                                                        dns.rdata._hexify(rdata.key)))

        except dns.resolver.NXDOMAIN:
            self.print_error("Could not resolve domain: {0}".format(self.domain))
        # sys.exit(1)

        except dns.exception.Timeout:
            self.print_error("A timeout error occurred please make sure you can reach the target DNS Servers")
            self.print_error("directly and requests are not being filtered. Increase the timeout from {0} second".format(
                self.res._res.timeout))
            self.print_error("to a higher number with --lifetime <time> option.")
            #sys.exit(1)
        except dns.resolver.NoAnswer:
            self.print_error("DNSSEC is not configured for {0}".format(self.domain))

    def check_bindversion(self, ns_server, timeout):
        """
        Check if the version of Bind can be queried for.
        """
        version = ""
        request = dns.message.make_query('version.bind', 'txt', 'ch')
        try:
            response = dns.query.udp(request, ns_server, timeout=timeout, one_rr_per_rrset=True)
            if (len(response.answer) > 0):
                self.print_info(
                    "\t Bind Version for {0} {1}".format(ns_server, response.answer[0].items[0].strings[0]))
                version = response.answer[0].items[0].strings[0]
        except (
                dns.resolver.NXDOMAIN, dns.exception.Timeout, dns.resolver.NoAnswer, socket.error,
                dns.query.BadResponse):
            return version
        return version

    def check_recursive(self, ns_server, timeout):
        """
        Check if a NS Server is recursive.
        """
        is_recursive = False
        query = dns.message.make_query('www.google.com.', dns.rdatatype.NS)
        try:
            response = dns.query.udp(query, ns_server, timeout)
            recursion_flag_pattern = "\.*RA\.*"
            flags = dns.flags.to_text(response.flags)
            result = re.findall(recursion_flag_pattern, flags)
            if (result):
                self.print_error("\t Recursion enabled on NS Server {0}".format(ns_server))
            is_recursive = True
        except (socket.error, dns.exception.Timeout):
            return is_recursive
        return is_recursive

    def get_a_answer(self, target, ns, timeout):
        query = dns.message.make_query(target, dns.rdatatype.A, dns.rdataclass.IN)
        query.flags += dns.flags.CD
        query.use_edns(edns=True, payload=4096)
        query.want_dnssec(True)
        answer = dns.query.udp(query, ns, timeout)
        return answer

    def ds_zone_walk(self):
        """
        Perform DNSSEC Zone Walk using NSEC records found the the error additional
        records section of the message to find the next host to query int he zone.
        """

        records = []
        self.print_info("Performing NSEC Zone Walk for {0}".format(self.domain))

        self.print_info("Getting SOA record for {0}".format(self.domain))
        soa_rcd = self.res.get_soa()
        if len(soa_rcd) > 0:

            self.print_info("Name Server {0} will be used".format(soa_rcd[0]['Address']))
            res = DnsHelper(self.domain, soa_rcd[0]['Address'], 3)
            nameserver = soa_rcd[0]['Address']

            timeout = res._res.timeout



            transformations = [
                # Send the hostname as-is
                lambda h, hc, dc: h,

                # Prepend a zero as a subdomain
                lambda h, hc, dc: "0.{0}".format(h),

                # Append a hyphen to the host portion
                lambda h, hc, dc: "{0}-.{1}".format(hc, dc),

                # Double the last character of the host portion
                lambda h, hc, dc: "{0}{1}.{2}".format(hc, hc[-1], dc)
            ]

            pending = set([self.domain])
            finished = set()

            try:
                while pending:
                    # Get the next pending hostname
                    hostname = pending.pop()
                    finished.add(hostname)

                    # Get all the records we can for the hostname
                    records.extend(self.lookup_next(hostname))

                    # Arrange the arguments for the transformations
                    fields = re.search("(^[^.]*).(\S*)", hostname)
                    params = [hostname, fields.group(1), fields.group(2)]

                    for transformation in transformations:
                        # Apply the transformation
                        target = transformation(*params)

                        # Perform a DNS query for the target and process the response
                        response = self.get_a_answer(target, nameserver, timeout)
                        for a in response.authority:
                            if a.rdtype != 47:
                                continue

                            # NSEC records give two results:
                            #   1) The previous existing hostname that is signed
                            #   2) The subsequent existing hostname that is signed
                            # Add the latter to our list of pending hostnames
                            for r in a:
                                pending.add(r.next.to_text()[:-1])

                    # Ensure nothing pending has already been queried
                    pending -= finished

            except (KeyboardInterrupt):
                self.print_error("You have pressed Ctrl + C. Saving found records.")

            except (dns.exception.Timeout):
                self.print_error("A timeout error occurred while performing the zone walk please make ")
                self.print_error("sure you can reach the target DNS Servers directly and requests")
                self.print_error("are not being filtered. Increase the timeout to a higher number")
                self.print_error("with --lifetime <time> option.")

            # Give a summary of the walk
            if len(records) > 0:
                self.print_good("{0} records found".format(len(records)))
            else:
                self.print_error("Zone could not be walked")

            return records
        else:
            return records

    def get_whois_nets_iplist(self,ip_list):
        """
        This function will perform whois queries against a list of IP's and extract
        the net ranges and if available the organization list of each and remover any
        duplicate entries.
        """
        seen = {}
        idfun = repr
        found_nets = []
        for ip in ip_list:
            if ip != "no_ip":
                # Find appropriate Whois Server for the IP
                whois_server = get_whois(ip)
                # If we get a Whois server Process get the whois and process.
                if whois_server:
                    whois_data = whois(ip, whois_server)
                    arin_style = re.search('NetRange', whois_data)
                    ripe_apic_style = re.search('netname', whois_data)
                    if (arin_style or ripe_apic_style):
                        net = get_whois_nets(whois_data)
                        if net:
                            for network in net:
                                org = get_whois_orgname(whois_data)
                                found_nets.append({'start': network[0], 'end': network[1], 'orgname': "".join(org)})
                    else:
                        for line in whois_data.splitlines():
                            recordentrie = re.match('^(.*)\s\S*-\w*\s\S*\s(\S*\s-\s\S*)', line)
                            if recordentrie:
                                org = recordentrie.group(1)
                                net = get_whois_nets(recordentrie.group(2))
                                for network in net:
                                    found_nets.append({'start': network[0], 'end': network[1], 'orgname': "".join(org)})
        # Remove Duplicates
        return [seen.setdefault(idfun(e), e) for e in found_nets if idfun(e) not in seen]

    def whois_ips(self,ip_list):
        """
        This function will process the results of the whois lookups and present the
        user with the list of net ranges found and ask the user if he wishes to perform
        a reverse lookup on any of the ranges or all the ranges.
        """
        answer = ""
        found_records = []
        self.print_info("Performing Whois lookup against records found.")
        list = self.get_whois_nets_iplist(self.unique(ip_list))
        if len(list) > 0:
            self.print_info("The following IP Ranges where found:")
            for i in range(len(list)):
                self.print_info(
                    "\t {0} {1}-{2} {3}".format(str(i) + ")", list[i]['start'], list[i]['end'], list[i]['orgname']))
            # self.print_info('What Range do you wish to do a Revers Lookup for?')
            # self.print_info('number, comma separated list, a for all or n for none')
            # val = sys.stdin.readline()[:-1]
            # answer = str(val).split(",")
            answer = 'a'

            if "a" in answer:
                for i in range(len(list)):
                    self.print_info("Performing Reverse Lookup of range {0}-{1}".format(list[i]['start'], list[i]['end']))
                    found_records.append(self.brute_reverse(self.expand_range(list[i]['start'], list[i]['end'])))

            elif "n" in answer:
                self.print_info("No Reverse Lookups will be performed.")
                pass
            else:
                for a in answer:
                    net_selected = list[int(a)]
                    self.print_info(net_selected['orgname'])
                    self.print_info(
                        "Performing Reverse Lookup of range {0}-{1}".format(net_selected['start'], net_selected['end']))
                    found_records.append(self.brute_reverse(self.expand_range(net_selected['start'], net_selected['end'])))
        else:
            self.print_error("No IP Ranges where found in the Whois query results")

        return found_records

    def process_range(self,arg):
        """
        Function will take a string representation of a range for IPv4 or IPv6 in
        CIDR or Range format and return a list of IPs.
        """
        try:
            ip_list = None
            range_vals = []
            if re.match(r'\S*\/\S*', arg):
                ip_list = IPNetwork(arg)

            elif (re.match(r'\S*\-\S*', arg)):
                range_vals.extend(arg.split("-"))
                if len(range_vals) == 2:
                    ip_list = IPRange(range_vals[0], range_vals[1])
            else:
                self.print_error("Range provided is not valid")
                return []
        except:
            self.print_error("Range provided is not valid")
            return []
        return ip_list

    def process_spf_data(self, data):
        """
        This function will take the text info of a TXT or SPF record, extract the
        IPv4, IPv6 addresses and ranges, request process include records and return
        a list of IP Addresses for the records specified in the SPF Record.
        """
        # Declare lists that will be used in the function.
        ipv4 = []
        ipv6 = []
        includes = []
        ip_list = []

        # check first if it is a sfp record
        if not re.search(r'v\=spf', data):
            return

        # Parse the record for IPv4 Ranges, individual IPs and include TXT Records.
        ipv4.extend(re.findall('ip4:(\S*) ', "".join(data)))
        ipv6.extend(re.findall('ip6:(\S*)', "".join(data)))

        # Create a list of IPNetwork objects.
        for ip in ipv4:
            for i in IPNetwork(ip):
                ip_list.append(i)

        for ip in ipv6:
            for i in IPNetwork(ip):
                ip_list.append(i)

        # Extract and process include values.
        includes.extend(re.findall('include:(\S*)', "".join(data)))
        for inc_ranges in includes:
            for spr_rec in self.res.get_txt(inc_ranges):
                spf_data = self.process_spf_data(spr_rec['String'])
                if spf_data is not None:
                    ip_list.extend(spf_data)

        # Return a list of IP Addresses
        return [str(ip) for ip in ip_list]

    def expand_cidr(self,cidr_to_expand):
        """
        Function to expand a given CIDR and return an Array of IP Addresses that
        form the range covered by the CIDR.
        """
        ip_list = []
        c1 = IPNetwork(cidr_to_expand)
        return c1

    def expand_range(self,startip, endip):
        """
        Function to expand a given range and return an Array of IP Addresses that
        form the range.
        """
        return IPRange(startip, endip)

    def range2cidr(self,ip1, ip2):
        """
        Function to return the maximum CIDR given a range of IP's
        """
        r1 = IPRange(ip1, ip2)
        return str(r1.cidrs()[-1])

    def get_constants(self,prefix):
        """
        Create a dictionary mapping socket module constants to their names.
        """
        return dict((getattr(socket, n), n)
                    for n in dir(socket)
                    if n.startswith(prefix))

    def socket_resolv(self,target):
        """
        Resolve IPv4 and IPv6 .
        """
        found_recs = []
        families = self.get_constants('AF_')
        types = self.get_constants('SOCK_')
        try:
            for response in socket.getaddrinfo(target, 0):
                # Unpack the response tuple
                family, socktype, proto, canonname, sockaddr = response
                if families[family] == "AF_INET" and types[socktype] == "SOCK_DGRAM":
                    found_recs.append(["A", target, sockaddr[0]])
                elif families[family] == "AF_INET6" and types[socktype] == "SOCK_DGRAM":
                    found_recs.append(["AAAA", target, sockaddr[0]])
        except:
            return found_recs
        return found_recs

    def lookup_next(self,target):
        """
        Try to get the most accurate information for the record found.
        """
        res_sys = DnsHelper(target)
        returned_records = []

        if re.search("^_[A-Za-z0-9_-]*._[A-Za-z0-9_-]*.", target, re.I):
            srv_answer = self.res.get_srv(target)
            if len(srv_answer) > 0:
                for r in srv_answer:
                    data = []
                    data.append(r['Type'])
                    data.append(r['Name'])
                    data.append(r['Address'])
                    data.append(r['Target'])
                    data.append(r['Port'])
                    data.append(r['String'])
                    self.print_info("\t {0}".format(" ".join(data)))
                    returned_records.append(r)
                    # returned_records.append({'Type': r[0],
                    #                          'Name': r[1],
                    #                          'Target': r[2],
                    #                          'Address': r[3],
                    #                          'Port': r[4]})

        elif re.search("(_autodiscover\\.|_spf\\.|_domainkey\\.)", target, re.I):
            txt_answer = self.res.get_txt(target)
            if len(txt_answer) > 0:
                for r in txt_answer:
                    data = []
                    data.append(r['Type'])
                    data.append(r['Name'])
                    data.append(r['Address'])
                    data.append(r['Target'])
                    data.append(r['Port'])
                    data.append(r['String'])
                    self.print_info("\t {0}".format(" ".join(data)))
                    returned_records.append(r)
                    # self.print_info("\t {0}".format(" ".join(r)))
                    # returned_records.append({'type': r[0],
                    #                          'name': r[1], 'strings': r[2]})
            else:
                txt_answer = res_sys.get_txt(target)
                if len(txt_answer) > 0:
                    for r in txt_answer:
                        data = []
                        data.append(r['Type'])
                        data.append(r['Name'])
                        data.append(r['Address'])
                        data.append(r['Target'])
                        data.append(r['Port'])
                        data.append(r['String'])
                        self.print_info("\t {0}".format(" ".join(data)))
                        returned_records.append(r)
                        # self.print_info("\t {0}".format(" ".join(r)))
                        # returned_records.append({'type': r[0],
                        #                          'name': r[1], 'strings': r[2]})
                else:
                    self.print_info('\t A {0} no_ip'.format(target))
                    tmp_dict =self.init_dict()
                    tmp_dict['Type']='A'
                    tmp_dict['Name']=target
                    tmp_dict['Address']="no_ip"
                    returned_records.append(tmp_dict)
                    # returned_records.append({'type': 'A', 'name': target, 'address': "no_ip"})

        else:
            a_answer = self.res.get_ip(target)
            if len(a_answer) > 0:
                for r in a_answer:
                    data = []
                    data.append(r['Type'])
                    data.append(r['Name'])
                    data.append(r['Address'])
                    data.append(r['Target'])
                    data.append(r['Port'])
                    data.append(r['String'])
                    self.print_info("\t {0}".format(" ".join(data)))
                    returned_records.append(r)
                    # self.print_info('\t {0} {1} {2}'.format(r[''], r[1], r[2]))
                    # if r[0] == 'CNAME':
                    #     returned_records.append({'type': r[0], 'name': r[1], 'target': r[2]})
                    # else:
                    #     returned_records.append({'type': r[0], 'name': r[1], 'address': r[2]})
            else:
                a_answer = self.socket_resolv(target)
                if len(a_answer) > 0:
                    for r in a_answer:
                        data = []
                        data.append(r['Type'])
                        data.append(r['Name'])
                        data.append(r['Address'])
                        data.append(r['Target'])
                        data.append(r['Port'])
                        data.append(r['String'])
                        self.print_info("\t {0}".format(" ".join(data)))
                        returned_records.append(r)
                        # self.print_info('\t {0} {1} {2}'.format(r[0], r[1], r[2]))
                        # returned_records.append({'type': r[0], 'name': r[1], 'address': r[2]})
                else:
                    self.print_info('\t A {0} no_ip'.format(target))
                    tmp_dict = self.init_dict()
                    tmp_dict['Type'] = 'A'
                    tmp_dict['Name'] = target
                    tmp_dict['Address'] = "no_ip"
                    returned_records.append(tmp_dict)
                    # returned_records.append({'type': 'A', 'name': target, 'address': "no_ip"})

        return returned_records

    def write_csv(self, found_record):
        if os.path.exists(self.result_dict):
            c = open(self.result_dict, 'a')
        else:
            c = open(self.result_dict, 'w')
        writer = csv.writer(c)
        tmp_len = len(found_record)
        for r in found_record:
            data = []
            data.append(r['Type'])
            data.append(r['Name'])
            data.append(r['Address'])
            data.append(r['Target'])
            data.append(r['Port'])
            data.append(r['String'])
            writer.writerow(data)

    def general_enum(self):
        returned_records = []
        found_spf_ranges = []

        # Var to hold the IP Addresses that will be queried in Whois
        ip_for_whois = []

        # Check if wildcards are enabled on the target domain
        self.check_wildcard(self.domain)

        # To identify when the records come from a Zone Transfer
        from_zt = None

        # Perform test for Zone Transfer against all NS servers of a Domain
        zonerecs = self.res.zone_transfer()
        if zonerecs is not None:
            returned_records.extend(self.res.zone_transfer())
            if len(returned_records) > 0:
                from_zt = True

        # If a Zone Trasfer was possible there is no need to enumerate the rest
        if from_zt is None:

            # Check if DNSSEC is configured
            self.dns_sec_check()

            # Enumerate SOA Record

            try:
                found_soa_records = self.res.get_soa()
                for found_soa_record in found_soa_records:
                    self.print_info('\t {0} {1} {2}'.format(found_soa_record['Type'], found_soa_record['Name'], found_soa_record['Address']))

                    # Save dictionary of returned record
                    # returned_records.extend([{'type': found_soa_record[0],
                    #                           "mname": found_soa_record[1], 'address': found_soa_record[2]}])
                    returned_records.extend(found_soa_records)
                    for i in range(len(found_soa_records)):
                        ip_for_whois.append(found_soa_records[i]['Address'])

            except:
                self.print_error("Could not Resolve SOA Record for {0}".format(self.domain))

            # Enumerate Name Servers
            try:
                for ns_rcrd in self.res.get_ns():
                    self.print_info('\t {0} {1} {2}'.format(ns_rcrd['Type'], ns_rcrd['Name'], ns_rcrd['Address']))

                    # Save dictionary of returned record
                    recursive = self.check_recursive(ns_rcrd['Address'], self.res._res.timeout)
                    bind_ver = self.check_bindversion(ns_rcrd['Address'], self.res._res.timeout)
                    # returned_records.extend([
                    #     {'type': ns_rcrd[0], "target": ns_rcrd[1], 'address': ns_rcrd[2], 'recursive': str(recursive),
                    #      "Version": bind_ver}])
                    ns_rcrd['String']='recursive='+str(recursive)+'|'+'Version='+bind_ver
                    returned_records.append(ns_rcrd)
                    ip_for_whois.append(ns_rcrd['Address'])

            except dns.resolver.NoAnswer:
                self.print_error("Could not Resolve NS Records for {0}".format(self.domain))

            # Enumerate MX Records
            try:
                for mx_rcrd in self.res.get_mx():
                    self.print_info('\t {0} {1} {2}'.format(mx_rcrd['Type'], mx_rcrd['Name'], mx_rcrd['Address']))

                    # Save dictionary of returned record
                    # returned_records.extend([{'type': mx_rcrd[0], "exchange": mx_rcrd[1], 'address': mx_rcrd[2]}])
                    returned_records.append(mx_rcrd)

                    ip_for_whois.append(mx_rcrd['Address'])

            except dns.resolver.NoAnswer:
                self.print_error("Could not Resolve MX Records for {0}".format(self.domain))

            # Enumerate A Record for the targeted Domain
            for a_rcrd in self.res.get_ip(self.domain):
                self.print_info('\t {0} {1} {2}'.format(a_rcrd['Type'], a_rcrd['Name'], a_rcrd['Address']))

                # Save dictionary of returned record
                # returned_records.extend([{'type': a_rcrd[0], "name": a_rcrd[1], 'address': a_rcrd[2]}])
                returned_records.append(a_rcrd)

                ip_for_whois.append(a_rcrd['Address'])

            # Enumerate SFP and TXT Records for the target domain
            text_data = ""
            spf_text_data = self.res.get_spf()

            # Save dictionary of returned record
            if spf_text_data is not None:
                for s in spf_text_data:
                    self.print_info('\t {0} {1}'.format(s['Type'], s['String']))
                    text_data = s['String']
                    # returned_records.extend([{'type': s[0], "strings": s[1]}])
                    returned_records.append(s)

            txt_text_data = self.res.get_txt()

            # Save dictionary of returned record
            if txt_text_data is not None:
                for t in txt_text_data:
                    self.print_info('\t {0} {1} {2}'.format(t['Type'], t['Name'], t['String']))
                    text_data += t['String']

                    # returned_records.extend([{'type': t[0], 'name': t[1], "strings": t[2]}])
                    returned_records.append(t)

            domainkey_text_data = self.res.get_txt("_domainkey." + self.domain)

            # Save dictionary of returned record
            if domainkey_text_data is not None:
                for t in domainkey_text_data:
                    # self.print_info('\t {0} {1} {2}'.format(t[0], t[1], t[2]))
                    # text_data += t[2]
                    # returned_records.extend([{'type': t[0], 'name': t[1], "strings": t[2]}])
                    self.print_info('\t {0} {1} {2}'.format(t['Type'], t['name'], t['String']))
                    text_data += t['String']

                    # returned_records.extend([{'type': t[0], 'name': t[1], "strings": t[2]}])
                    returned_records.append(t)

            # Process SPF records if selected
            if  len(text_data) > 0:
                self.print_info("Expanding IP ranges found in DNS and TXT records for Reverse Look-up")
                processed_spf_data = self.process_spf_data(text_data)
                if processed_spf_data is not None:
                    found_spf_ranges.extend(processed_spf_data)
                if len(found_spf_ranges) > 0:
                    self.print_info("Performing Reverse Look-up of SPF Ranges")
                    returned_records.extend(self.brute_reverse(self.unique(found_spf_ranges)))
                else:
                    self.print_info("No IP Ranges where found in SPF and TXT Records")

            # Enumerate SRV Records for the targeted Domain
            self.print_info('Enumerating SRV Records')
            self.write_csv(returned_records)
            returned_records=[]
            srv_rcd = self.brute_srv()
            if srv_rcd:
                for r in srv_rcd:
                    ip_for_whois.append(r['Address'])
                    returned_records.append(r)
            whois_rcd = self.whois_ips(ip_for_whois)

            if whois_rcd:
                for r in whois_rcd:
                    returned_records.extend(r)

            zone_info = self.ds_zone_walk()
            if zone_info:
                returned_records.extend(zone_info)

            return returned_records

            # sys.exit(0)


def test_sub(domain,filename=None):
    dict = os.path.join(dict_path,'subnames_full.txt')
    tmp =subBruteBase(domain,dict=dict,filename=filename)
    tmp.run()
def test_ds_walk(domain,filename=None):
    dict = os.path.join(dict_path, 'subnames_full.txt')
    tmp =subBruteBase(domain,dict=dict,filename=filename)
    tmp.ds_zone_walk()




if __name__=='__main__':
    test_sub('cuit.edu.cn')