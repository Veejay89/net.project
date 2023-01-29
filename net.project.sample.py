#!/usr/bin/python3
# Copyright 2022 Sergey Malkov

"""
Use this section to describe script functionalty
"""

import os
import sys
import re
import getpass
import paramiko
import time
# Import Custom Functions libraries
# sys.path[0] contains absolute path to directory contains running script 
this_path = sys.path[0]
sys.path.append(this_path+'/modules')
import cf
import cfsec



def main_init():
  """
  Use main_init function in module:
  1. Define global variables;
  2. Determine log file and start logging procedure;
  3. Determine timer class if necessary;
  4. Read params template if it used in script.
  """
  pass


def main_preprocessing():
  """docstring"""
  pass


def main_process():
  pass


def main():
  main_init()
  main_preprocessing()
  main_process()
  
  
  print("IPv4 address verification example:")
  ip_array = ["192.168.1.1", "192.168.1.x", "172.16.1.254", "192.256.1.1", "uncorrect_ip"]
  for ip in ip_array:
    print("  Value: %s | Valid: %s | Valid2: %s" % (ip, cf.check.ip.do(ip), cf.check.typeof('ip').do(ip)))
    
  print("Network port verification example:")
  port_array = ["22", "443", "70000", "0","uncorrect_port"]
  for port in port_array:
    print("  Value: %s | Valid: %s | Valid2: %s" % (port, cf.check.port.do(port), cf.check.typeof('port').do(port)))
  
  print("Email address verification example:")
  email_array = ["1@gmail.com", "mymail@mail.ru", "mymail@@gmail.com", "@domain.com","mail@mail.r"]
  for email in email_array:
    print("  Value: %s | Valid: %s | Valid2: %s" % (email, cf.check.email.do(email), cf.check.typeof('email').do(email)))
  
  print("FQDN without TLD verification example:")
  fqdn_array = ["zabbix-prod-02", "zabbix-prod-02.cplsb.ru", "zabbix-prod-02.cplsb.r", "zabbix-prod-02.@.ru","zabbix-prod-02..ru"]
  for fqdn in fqdn_array:
    print("  Value: %s | Valid: %s" % (fqdn, cf.check.fqdn.do(fqdn)))

  print("FQDN with TLD verification example:")
  fqdn_array = ["zabbix-prod-02", "zabbix-prod-02.cplsb.ru", "zabbix-prod-02.cplsb.r", "zabbix-prod-02.@.ru","zabbix-prod-02..ru"]
  for fqdn in fqdn_array:
    print("  Value: %s | Valid: %s" % (fqdn, cf.check.fqdn_tld.do(fqdn)))
  
  print("Host verification example:")
  host_array = ["zabbix-prod-02", "zabbix-prod-02.cplsb.ru", "10.1.1.1", "10.1.1.256","zabbix-prod-02..ru"]
  for host in host_array:
    print("  Value: %s | Valid: %s" % (host, cf.check.host.do(host)))
  
  print("Integer verification example:")
  integer_array = ["222", "95", "07", "95x","uncorrect_int"]
  for integer in integer_array:
    print("  Value: %s | Valid: %s" % (integer, cf.check.integer.do(integer)))
 
if __name__ == '__main__':
  main()