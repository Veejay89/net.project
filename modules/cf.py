#!/usr/bin/python3 -tt
# Copyright 2022 Sergey Malkov

"""
Custom functions module for network authomatization
"""
import os

import sys
# https://docs.python.org/3/library/string.html
import string
# https://docs.python.org/3/library/random.html
import random
# https://docs.python.org/3/library/smtplib.html
import smtplib
# https://docs.python.org/3/library/re.html
import re
# https://docs.python-requests.org/en/latest/
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

import time

import paramiko

import json
# datetime object containing current date and time
from datetime import datetime

from psutil import disk_usage



# ---Global module variables
# Paramiko ssh connect default timeout. Default: tcp=5, auth=30
ssh_tcp_timeout = 5
ssh_auth_timeout = 20

net_supported_software = {
    'ios': 'ios',
    'nx-os': 'nx-os',
    'asa': 'asa',
    'asdm': 'asa',
    'adaptive security appliance': 'asa',
    'vyos': 'vyos',
    'gaia': 'gaia'
}


# Internal support classes
class Req:
  """docstring"""

  def __init__(self):
    self.error = False
    self.status_code = False
    self.data = ''

class DiskUsageInfo:
  """docstring"""
  
  class DiskUsageValue:
    def __init__(self):
      self.b = None
      self.measure = ['B','Kb','Mb','Gb','Tb']
    
    def mb(self):
      self._mb = None
      
      if self.b is not None:
        self._mb = round(self.b/1024/1024)
      
      return self._mb
    
    def st(self, dec=1):
      i = 0
      self._st = None
      
      if self.b is not None:
        _v = self.b
        while (_v > 1024 and i<4):
          _v = _v/1024
          i = i+1
        self._st = "%s %s" % (round(_v,dec), self.measure[i])
      
      return self._st
  
  def __init__(self):
    self.error = None
    self.total = self.DiskUsageValue()
    self.free = self.DiskUsageValue()
    self.used = self.DiskUsageValue()



def convert_bytes(size, dec=1):
  """ Convert bytes to nearest value in KB, MB, GB.. """
  for x in ['bytes', 'KB', 'MB', 'GB', 'TB']:
    if size < 1024.0:
      return "%s %s" % (round(size,dec), x)
    size /= 1024.0

"""
# IN PROGRESS...
class html_table:
  
  cell_template = {
    'bgcolor': None,
    'fgcolor': None,
    'bold': False,
    'align': None,
    'colspan' : 0,
    'rowspan' : 0,
    'value': ""
  }
  
  row_template = {
    'bgcolor': None,
    'fgcolor': None,
    'bold': False,
    'align': None
  }
  
  def __init__(self):
    self.row_bgcolor = None
    self.row_fgcolor = None
    self.row_st_bold = False
    self.row_st_align = None
    self.row_bgcolor_seq = False
    self.row_bgcolor_seq_colors = []
    self.row_position = 0
    self.columns = []
    self.rows = []
    
  def row(self, bgcolor=None, fgcolor=None, bold=False, align=None):
    self.row_position = self.row_position+1
    self.rows[self.row_position] = []
    self.rows[self.row_position][0] = self.row_template.copy()
    #pass
  
  def cell(self, text, bgcolor=None, fgcolor=None, bold=False, align=None, colspan=0, rowspan=0):
    pass
    
  def add_column(self):
    pass
  
  def row_color_seq(self):
    pass
  
  def table():
    pass
""" 


"""
VALIDATION AND VERIFICATION FUNCTIONS
"""

"""
class check:

  class template_default:
    def __init__(self, pattern):
      self.pattern = pattern
      self.regexp = re.compile(r'%s' % pattern)
    
    def do(self, value):
      if re.fullmatch(self.regexp, value):
        return True
      else:
        return False
  
  ip = template_default('^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)(\.(?!$)|$)){4}$')
  fqdn = template_default('(?=^.{1,253}$)(^(((?!-)[a-zA-Z0-9-]{1,63}(?<!-))|((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63})$)')
  fqdn_tld = template_default('(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)')
  port = template_default('^([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$')
  email = template_default('([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+')
  host = template_default('(^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)(\.(?!$)|$)){4}$)|((?=^.{1,253}$)(^(((?!-)[a-zA-Z0-9-]{1,63}(?<!-))|((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63})$))')
  
  class template_integer:
    def do(self, value):
      try:
        result = int(value)
        return result
      except Exception as e:
        return None
  
  integer = template_integer()
"""

class _check:
  """docstring"""

  class template_default:
    def __init__(self, pattern):
      self.pattern = pattern
      self.regexp = re.compile(r'%s' % pattern)
    
    def do(self, value):
      if re.fullmatch(self.regexp, value):
        return True
      else:
        return False
  
  class template_integer:
    def do(self, value):
      try:
        result = int(value)
        return result
      except Exception as e:
        return None
  
  class template_stub:
    def do(self, value):
      return None
  
  ip = template_default('^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)(\.(?!$)|$)){4}$')
  fqdn = template_default('(?=^.{1,253}$)(^(((?!-)[a-zA-Z0-9-]{1,63}(?<!-))|((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63})$)')
  fqdn_tld = template_default('(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)')
  port = template_default('^([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$')
  email = template_default('([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+')
  host = template_default('(^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)(\.(?!$)|$)){4}$)|((?=^.{1,253}$)(^(((?!-)[a-zA-Z0-9-]{1,63}(?<!-))|((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63})$))')
  integer = template_integer()
  stub = template_stub()
  
  types = {
    'ip': ip,
    'port': port,
    'email': email
  }
  
  def typeof(self, tp):
    if tp in self.types:
      return self.types[tp]
    else:
      return self.stub


check = _check()


def script_name():
  # os.path.abspath(__file__) can't be used, because returns
  # current (this - cf.py) file location even if running in another script
  path = sys.argv[0]
  while True:
    i = path.find('/')
    if i >= 0:
      path = path[(i+1):]
    else:
      break
  # Detect file extension and remove if it exists
  if path[-3:] == '.py':
    path = path[:-3]
  # Return final file name without directories in path and extension
  return path



def script_dir():
  #return os.path.abspath(__file__)
  return os.path.dirname(sys.argv[0])



def get_disk_size(dirname=None):
  """
  Returns directory free space in MB
  Works only in *nix systems
  """
  if dirname is None:
    dirname = script_dir()
  
  result = DiskUsageInfo()
  
  try:
    # psutil.disk_usage(path) gets:
    # - total: total amount of memory
    # - used: used memory
    # - free: free memory
    # - percent: percentage usage of the memory
    # All the above attributes are reported in bytes
    du = disk_usage(dirname)

    result.total.b = du.total
    result.used.b = du.used
    result.free.b = du.free
  except Exception as e:
    result.error = e
  #except Exception: 
  #  pass
  
  return result



class Timer:
  """Simple class for time measurement"""
  
  def __init__(self, start=False):
    if start:
      self.start()
    else:
      self.start_time = None
  
  def start(self):
    self.start_time = datetime.now()
    self.finish_time = None
  
  def finish(self):
    if self.start_time:
      self.finish_time = datetime.now()
      self.result = self.finish_time - self.start_time
      return (self.result)


class console:
  reset = '\033[0m'
  
  class st:
    bold = '\033[01m'
    disable = '\033[02m'
    underline = '\033[04m'
    reverse = '\033[07m'
    strikethrough = '\033[09m'
    invisible = '\033[08m'
  
  class fg:
    black = '\033[30m'
    red = '\033[31m'
    green = '\033[32m'
    orange = '\033[33m'
    blue = '\033[34m'
    purple = '\033[35m'
    cyan = '\033[36m'
    lightgrey = '\033[37m'
    darkgrey = '\033[90m'
    lightred = '\033[91m'
    lightgreen = '\033[92m'
    yellow = '\033[93m'
    lightblue = '\033[94m'
    pink = '\033[95m'
    lightcyan = '\033[96m'
 
  class bg:
    black = '\033[40m'
    red = '\033[41m'
    green = '\033[42m'
    orange = '\033[43m'
    blue = '\033[44m'
    purple = '\033[45m'
    cyan = '\033[46m'
    lightgrey = '\033[47m'

class rgb:
   orange = '#FFA500'
   green = '#008000'
   Tomato = '#FF6347'
   DodgerBlue = '#1E90FF'



class Log:
  """Logger Lite Class for writing simple log messages"""
  
  class log_display:
    def __init__(self):
      self._state = False
      self._prefix = False
      self._timestamp = False
      self._colored = []
    def on(self):
      self._state = True
    def off(self):
      self._state = False
    def prefix(self, value=True):
      self._prefix = bool(value)
    def timestamp(self, value=True):
      self._timestamp = bool(value)
    def color(self, template, color):
      self._colored.append(dict(template=template, color=color))
  
  # 22.01.23
  class log_record:
    def __init__(self):
      self._state = False
      self._prefix = False
      self._timestamp = False
      self._style = dict()
      self._text = []
    def on(self):
      self._state = True
    def off(self, wipe=False):
      self._state = False
      if wipe: self._text.clear()
    def prefix(self, value=True):
      self._prefix = bool(value)
    def timestamp(self, value=True):
      self._timestamp = bool(value)
    def add(self, msg):
      self._text.append(msg)
    
    def color(self, template, color):
      # tbd, color check procedure
      if not self._style.get(template):
        self._style[template] = ''
      self._style[template] += 'color:'+color+';'
    def bold(self, template):
      if not self._style.get(template):
        self._style[template] = ''
      self._style[template] += 'font-weight:bold;'
      
    def html(self):
      style = self._style.copy()
      for tkey in style:
        style[tkey] = 'style="'+style[tkey]+'"'
      #
      result = "<html>"
      for s in self._text:
        #
        for t in style:
          s = s.replace(t, '<span '+style[t]+'>'+t+'</span>')
        result += s
        result += "<br>"
      result += "</html>"
      return result
  
  # file_max_size - in Kb, by default = 10 Mb
  def __init__(self, file='cf_log.txt', path='', file_max_size=10240):
    self.log_path = path
    self.log_fullpath = "%s/%s" % (path,file)
    self.log_prefix = '-'
    self.log_timestamp = True
    
    if path != '' and (not os.path.isdir(path)):
    # If path is not exists, new directory will be created as log files storage    
      os.makedirs(path)
    elif os.path.isfile(self.log_fullpath):
    # If log file already exists, init file size check
      log_file_size = round(os.path.getsize(self.log_fullpath)/1024)
      if log_file_size >= file_max_size:
        now = datetime.now()
        ext_timestamp = now.strftime("%y%d%m")
        
        log_new_fullpath = "%s/%s-%s" % (path,file,ext_timestamp)
        
        if os.path.isfile(log_new_fullpath):
          ext_timestamp = now.strftime("%y%d%m-%H%M%S")
          log_new_fullpath = "%s/%s-%s" % (path,file,ext_timestamp)
        
        os.rename(self.log_fullpath, log_new_fullpath)
    
    self.log_file = open(self.log_fullpath, 'a') # append
    self.log_ewf_msg = None
    self.display = self.log_display()
    # NEW
    self.msg_lvl_template = None
    # 22.01.23
    self.record = self.log_record()
 
  def __del__(self):
    if self.log_file:
      self.log_file.close()
  
  def timestamp(self, value=True):
    self.log_timestamp = bool(value)
  
  def define_prefix(self,p=''):
    if p != '':
      self.log_prefix = p
    else:
      self.log_prefix = '-'
  
  # NEW
  def set_lvl_prefix(self,p='>'):
    if p is None:
      self.msg_lvl_template = None
    else:
      if len(p) != 1:
        p = '>'
      self.msg_lvl_template = re.compile(r'^(?P<prefix>'+p+'*)(?P<msg>.*)$')
  
  def write(self, msg='', lvl=0, display=False):
    # NEW
    if lvl==0 and (self.msg_lvl_template is not None):
      match = self.msg_lvl_template.search(msg)
      if match:
        lvl = len(match.group('prefix'))
        msg = match.group('msg')
    
    # Create new immunable copy of original string
    msgd = msg[:]
    msgr = msg[:]
    # Append log level prefix
    i = 0
    while i < lvl:
      msg = self.log_prefix + msg
      i += 1
    if self.display._prefix:
      msgd = msg[:]
    if self.record._prefix:
      msgr = msg[:]
    
    if self.log_timestamp:
      # Get log message timestamp, format: dd/mm/YY H:M:S
      now = datetime.now()
      msg_timestamp = now.strftime("%d/%m/%Y %H:%M:%S")
      msg = '%s: %s' % (msg_timestamp, msg)
      if self.display._timestamp:
        msgd = msg[:]
      # 28.01.23
      if self.record._timestamp:
        msgr = msg[:]
    
    if self.display._state or display:
      for t in self.display._colored:
        msgd = msgd.replace(t['template'], t['color']+t['template']+console.reset)
      print(msgd)
    
    # 22.01.23
    if self.record._state:
      self.record.add(msgr)
    
    if self.log_file:
      print(msg, file=self.log_file)
  
  def write_exit(self, msg=None, display=False):
    if msg:
      self.write(msg, display=display)
    elif self.log_ewf_msg:
      self.write(self.log_ewf_msg, display=display)
    sys.exit()
    
    

def rdisablesslwarnings():
  requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def rget(url, headers, sslverify=False, data=False):
  result = Req()
  
  try:
    if not data:
      response = requests.get(url, headers=headers, verify=sslverify)
    else:
      response = requests.get(url, data=json.dumps(data), headers=headers, verify=sslverify)
  except Exception as e:
    result.error = str(e)
    return result
  result.status_code = response.status_code
  if response.status_code != 200:
    result.error = 'HTTP response code: {}'.format(response.status_code)
    return result
    
  result.data = response.json()
  return result



def rput(url, data, headers, sslverify=False):
  result = Req()
  
  try:
    response = requests.put(url, data=json.dumps(data), headers=headers, verify=sslverify)
  except Exception as e:
    result.error = str(e)
    return result
  result.status_code = response.status_code
  if response.status_code != 200:
    result.error = 'HTTP response code: {}'.format(response.status_code)
    return result
    
  result.data = response.json()
  return result


class settings:
  """
  Class description
  """
  def __init__(self, file):
    self.settings_file = file
    """
    self.settings_template = {
      'name': None,
      'type': 'any',
      'default': None,
      'mandatory': True,
      'value': None,
      'multiple': False
    }
    """
    self.settings_types = ['any','string','int','ip','port','email','host','fqdn','fqdn_tld']
    self.settings = {}
    self.description = ''
    pass
  
  def add(self, name, default=None, mandatory=True, t='any', multiple=False):
    # Exception if adding attribute already exists
    if name in self.settings:
      return
    # Exception if unsupported type defined
    if not t in self.settings_types:
      return
    self.settings[name] = {
      'type': t,
      'default': default,
      'mandatory': mandatory,
      'multiple': multiple,
      'value': None
    }
    pass
  
  def get(self, name):
    pass
  
  def set(self, name, value):
    pass
  
  def remove(self, name):
    pass
  
  def read(self, new=True, override=True):
    pass
  
  def verify(self):
    pass
  
  def params(self):
    pass
    
  def errors(self):
    pass
  


def get_settings(file='_sample_get_settings.txt', name_check=None):
  
  lines = []
  try:
    #f = open(file,'r')
    with open(file,'r') as f:
      lines = f.readlines()
  except IOError as e:
    return None

  templateAttribute = re.compile(r'^(?:[\s\t]*)(?P<attr_name>[A-Za-z-_]+)(?:[\s\t]*)=(?:[\s\t]*)(?P<attr_value>[A-Za-z0-9-_\.:;/\\@\s\(\)=]+)(?:[\s\t]*)$')
  settings = {}
  dflag = False  # Description flag
  
  for line in lines:
    line = line.strip()
    if line == '"""' and not dflag:
      dflag = True
      settings['description'] = ''
      continue
    elif line == '"""' and dflag:
      dflag = False
      continue
    elif dflag:
      if line != '' and (settings['description'][-2:] == '\n' or not settings['description']):
        pass
      else:
        settings['description'] += '\n'
      settings['description'] += line
      continue
    elif line == '':
      # Empty line - ignore
      continue
    elif line[0] == '#':
      # Commented string or value - ignore
      continue

    attr = templateAttribute.fullmatch(line)
    if attr == None:
      # Invalid attribute format
      continue
    attr_name = attr.group('attr_name')
    attr_value = attr.group('attr_value')
    
    if name_check and (not attr_name in name_check):
      continue
    
    if attr_name in settings:
      if isinstance(settings[attr_name], str):
        # Create dict for adding second attribute
        settings[attr_name] = [settings[attr_name]]
      # Add second or more attribute to existing dict
      settings[attr_name].append(attr_value)
    else:
      settings[attr_name] = attr_value
    
  return settings



def generate_password(strLen=8,isLetters=True,isDigits=True,isPunctuation=False):
  """ Generates a random string of letters / digits / punctuation """
  
  templatePassword = ''
  if isDigits == True:
    templatePassword += string.digits
  if isPunctuation == True:
    templatePassword += string.punctuation
  if templatePassword == '' or isLetters == True:
    templatePassword += string.ascii_letters
  
  result = ''
  for i in range(strLen):
    result += random.choice(templatePassword)
    
  if result == '':
    result = False
  else:
    result = ''.join(random.sample(result,k=len(result)))

  return result



class smtp:
  """tbd"""
   
  # [fAuth] forces setting esmtp_features['auth'] attribute of SMTP connection. Might be useful, f.e. if SMTP server does support the AUTH command even though it doesn't advertise it via EHLO request. Without this attr you'll get [No suitable authentication method found] exception in smtplib.login.
  #    Examples:
  #    fAuth = 'LOGIN'
  #    fAuth = 'PLAIN'
  def __init__(self):
    self.fromAddr = ''
    self.smtpServer = ''
    self.smtpPort = 587
    self.username = ''
    self.password = ''
    self.tls = True
    self.fAuth = False
    
    self.error = None
  
  def gmail(fromAddr,password):
    self.fromAddr = fromAddr
    self.smtpServer = 'smtp.gmail.com'
    self.smtpPort = 587
    self.username = self.fromAddr # Just a pointer, keep in mind that strings are immunable
    self.password = password
    self.tls = True
    self.fAuth = False
  
  def send(self, subject, message, recepient):
    """
    Sends a single message via defined SMTP server
    Use FOR/IN structure to send more than one equal message
    """
    self.error = None
    supportedAuth = ['LOGIN','PLAIN']
    
    # Allow to define tls variable as string (bool by default)
    if isinstance(self.tls, str):
      if self.tls.lower() == 'true':
        self.tls = True
      else:
        self.tls = False
    
    # tbd - adding check for correct attributes
    
    # Send a message via algorythm of defined smtp server
    try:
      # Form Content-Type header if <html> tags exists in message
      content = ''
      if message.find('<html>') >= 0:
        content = 'Content-Type: text/html\n'
      # Form Email message in smtplib format w/ Content-Type if nesessary
      # message = 'Subject: {}\n\n{}'.format(subject, message)
      message = 'Subject: {}\nFrom: {}\nTo: {}\n{}\n{}'.format(subject, self.fromAddr, recepient, content, message)
      
      conn = smtplib.SMTP(self.smtpServer,self.smtpPort)
      conn.ehlo()
      if self.tls == True:
        # TLS Algorythm (f.e. used by GMail)
        conn.starttls()
        conn.ehlo()
      if self.fAuth in supportedAuth:
        conn.esmtp_features['auth'] = self.fAuth
      conn.login(self.username, self.password)
      conn.sendmail(self.fromAddr, recepient, message)
      conn.quit()
    except Exception as e:
      self.error = str(e)

    if self.error:
      return False
    else:
      return True



cset = {
  'ios': {
    'get_prompt': '^(?P<state>\([A-Za-z]+\)|)(?P<hostname>[A-Za-z0-9-_]+)(?P<mode>\>|#)$',
    'set_priviledge': 'enable',
    'set_pager': 'terminal length 0',
    'get_congig': 'show running-config view full'
  },
  'nx-os': {
    'get_prompt': '^(?P<state>\([A-Za-z]+\)|)(?P<hostname>[A-Za-z0-9-_]+)(?P<mode>\>|#)$',
    'set_priviledge': 'enable',
    'set_pager': 'terminal length 0',
    'get_congig': 'show running-config'
  },
  'asa': {
    'get_prompt': '^(?P<state>\([A-Za-z]+\)|)(?P<hostname>[A-Za-z0-9-_]+)(?P<mode>\>|#)$',
    'set_priviledge': 'enable',
    'set_pager': 'terminal pager 0',
    'get_congig': 'show running-config'
  },
  'vyos': {
    # srv_net_bkp_01@sp-net-rtr-pr01>
    # srv_net_bkp_01@sp-net-rtr-pr01:~$
    'get_prompt': '^(?P<username>[A-Za-z0-9-_]+)@(?P<hostname>[A-Za-z0-9-_]+)[>|:](?P<other>.*)$',
    'set_priviledge': None,
    'set_pager': 'set terminal length 0',
    'get_congig': 'show configuration commands'
  },
  'gaia': {
    #'get_prompt': '^(?P<hostname>[A-Za-z0-9-_]+)>$',
    # sp-net-fwv-pr01:TACP-0>
    # sp-net-mcv-pr02:TACP-0sp-net-mcv-pr02:TACP-0>
    # FW-DC-08G-CP5600-2>
    # sc-net-nfw-pr01:TACP-0:mplane>
    'get_prompt': '^((?P<hostname>[A-Za-z0-9-_]+)(:TACP-0|)(:mplane|)){1,2}>$',
    'set_priviledge': None,
    'set_pager': 'set clienv rows 0',
    'get_congig': 'show configuration'
  }
}

def net_backup_ssh_cset(name, ip, username, password, path, cset, port=22, enable=None):
  """
  function description
  """
  # Pseudo-class for function results
  class _result:
    pass
  result = _result()
  result.ok = False
  result.size = 0
  result.msg = ''
  
  if not cset.get('get_prompt') or not cset.get('get_congig'):
    result.msg = "Uncorrect command set defined for backup function"
    return result
  
  prompt = re.compile(r'%s' % cset['get_prompt'])
  
  try:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, port, username, password, look_for_keys=False, timeout=ssh_tcp_timeout, auth_timeout=ssh_auth_timeout)
    chan = ssh.invoke_shell()
    time.sleep(2)
    
    # Get first console greetings
    output = chan.recv(999999)
    # Decode string from byte format
    output = output.decode("utf-8")
    # Get hostname
    output = "".join(output.splitlines()[-1:])
    # Remove possible whitespaces (in the end of output)
    output = output.strip()
    
    a = prompt.fullmatch(output)
    if a != None:
      d = a.groupdict()
      cli_hostname = d.get('hostname')
      # Redefine host name from CLI
      if cli_hostname and name == ip:
        name = cli_hostname
        path = path.replace(ip, name)
      # Get CLI mode sign (priviledged or not). Expected "#" or ">"
      cli_mode = d.get('mode')
      if cli_mode:
        if cli_mode == ">" and cset.get('set_priviledge'):
          chan.send('%s\n' % cset['set_priviledge'])
          if enable:
            chan.send(enable +'\n')
          else:
            chan.send('\n')
        time.sleep(1)
    else:
      # If 'mode' can't be parsed, exception will be executed later: 
      # local variable 'mode' referenced before assignment
      result.msg = "Cannot parse device prompt with predefined regexp: %s" % output
      return result
   
    if cset.get('set_pager'):
      chan.send('%s\n' % cset['set_pager'])
      time.sleep(1)
    
    # Clear output before capture running-config
    output = chan.recv(999999)
    
    chan.send('%s\n' % cset['get_congig'])
    time.sleep(10)
    output = chan.recv(999999)
  except paramiko.AuthenticationException:
    result.msg = "Authentication failed, verify credentials used for connection"
    return result
    #return "%s: Authentication failed, verify credentials used for connection" % name
  except paramiko.SSHException as e:
    result.msg = "Unable to establish SSH connection: %s" % e
    return result
    #return "%s: Unable to establish SSH connection: %s" % (name, e)
  except paramiko.BadHostKeyException as e:
    result.msg = "Unable to verify device's host key: %s" % e
    return result
    #return "%s: Unable to verify device's host key: %s" % (name, e)
  except Exception as e:
    result.msg = e
    return result
    #return ("%s: %s" % (name, e))
  finally:
    ssh.close()  
  
  if not os.path.exists(path):
    try:
      os.makedirs(path)
    except OSError:
      result.msg = "Error creating backup derectory %s" % path
      return result
      #return ("Error creating derectory %s" % path)

  now = datetime.now()
  timestamp = now.strftime("%d-%b-%y--%H-%M-%S")
  filename = "%s/%s--%s.txt" % (path, name, timestamp)
  
  try:
    f = open(filename, 'w')
    f.write(output.decode("utf-8"))
  except OSError as e:
    if e.errno == errno.ENOSPC:
      result.msg = "Can't create backup file. No disk space left"
      return result
      #return "%s: Can't create backup file. No disk space left" % name
    else:
      result.msg = e
      return result
      #return ("%s: %s" % (name, e))
  except Exception as e:
    result.msg = e
    return result
    #return ("%s: %s" % (name, e))
  finally:
    f.close()
    
  try:
    f_size = os.path.getsize(filename)
    result.size = f_size
  except OSError as e:
    result.msg = "Error while checking backup file size: %s" % e

  # If function finished with no exception, set OK flag to True
  result.ok = True
  return result



def net_backup_ssh(name, ip, username, password, path, enable=None, port=22, ostype=None):
  """
    Adopted for backup plain-text configuration on ssh-cli network devices. Supports:
    - Cisco IOS
    - Cisco NX-OS
    - Cisco ASDM (ASA)
    - VyOS (Vyatta OS)
    - Gaia (Checkpoint Gaia OS)
    :ostype defines OS type of device:
        ios (default)
        nx-os
        asa
        vyos
        gaia
  """
  
  result = net_backup_ssh_cset(name, ip, username, password, path, cset[ostype], port, enable)
  return result  



"""
Fallbacks for Log Class
"""

_cf_log_default_path = 'cf_log.txt'

def log_define_file(file):
  global _cf_log_default_path
  _cf_log_default_path = file


def log(msg,file='',lvl=0):
  if file == '':
    file = _cf_log_default_path
  # Get log message timestamp, format: dd/mm/YY H:M:S
  now = datetime.now()
  msg_timestamp = now.strftime("%d/%m/%Y %H:%M:%S")
  # Append log level prefix
  i = 0
  while i < lvl:
    msg = '-' + msg
    i += 1
  # Insert new record in log file
  f = open(file, 'a') # append
  print(msg_timestamp+': '+msg, file=f)
  f.close()


def log_exit(msg='',file=''):
  if file == '':
    file = _cf_log_default_path
  if msg != '':
    log(msg,file)
  sys.exit()


def is_valid_ip(ip):
  """
  Function returns 'True' if addr is valid IPv4 address or 'False' - if not
  """
  # Compile a regular expression pattern into a regular expression object
  template_ip = re.compile(r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$')
  # Compare ip string with pattern
  if re.fullmatch(template_ip, ip):
    return True
  else:
    return False


def is_valid_port(port):
  """
  Function returns 'True' if port is network port or 'False' - if not
  """
  # Compile a regular expression pattern into a regular expression object
  template_port = re.compile(r'^([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$')
  # Compare ip string with pattern
  if re.fullmatch(template_port, port):
    return True
  else:
    return False


def is_valid_fqdn(fqdn, tld=False):
  """
  Function returns 'True' if fqdn is valid FQDN or 'False' - if not
  TLD - top-level-domain flag
  """
  # Compile a regular expression pattern into a regular expression object
  if tld:
    template_tld_true = re.compile(r'(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)')
  else:
    template_tld_false = re.compile(r'(?=^.{1,253}$)(^(((?!-)[a-zA-Z0-9-]{1,63}(?<!-))|((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63})$)')
  
  

def is_valid_email(email):
  """
  Function returns 'True' if addr is valid Email address or 'False' - if not
  """
  # Compile a regular expression pattern into a regular expression object
  template_email = re.compile(r'([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+')
  # Compare whole email string with pattern
  if re.fullmatch(template_email, email):
    return True
  else:
    return False


def is_int(x):
  """
  
  """
  try:
    result = int(x)
    return result
  except Exception as e:
    return False


"""
Deprecated in 1.0.1. To remove in next versions
"""

"""
def net_backup_ssh_cisco(name, ip, username, password, path, enable=None, port=22, ostype=None):
"""
"""
    Adopted for backup run-config on ssh-cli network devices. Supports:
    - Cisco IOS
    - Cisco NX-OS
    - Cisco ASDM (ASA)
    :ostype defines OS type of device:
        ios (default)
        nx-os
        asa
"""
"""  
  #re_hostname_t1 = re.compile(r'^(?P<hostname>[A-Za-z0-9-_]+)(?P<mode>\>|#)$')
  # First group <state> in RegEx added to except '(Restricted)' keyword in CLI, f.e.
  # (Restricted)RTR-DC-ISRv-01
  re_hostname_t1 = re.compile(r'^(?P<state>\([A-Za-z]+\)|)(?P<hostname>[A-Za-z0-9-_]+)(?P<mode>\>|#)$')
  
  
  ostype = net_supported_software.get(ostype)
  if not ostype:
    ostype = 'ios'
  
  try:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, port, username, password, look_for_keys=False, timeout=ssh_tcp_timeout, auth_timeout=ssh_auth_timeout)
    chan = ssh.invoke_shell()
    time.sleep(2)
    
    # Get first console greetings
    output = chan.recv(999999)
    # Decode string from byte format
    output = output.decode("utf-8")
    # Get hostname
    output = "".join(output.splitlines()[-1:])
    # Remove possible whitespaces (in the end of output)
    output = output.strip()
    
    a = re_hostname_t1.fullmatch(output)
    state = None
    if a != None:
      # Get CLI mode sign (priviledged or not). Expected "#" or ">"
      mode = a.group('mode')
      # Redefine host name from CLI
      if name == ip:
        name = a.group('hostname')
        path = path.replace(ip, name)
      if a.group('state') == '(Restricted)':
        state = 'restricted'
    else:
      # If 'mode' can't be parsed, exception will be executed later: 
      # local variable 'mode' referenced before assignment
      return "%s: Can't parse hostname and mode from '%s'" % (name, output)
      #pass
    
    if mode == ">":
      chan.send('enable\n')
      if enable:
        chan.send(enable +'\n')
      else:
        chan.send('\n')
      time.sleep(1)
    
    # In privileged mode allows display output without any breaks and pauses
    if ostype == 'ios' or ostype == 'nx-os':
      chan.send('terminal length 0\n')
    elif ostype == 'asa':
      chan.send('terminal pager 0\n')
    time.sleep(1)
    
    # Clear output before capture running-config
    output = chan.recv(999999)
    
    if ostype == 'ios':
    # view full extension allows to get configuration with low-privileged user profile.
    # For Cisco IOS:
    # file privilege 3
    # privilege exec all level 3 show
    # privilege exec all level 3 dir
    # privilege exec all level 3 more
    # privilege exec all level 3 verify
    # -----
    # For NX-OS:
    # role name read-only
    # rule 5 permit command terminal length 0
    # rule 4 permit command show version
    # rule 3 permit command show running-config all
    # rule 2 permit command show *
    # rule 1 permit read
       chan.send('show running-config view full\n')
    elif ostype == 'nx-os' or ostype == 'asa':
      chan.send('show running-config\n')
    
    time.sleep(10)
    output = chan.recv(999999)
  except paramiko.AuthenticationException:
    return "%s: Authentication failed, verify credentials used for connection" % name
  except paramiko.SSHException as e:
    return "%s: Unable to establish SSH connection: %s" % (name, e)
  except paramiko.BadHostKeyException as e:
    return "%s: Unable to verify device's host key: %s" % (name, e)
  except Exception as e:
    return ("%s: %s" % (name, e))
  finally:
    ssh.close()

  if not os.path.exists(path):
    try:
      os.makedirs(path)
    except OSError:
      return ("Error creating derectory %s" % path)

  now = datetime.now()
  timestamp = now.strftime("%d-%b-%y--%H-%M-%S")
  filename = "%s/%s--%s.txt" % (path, name, timestamp)
  
  try:
    f = open(filename, 'w')
    f.write(output.decode("utf-8"))
  except OSError as e:
    if e.errno == errno.ENOSPC:
      return "%s: Can't create backup file. No disk space left" % name
    else:
      return ("%s: %s" % (name, e))
  except Exception as e:
    return ("%s: %s" % (name, e))
  finally:
    f.close()
  
  if state == 'restricted':
    return "%s: Device in restricted mode. A partial backup was made" % (name)
  
  return
"""

"""
def net_backup_ssh_vyos(name, ip, username, password, path, port=22):
"""
"""
    Adopted for backup configuration on ssh-cli VyOS (Vyatta OS) devices.
"""
"""  
  re_hostname_t1 = re.compile(r'^(?P<username>[A-Za-z0-9-_]+)@(?P<hostname>[A-Za-z0-9-_]+):(?P<other>.*)$')
  
  try:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, port, username, password, look_for_keys=False, timeout=ssh_tcp_timeout, auth_timeout=ssh_auth_timeout)
    chan = ssh.invoke_shell()
    time.sleep(2)
    
    # Get first console greetings
    output = chan.recv(999999)
    # Decode string from byte format
    output = output.decode("utf-8")
    # Get hostname
    output = "".join(output.splitlines()[-1:])
    # Remove possible whitespaces (in the end of output)
    output = output.strip()
    
    a = re_hostname_t1.fullmatch(output)
    if a != None:
      # Redefine host name from CLI
      if name == ip:
        name = a.group('hostname')
        path = path.replace(ip, name)
    else:
      pass
    
    # In privileged mode allows display output without any breaks and pauses
    chan.send('set terminal length 0\n')
    time.sleep(1)
    
    # Clear output before capture configuration commands
    output = chan.recv(999999)
    
    chan.send('show configuration commands\n')
    time.sleep(10)
    output = chan.recv(999999)
  except paramiko.AuthenticationException:
    return "%s: Authentication failed, verify credentials used for connection" % name
  except paramiko.SSHException as e:
    return "%s: Unable to establish SSH connection: %s" % (name, e)
  except paramiko.BadHostKeyException as e:
    return "%s: Unable to verify device's host key: %s" % (name, e)
  except Exception as e:
    return ("%s: %s" % (name, e))
  finally:
    ssh.close()

  if not os.path.exists(path):
    try:
      os.makedirs(path)
    except OSError:
      return ("Error creating derectory %s" % path)

  now = datetime.now()
  timestamp = now.strftime("%d-%b-%y--%H-%M-%S")
  
  filename = "%s/%s--%s.txt" % (path, name, timestamp)
  
  try:
    f = open(filename, 'w')
    f.write(output.decode("utf-8"))
  except OSError as e:
    if e.errno == errno.ENOSPC:
      return "%s: Can't create backup file. No disk space left" % name
    else:
      return ("%s: %s" % (name, e))
  except Exception as e:
    return ("%s: %s" % (name, e))
  finally:
    f.close()
  
  return
"""

"""
def net_backup_ssh_gaia(name, ip, username, password, path, port=22):
"""
"""
    Adopted for backup configuration on ssh-cli (clish) Gaia OS devices.
"""
"""  
  re_hostname_t1 = re.compile(r'^(?P<hostname>[A-Za-z0-9-_]+)>$')
  
  try:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, port, username, password, look_for_keys=False, timeout=ssh_tcp_timeout, auth_timeout=ssh_auth_timeout)
    chan = ssh.invoke_shell()
    time.sleep(2)
    
    # Get first console greetings
    output = chan.recv(999999)
    # Decode string from byte format
    output = output.decode("utf-8")
    # Get hostname
    output = "".join(output.splitlines()[-1:])
    # Remove possible whitespaces (in the end of output)
    output = output.strip()
    
    a = re_hostname_t1.fullmatch(output)
    if (a != None) and (name == ip):
      # Redefine host name from CLI
      name = a.group('hostname')
      path = path.replace(ip, name)
    
    # Allows display output without any breaks and pauses
    chan.send('set clienv rows 0\n')
    time.sleep(1)
    
    # Clear output before capture configuration commands
    output = chan.recv(999999)
    
    chan.send('show configuration\n')
    time.sleep(10)
    output = chan.recv(999999)
  except paramiko.AuthenticationException:
    return "%s: Authentication failed, verify credentials used for connection" % name
  except paramiko.SSHException as e:
    return "%s: Unable to establish SSH connection: %s" % (name, e)
  except paramiko.BadHostKeyException as e:
    return "%s: Unable to verify device's host key: %s" % (name, e)
  except Exception as e:
    return ("%s: %s" % (name, e))
  finally:
    ssh.close()

  if not os.path.exists(path):
    try:
      os.makedirs(path)
    except OSError:
      return ("Error creating derectory %s" % path)

  now = datetime.now()
  timestamp = now.strftime("%d-%b-%y--%H-%M-%S")
  
  filename = "%s/%s--%s.txt" % (path, name, timestamp)
  
  try:
    f = open(filename, 'w')
    f.write(output.decode("utf-8"))
  except OSError as e:
    if e.errno == errno.ENOSPC:
      return "%s: Can't create backup file. No disk space left" % name
    else:
      return ("%s: %s" % (name, e))
  except Exception as e:
    return ("%s: %s" % (name, e))
  finally:
    f.close()
  
  return
"""

"""
def net_backup_ssh(name, ip, username, password, path, enable=None, port=22, ostype=None):
"""
"""
    Adopted for backup plain-text configuration on ssh-cli network devices. Supports:
    - Cisco IOS
    - Cisco NX-OS
    - Cisco ASDM (ASA)
    - VyOS (Vyatta OS)
    - Gaia (Checkpoint Gaia OS)
    :ostype defines OS type of device:
        ios (default)
        nx-os
        asa
        vyos
        gaia
"""
""" 
  # In 3.10 introduced match case statement, if/case used for 3.9 or lower
  if ostype == 'vyos':
    return net_backup_ssh_vyos(name, ip, username, password, path, port)
  elif ostype == 'gaia':
    return net_backup_ssh_gaia(name, ip, username, password, path, port)
  else:
  # By default Cisco, (IOS)
    return net_backup_ssh_cisco(name, ip, username, password, path, enable, port, ostype)
"""

"""
Presented functions usage examples and test output
"""
if __name__ == '__main__':
  print ('Custom functions module test output section:')
  print ('--------------------------------------------')
  
  #print (generate_password())