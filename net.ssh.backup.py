#!/usr/bin/python3
# Copyright 2023 Sergey Malkov

"""
Use this section to describe script functionalty
"""

import os
import sys
import argparse
import re
import multiprocessing
import getpass
# Import Custom Functions libraries
# sys.path[0] contains absolute path to directory contains running script 
this_path = sys.path[0]
sys.path.append(this_path+'/modules')
import cf
import cfzbx
import cfsec


"""
Define mandatory and optional arguments using argparse module functions
"""
parser = argparse.ArgumentParser(description='Creates backup via ssh for selected list of network devices. Supports: Cisco (IOS, NX-OS, ASA ASDM platforms), VyattaOS (VyOS).')
parser.add_argument('--settings', '-s', help="Name of text file where settings is defined", type=str, required=True)
parser.add_argument('--display', '-d', help="Turns on log output in console. Default: False", action='store_true')
parser.add_argument('--credentials', '-c', help="Enables input authZ credentials for any integration. Default: False", action='store_true')
args = parser.parse_args()


def finish_script(success=False):
  """
  Global-defined function, that forms script nesessary exit actions, f.e. push email reports.
  "success" attribute defines correct exit action or error interruption.
  Note that it is reasonable to use this function when log.record._state attribute is fixed
  Before standard log.write_exit() function is used to interrupt script
  """
  if not success:
    log.record.timestamp()
    log.write(log.log_ewf_msg)
  # Next block pushes email reports, if mail server attributes defined in settings file
  if log.record._state:
    log.record.off()
    log.write('Sending mail reports')
    body = log.record.html()
    
    mail = cf.smtp()
    mail.fromAddr = params['smtp_sender']
    mail.smtpServer = params['smtp_server']
    mail.smtpPort = params['smtp_port']
    mail.username = params['smtp_user']
    mail.password = params['smtp_password']
    mail.tls = params['smtp_tls']
    mail.fAuth = params['smtp_auth']
    
    if isinstance(params['mail_recepient'], str): params['mail_recepient'] = [params['mail_recepient']]
    for r in params['mail_recepient']:
      mail.send(params['mail_subject'], body, r)
      if not mail.error:
        log.write('>[OK] %s: report successfully sent' % r)
      else:
        log.write('>[ERROR]%s: %s' % (r, mail.error))
  # Finish python instance
  sys.exit()


def main_init():
  """
  Use main_init function in module:
  1. Define global variables;
  2. Determine log file and start logging procedure;
  3. Determine timer class if necessary;
  4. Read params template if it used in script.
  """
  global log
  global timer
  global params
  global devices
  global multithreads
  global fpwd
  global min_size_bkp
  
  # Defile global variable for backup job list
  devices = []
  # Define params template
  params = {
    # Primary params
    'description': None,
    'zabbix_server': None,
    'zabbix_username': None,
    'zabbix_password': None,
    'zabbix_group': None,
    'default_username': None,
    'default_password': None,
    'backup_path': None,
    'device': None,
    'decryption_key': None,
    # Mail server params for reports
    'smtp_server': None,
    'smtp_port': 587,
    'smtp_sender': None,
    'smtp_user': None,
    'smtp_password': None,
    'smtp_tls': True,
    'smtp_auth': 'LOGIN',
    'mail_subject': 'Backup job result',
    'mail_recepient': None
  }
  # Maximum threads value for backup job (running in multiprocessing)
  multithreads = 10
  # Minimum free space in default backup directory for starting backup procedure (in MB)
  min_size_bkp = 100
  # Minimum free space in script directory for starting backup procedure (logging purposes) (in MB)
  min_size_log = 1
  
  # Disable SSL-Certificate validation
  cf.rdisablesslwarnings()
  
  # Define default log file path
  log_path = this_path + '/logs'
  log_name = cf.script_name() +'.log'
  # Create default logger object for current script
  log = cf.Log(log_name, log_path)
  # Set abnormal log message (Exit with fail)
  log.log_ewf_msg = 'Backup procedure stopped. See logs above for reason.'
  #
  log.set_lvl_prefix()
  # Turn on console display mode
  if args.display:
    log.display.on()
    log.display.prefix()
    # Define color templates for binded log display output
    log.display.color('[INFO]', cf.console.fg.blue)
    log.display.color('[OK]', cf.console.fg.green)
    log.display.color('[ADD]', cf.console.fg.green)
    log.display.color('[DONE]', cf.console.fg.green)
    log.display.color('[MIS]', cf.console.fg.orange)
    log.display.color('[WARN]', cf.console.fg.orange)
    log.display.color('[FAIL]', cf.console.fg.red)
    log.display.color('[ERROR]', cf.console.fg.red)
  
  # Define Timer class for measurement script's processing time
  timer = cf.Timer()
  
  # Push delimiter to log file (before start recording for email report)
  log.write('--------------------------')
  
  # Turn on recording to log buffer (for email report)
  # Note that the log buffer begins to form before user-defined parameters are received.
  # This allows you to include events generated up to this point in the mail report
  log.record.on()
  log.record.prefix()
  log.record.color('[INFO]', cf.rgb.DodgerBlue)
  log.record.color('[OK]', cf.rgb.green)
  log.record.color('[ADD]', cf.rgb.green)
  log.record.color('[DONE]', cf.rgb.green)
  log.record.color('[MIS]', cf.rgb.orange)
  log.record.color('[WARN]', cf.rgb.orange)
  log.record.color('[FAIL]', cf.rgb.Tomato)
  log.record.color('[ERROR]', cf.rgb.Tomato)
  
  # Include timestamp in first log record
  log.record.timestamp()
  log.write('Start backup procedure')
  log.record.timestamp(False)
  
  # Check-up for free space in running script directory (for logging purposes)
  fs = cf.get_disk_size()
  if fs.error is None:
    if (fs.free.mb() >= min_size_log):
      log.write('>[OK] Free space in script directory: %s' % fs.free.st())
    else:
      log.write("[ERROR] Free space in script directory is less than minimum value: %s/%s Mb" % (fs.free.mb(), min_size_log), lvl=1)
      log.write_exit()
  
  # Read settings for running script
  log.write('Preparing for start backup procedure')
  # Define param and custom files path
  param_path = this_path + '/params/' + cf.script_name() + '/'
  # Define mandatory settings file
  params_file = param_path + args.settings
  # Read user-defined settings
  _params = cf.get_settings(params_file, params.keys())
  if not _params:
    log.write('[ERROR] Cannot access settings file: %s' % params_file, lvl=1)
    log.write_exit()
  log.write('[OK] Settings received from file: %s' % params_file, lvl=1)
  # Create result settings dict, where non-defined attributes have "None" value
  params.update(_params)
  
  #if --credentials flag is selected, section wipes out all credentials values even it defined in --settings file 
  if args.credentials:
    params['default_username'] = ''
    params['default_password'] = ''
    params['zabbix_username'] = ''
    params['zabbix_password'] = ''
  else:
    # Fernet secret key is not needed (mandatory) if --credentials flag is selected, so default_password value decryption is skipped even it's presented
    if not params['decryption_key']:
      log.write('[ERROR] Mandatory attribute decryption_key is not presented in settings file', lvl=1)
      log.write_exit()
    # Create Secret Object for passwords decryption purpose
    fpwd = cfsec.Secret()
    fpwd.key_init(params['decryption_key'])



def main_preprocessing():
  """docstring"""

  _devices = dict()

  re_device_attr_template = {
    'ip': re.compile(r'(?:^|;)(?P<attr>ip=(?P<ip>[0-9\.]{7,15})(?:$|;))'),
    'name': re.compile(r'(?:^|;)(?P<attr>name=(?P<name>[A-Za-z0-9-_]+)(?:$|;))'),
    'username': re.compile(r'(?:^|;)(?P<attr>username=(?P<username>[A-Za-z0-9-_]+)(?:$|;))'),
    'password': re.compile(r'(?:^|;)(?P<attr>password=(?P<password>[A-Za-z0-9-_=]+)(?:$|;))'),
    'port': re.compile(r'(?:^|;)(?P<attr>port=(?P<port>[0-9]{2,5})(?:$|;))'),
    'enable': re.compile(r'(?:^|;)(?P<attr>enable=(?P<enable>[A-Za-z0-9-_=]+)(?:$|;))'),
    'path': re.compile(r'(?:^|;)(?P<attr>path=(?P<path>[A-Za-z0-9-_]+)(?:$|;))'),
    'os': re.compile(r'(?:^|;)(?P<attr>os=(?P<os>[A-Za-z0-9-_]+)(?:$|;))')
  }
  re_device_simple_template = {
    'ip': re.compile(r'(?:^|;|:)(?P<attr>(?P<ip>[0-9\.]{7,15})(?:$|;|:))'),
    'name': re.compile(r'(?:^|;|:)(?P<attr>(?P<name>[A-Za-z0-9-_]+)(?:$|;|:))')
  }
  
  # Trying to decrypt smtp_password with decryption_key value
  if (params['smtp_server'] and params['smtp_port'] and params['smtp_sender'] and params['smtp_user'] and params['smtp_password'] and params['mail_recepient']):
    dec_smtp_password = fpwd.decrypt(params['smtp_password'])
    if not dec_smtp_password:
      log.record.off(wipe=True)
      log.write('[ERROR] smtp_password cannot be decrypted with presented decryption_key', lvl=1)
      log.write('[INFO] Mail reports will not be sent', lvl=1)
    else:
      params['smtp_password'] = dec_smtp_password
  else:
    log.record.off(wipe=True)
  
  # 
  if params['backup_path'] is None or params['backup_path'] == '':
    log.write('[ERROR] backup_path parameter is not defined in settings file', lvl=1)
    #log.write_exit()
    finish_script()
  if (not os.path.isdir(params['backup_path'])):
    try:
      os.makedirs(params['backup_path'])
    except Exception as e:
      log.write("[ERROR] Can't create backup directory '%s': %s" % (params['backup_path'], e), lvl=1)
      #log.write_exit()
      finish_script()
      
    log.write("[OK] Default backup directory created: '%s'" %params['backup_path'], lvl=1)
  else:
    log.write("[OK] Default backup directory defined and exists: '%s'" %params['backup_path'], lvl=1)
  # Check-up for free space in backup path directory
  fs = cf.get_disk_size(params['backup_path'])
  if fs.error is None:
    if (fs.free.mb() >= min_size_bkp):
      log.write('[OK] Free space in backup directory: %s' % fs.free.st(), lvl=1)
    else:
      log.write("[ERROR] Free space in default backup directory is less than minimum value: %s/%s Mb" % (fs.free.mb(), min_size_bkp), lvl=1)
      #log.write_exit()
      finish_script()
  else:
    log.write("[WARN] Can't calculate free space in backup directory: %s" % fs.error, lvl=1)
  
  # Console print description of settings file (only with --display arg)
  if args.display and params['description']:
    print(params['description'])
  
  if args.credentials:
    log.display.off()
    print('Credentials input flag is selected. Define it manually:')
    # default_username
    while len(params['default_username'])==0:
      params['default_username'] = input(' Specify default username for ssh connection: ')
      if len(params['default_username'])==0:
        print(' Invalid input. Default username value cannot be empty')
    # default_password
    while len(params['default_password'])==0:
      params['default_password'] = getpass.getpass(' Specify password for "%s": ' % params['default_username'])
      if len(params['default_password'])==0:
        print(' Invalid input. Password cannot be empty')
    log.write('Reading user-defined credentials from manual input')
    log.write('default_username: %s' % params['default_username'], lvl=1)
    #
    if params['zabbix_server'] and params['zabbix_group']:
      # zabbix_username
      while len(params['zabbix_username'])==0:
        params['zabbix_username'] = input(' Specify Zabbix API username: ')
        if len(params['zabbix_username'])==0:
          print(' Zabbix username value cannot be empty')
      # zabbix_password
      while len(params['zabbix_password'])==0:
        params['zabbix_password'] = getpass.getpass(' Specify password for "%s": ' % params['zabbix_username'])
        if len(params['zabbix_password'])==0:
          print(' Password cannot be empty')
      log.write('zabbix_username: %s' % params['zabbix_username'], lvl=1)
    if args.display:
      log.display.on()
  
  log.write('Parse script setting')
  if not args.credentials:
    # Decrypt default_password value with Fernet algorythm
    #if params['default_username'] and params['default_password']:
    if params['default_password']:
      dec_default_password = fpwd.decrypt(params['default_password'])
      #dec_default_password = sec_decrypt_password(params['decryption_key'], params['default_password'])
      if not dec_default_password:
        log.write('[ERROR] default_password cannot be decrypted with presented decryption_key', lvl=1)
        #log.write_exit()
        finish_script()
      params['default_password'] = dec_default_password
    else:
      # Wipe default_password (do not able to use without each other)
      log.write('[INFO] Default credentials is not defined. Check that both default_username and default_password values is presented', lvl=1)
  
  device_attr_template = {
    'ip': None,
    'name': None,
    'username': params['default_username'],    # Defined username value in params
    'password': params['default_password'],    # Decrypted password if it defined
    'port': 22,
    'enable': None,
    'path': None,
    'os': None
    #'os': 'ios'    # Default OS type = Cisco IOS
  }
  
  # Process predefined device list
  if params['device']:
    if isinstance(params['device'], str):
      params['device'] = [params['device']]
    for device in params['device']:
      # Copy device information line for parse
      _device = str(device)
      # Device extended defenition
      _t = device_attr_template.copy()
      for attr, template in re_device_attr_template.items():
        match = template.search(_device)
        if match:
          _t[attr] = match.group(attr)
          _device = _device[0:match.start('attr')] + _device[match.end('attr'):]
      
      name = _t.pop('name', None) or _t['ip']
      # Device simple defenition
      if not name:
        for attr, template in re_device_simple_template.items():
          match = template.search(_device)
          if match:
            _t[attr] = match.group(attr)
            _device = _device[0:match.start('attr')] + _device[match.end('attr'):]
        if not _t['ip']:
          # Generate error message for wrong device line
          log.write('[ERROR] IP address must be defined using simple syntax: %s' % device, lvl=1)
          continue    # Jump to next device
        name = _t.pop('name', None) or _t['ip']
      
      # Check device login password and decrypt if it presented
      if _t['password'] != device_attr_template['password']:
        dec_password = fpwd.decrypt(_t['password'])
        #dec_password = sec_decrypt_password(params['decryption_key'], _t['password'])
        if dec_password:
          _t['password'] = dec_password
        elif device_attr_template['password']:
          _t['password'] = device_attr_template['password']
          log.write('[WARN] %s: device login password defined but cannot be decrypted with decryption_key, default_password value will be used' % name, lvl=1)
        else:
          log.write('[ERROR] %s: device login password defined but cannot be decrypted with decryption_key' % name, lvl=1)
          continue
      
      # Check enable password and decrypt if it presented
      if _t['enable']:
        dec_password = fpwd.decrypt(_t['enable'])
        #dec_password = sec_decrypt_password(params['decryption_key'], _t['enable'])
        if dec_password:
          _t['enable'] = dec_password
        else:
          log.write('[ERROR] %s: device enable password defined but cannot be decrypted with decryption_key value' % name, lvl=1)
      
      # Generate default path
      if not _t['path']:
        _t['path'] = '%s/%s' % (params['backup_path'], name)
      # Generate info error if 
      if _device != '':
        log.write('[WARN] %s: incorrect syntax in device information line: %s' % (name, _device), lvl=1)
        
      _devices[name] = _t
  else:
    log.write('[INFO] Manual device list is not presented in settings file', lvl=1)
  
  
  # Process Zabbix API
  if params['zabbix_server'] and params['zabbix_username'] and params['zabbix_password'] and params['zabbix_group']:
    # if --credentials flag used, zabbix_username and zabbix_password should be defined manually
    if not args.credentials:
    # Decrypt zabbix password value (if presented) with Fernet algorythm
      params['zabbix_password'] = fpwd.decrypt(params['zabbix_password'])
      #params['zabbix_password'] = sec_decrypt_password(params['decryption_key'], params['zabbix_password'])
    
    if params['zabbix_password']:
      log.write('Get information from Zabbix API')
      zbx = cfzbx.Zabbix(params['zabbix_server'])
      # Login into Zabbix API
      zbx.get_token(params['zabbix_username'], params['zabbix_password'])
      if not zbx.error:
        # Get Hosts from defined Zabbix Groups 
        hosts = zbx.get_net_in_groups(params['zabbix_group'])
        hosts_count = len(hosts.values())
        if hosts_count > 0:
          for host in hosts.values():
            if not host['name'] in _devices:
              _devices[host['name']] = device_attr_template.copy()
            _devices[host['name']]['ip'] = host['ip']
            _devices[host['name']]['path'] = params['backup_path']+'/'+host['group']+'/'+host['name']
            if _devices[host['name']]['os'] and not host['software']:
              pass
            else:
              _devices[host['name']]['os'] = host['software']
          log.write('[OK] %s devices imported from Zabbix database' % hosts_count, lvl=1)
        else:
          log.write('[INFO] Script successfully connected to Zabbix, but neither devices are imported. Check defined groups', lvl=1)
      else:
        log.write('[ERROR] %s' % zbx.error, lvl=1)
    else:
      log.write('[ERROR] zabbix_password cannot be decrypted with presented decryption_key', lvl=1)
  
  # Validate that every device in [_devices] contains mandatary params: ip, username, password
  # And form list of dicts, where every dict contains single device parameters
  log.write('Create Backup Job list')
  for name,device in _devices.items():
    if (not device['username'] or not device['password']):
      log.write('[MIS] %s: default username and password expected but not defined' % name, lvl=1)
      continue
    if not device['ip']:
      log.write('[MIS] %s: device IPv4 address is not defined' % name, lvl=1)
      continue
    device['os'] = cf.net_supported_software.get(device['os'].lower())
    if not device['os']:
      log.write('[MIS] %s: OS type is not supported or not defined' % name, lvl=1)
      continue    # Jump to next device
    
    devices.append(dict(name=name, ip=device['ip'], username=device['username'], password=device['password'], path=device['path'], port=device['port'], enable=device['enable'], os=device['os']))
    log.write('[ADD] %s [%s]' % (name, device['ip']), lvl=1)
  
  if len(devices) == 0:
    log.write('[INFO] Devices is not presented or defined attributes is invalid', lvl=1)


def ssh_backup_flow(attr):
  """
    [Example] attr = {
      'name': 'PKL-SW-TEST-C9300-48P',
      'ip': '10.0.64.25',
      'username': 'admin',
      'password': '123456789',
      'path': '/py/test/PKL-SW-TEST-C9300-48P',
      'enable': xxx,
      'port': 22,
      'os': ios/nx-os/asa/vyos
    }
  """
  # 12.02.23
  """
  result = cf.net_backup_ssh(attr['name'], attr['ip'], attr['username'], attr['password'], attr['path'], attr['enable'], attr['port'], attr['os'])
  # result = None: means that backup successfully done
  if result:
    result = '[FAIL] %s' %result
    return False, result
  else:
    result = '[DONE] %s: configuration backup successfully done' % attr['name']
    return True, result
  """
  result = cf.net_backup_ssh(attr['name'], attr['ip'], attr['username'], attr['password'], attr['path'], attr['enable'], attr['port'], attr['os'])
  if result.ok:
    if result.size < 512:
      result.ok = False
      msg = '[FAIL] %s: Backup file size is less then 512 Bytes' % attr['name']
    elif result.msg:
      msg = '[DONE] %s: %s' % (attr['name'], result.msg)
    else:
      msg = '[DONE] %s: conf backup successfully done. Size: %s Bytes' % (attr['name'], cf.convert_bytes(result.size))
  else:
    msg = '[FAIL] %s: %s' % (attr['name'], result.msg)
  
  return result.ok, msg


def main_process():
  if len(devices) == 0:
    log.write('Backup job cannot be started because no device is defined or it attributes is invalid')
    #return
    finish_script()
    
  log.write('Run backup job in multiprocessing (max %s processes)' % multithreads)
  timer.start()
  multiprocessing.set_start_method('spawn')
  with multiprocessing.Pool(processes=multithreads) as process_pool:
    backup_result = process_pool.map(ssh_backup_flow, devices, 1)  # ssh_backup_flow - function, devices - argument
    process_pool.close()
    process_pool.join()
  timer.finish()
  
  backup_done = 0
  backup_fail = 0
  for result in backup_result:
    if result[0]:
      backup_done +=1
    else:
      backup_fail +=1
    log.write(result[1], lvl=1)
  log.write('Backup job completed: [Total: %i] [Success: %i] [Failed: %i]' % (len(devices), backup_done, backup_fail), display=True)
  log.write('Time ellapsed: %s' % timer.result)
  # Finish script execution and send email notifications (if recepients is defined)
  finish_script(success=True)
  

def main():
  main_init()
  main_preprocessing()
  main_process()


if __name__ == '__main__':
  main()