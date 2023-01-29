#!/usr/bin/python3
# Copyright 2022 Sergey Malkov

"""
Use this section to describe script functionalty
"""

import os
import sys
import argparse
import re
import multiprocessing
import getpass
import paramiko
import time
# Import Custom Functions libraries
# sys.path[0] contains absolute path to directory contains running script 
this_path = sys.path[0]
sys.path.append(this_path+'/modules')
import cf
import cfsec



"""
Define mandatory and optional arguments using argparse module functions
"""
parser = argparse.ArgumentParser(description='Initiate AP autoreload if it uptime more than N days')
parser.add_argument('--settings', '-s', help="Name of text file where settings is defined", type=str, required=True)
parser.add_argument('--display', '-d', help="Turns on log output in console. Default: False", action='store_true')
parser.add_argument('--credentials', '-c', help="Enables input authZ credentials for any integration. Default: False", action='store_true')
args = parser.parse_args()


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
  global aps
  global fpwd
  
  # Defile global variable for backup job list
  aps = {}
  # Define params template
  params = {
    'description': None,
    'wlc_address': None,
    'wlc_port': 22,
    'wlc_username': None,
    'wlc_password': None,
    'days_gone': None,
    'ap_reset_count': 9999,
    'decryption_key': None
  }
  # Minimum free space in script directory for starting backup procedure (logging purposes) (in MB)
  min_size_log = 1
  
    # Define default log file path
  log_path = this_path + '/logs'
  log_name = cf.script_name() +'.log'
  # Create default logger object for current script
  log = cf.Log(log_name, log_path)
  # Set abnormal log message (Exit with fail)
  log.log_ewf_msg = 'WLC AP autoreload task stopped. See logs above for reason.'
  #
  log.set_lvl_prefix()
  # Turn on console display mode
  if args.display:
    log.display.on()
    log.display.prefix()
    # Define color templates for binded log display output
    log.display.color('[INFO]', cf.console.fg.blue)
    log.display.color('[OK]', cf.console.fg.green)
    log.display.color('[ERROR]', cf.console.fg.red)
    log.display.color('[RL]', cf.console.fg.orange)
    log.display.color('[AB]', cf.console.fg.red)
  
  # Define Timer class for measurement script's processing time
  timer = cf.Timer()
  
  # Push delimiter to log file
  log.write('--------------------------')
  log.write('Start WLC AP autoreload task')
  
  # Check-up for free space in running script directory (for logging)
  fs = cf.get_disk_size()
  if fs.error is None:
    if (fs.free.mb() >= min_size_log):
      log.write('>[OK] Free space in script directory: %s' % fs.free.st())
    else:
      log.write("[ERROR] Free space in script directory is less than minimum value: %s/%s Mb" % (fs.free.mb(), min_size_log), lvl=1)
      log.write_exit()
  
  # Read settings for running script
  log.write('Preparing for autoreload task')
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


def main_preprocessing():
  """docstring"""

  # Console print description of settings file
  if args.display and params['description']:
    print(params['description'])
  
  if args.credentials:
    log.display.off()
    
    #if --credentials flag is selected, section wipes out all credentials values even it defined in --settings file 
    params['wlc_username'] = ''
    params['wlc_password'] = ''
    
    print('Credentials input flag is selected. Define it manually:')
    # wlc_username
    while len(params['wlc_username'])==0:
      params['wlc_username'] = input(' Specify WLC username for ssh connection: ')
      if len(params['wlc_username'])==0:
        print(' Invalid input. Username value cannot be empty')
    # wlc_password
    while len(params['wlc_password'])==0:
      params['wlc_password'] = getpass.getpass(' Specify password for "%s": ' % params['wlc_username'])
      if len(params['wlc_password'])==0:
        print(' Invalid input. Password cannot be empty')
    log.write('Reading user-defined credentials from manual input')
    log.write('wlc_username: %s' % params['wlc_username'], lvl=1)
    
    if args.display:
      log.display.on()
  
  log.write('Parse script setting')
  
  if not cf.is_valid_ip(params['wlc_address']):
    log.write('[ERROR] wlc_address parameter is not defined in settings file or incorrect', lvl=1)
    log.write_exit()
  if not cf.is_valid_port(params['wlc_port']):
    log.write('[ERROR] wlc_port parameter is not defined in settings file or incorrect', lvl=1)
    log.write_exit()
  
  params['days_gone'] = cf.is_int(params['days_gone'])
  if not params['days_gone']:
    log.write('>[ERROR] days_gone parameter is not defined in settings file or incorrect')
    log.write_exit()
  params['ap_reset_count'] = cf.is_int(params['ap_reset_count'])
  if not params['ap_reset_count']:
    log.write('>[ERROR] ap_reset_count parameter is not defined in settings file or incorrect')
    log.write_exit()
  
  if not args.credentials:
    # Fernet secret key is not needed (mandatory) if --credentials flag is selected, so wlc_password value decryption is skipped even it's presented
    if not params['decryption_key']:
      log.write('>[ERROR] Mandatory attribute decryption_key is not presented in settings file')
      log.write_exit()
    # Create Secret Object for passwords decryption purpose
    fpwd = cfsec.Secret()
    fpwd.key_init(params['decryption_key'])
    
    # Decrypt wlc_password value with Fernet algorythm
    if params['wlc_username'] and params['wlc_password']:
      dec_wlc_password = fpwd.decrypt(params['wlc_password'])
      if not dec_wlc_password:
        log.write('[ERROR] wlc_password cannot be decrypted with presented decryption_key', lvl=1)
        log.write_exit()
      params['wlc_password'] = dec_wlc_password
    else:
      # Wipe wlc_password (do not able to use without each other)
      log.write('>[ERROR] WLC credentials is not defined. Check that both default_username and default_password values is presented')
      log.write_exit()
  
  log.write('>[OK] All setting validated')


def wlc_ap_autoreload(ip, port, username, password, days_gone=30, ap_reset_count=9999):
  """

  """
  
  # OUTPUT [show ap uptime]:
  # -----
  #Number of APs.................................... 40
  #Global AP User Name.............................. cplnetadm
  #Global AP Dot1x User Name........................ Not Configured
  #
  #AP Name              Ethernet MAC       AP Up Time               Association Up Time
  #------------------   -----------------  -----------------------  -----------------------
  #E4_L4_03             dc:8c:37:fe:8f:ea  298 days, 19 h 02 m 33 s   112 days, 17 h 17 m 31 s
  #E4_L4_08             dc:8c:37:fe:90:36  298 days, 19 h 02 m 43 s   112 days, 17 h 17 m 18 s
  #E4_L4_11             dc:8c:37:fe:90:3a  298 days, 19 h 02 m 50 s   112 days, 17 h 17 m 17 s
  #E2_L3_09             78:bc:1a:1d:61:bc  42 days, 22 h 08 m 18 s   42 days, 22 h 06 m 04 s
  #E2_L3_25             70:61:7b:ae:07:c2  1 days, 00 h 50 m 36 s   1 days, 00 h 48 m 16 s
  re_output = re.compile(r'^(?P<ap_name>[A-Za-z0-9_]+).*\s(?P<ap_up_d>[0-9]+)\sdays,\s(?P<ap_up_h>[0-9]+)\sh\s(?P<ap_up_m>[0-9]+)\sm\s(?P<ap_up_s>[0-9]+)\ss.*\s(?P<ap_as_d>[0-9]+)\sdays,\s(?P<ap_as_h>[0-9]+)\sh\s(?P<ap_as_m>[0-9]+)\sm\s(?P<ap_as_s>[0-9]+)\ss$')
  

  try:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, port, username, password, look_for_keys=False, timeout=cf.ssh_tcp_timeout, auth_timeout=cf.ssh_auth_timeout)
    chan = ssh.invoke_shell()
    time.sleep(2)
    
    # Allows display output without any breaks and pauses
    chan.send('config paging disable\n')
    time.sleep(1)
    
    chan.send('show ap uptime\n')
    time.sleep(3)
    output = chan.recv(999999)
    
    a = output.split(b'\r\n')
    for line in a:
      line = line.decode('UTF-8')
      attr = re_output.fullmatch(line)
      if attr == None:
        # Invalid attribute format
        continue
      else:
        aps[attr.group('ap_name')] = int(attr.group('ap_up_d'))
        #print(line)
    
    for ap in aps:
      if aps[ap] < days_gone:
        log.write('>[OK] AP: %s uptime %d days is lower than %d' % (ap, aps[ap], days_gone))
      elif ap_reset_count > 0:
        # Initiate reload
        log.write('>[RL] AP: %s uptime %d days is greater than %d. Reload pushed' % (ap, aps[ap], days_gone))
        ap_reset_count = ap_reset_count-1
        # Send AP restart
        chan.send('config ap reset %s\n' % ap)
        time.sleep(1)
        chan.send('y\n')
        time.sleep(60)
      else:
        log.write('>[AB] AP: %s uptime %d days is greater than %d, but reset quota is exhausted. Reload declined' % (ap, aps[ap], days_gone))
    
    chan.send('config paging enable\n')
    
  except paramiko.AuthenticationException:
    return "WLC %s: Authentication failed, verify credentials used for connection" % ip
  except paramiko.SSHException as e:
    return "WLC %s: Unable to establish SSH connection: %s" % (ip, e)
  except paramiko.BadHostKeyException as e:
    return "WLC %s: Unable to verify device's host key: %s" % (ip, e)
  except Exception as e:
    return ("%s" % e)
  finally:
    ssh.close()
 
  return


def main_process():
  log.write('Connecting to Cisco Wireless Controller')
  timer.start()
  
  result = wlc_ap_autoreload(params['wlc_address'], params['wlc_port'], params['wlc_username'], params['wlc_password'], params['days_gone'], params['ap_reset_count'])
  if result:
    log.write(result)
    log.write_exit()
  
  timer.finish()
  log.write('Time ellapsed: %s' % timer.result)


def main():
  main_init()
  main_preprocessing()
  main_process()


if __name__ == '__main__':
  main()