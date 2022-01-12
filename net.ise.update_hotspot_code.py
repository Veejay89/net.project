#!/usr/bin/python3
# Copyright 2022 Sergey Malkov

"""
Module to update Cisco ISE HotSpot UAP Access Code
After updating, module might send new code by email if smtp server defined in params
"""

import requests
import time
from datetime import datetime, timedelta
import re
import sys
# Import Custom Functions libraries
# sys.path[0] contains absolute path to directory contains running script 
this_path = sys.path[0]
sys.path.append(this_path+'/modules')
import cf
import cfise
from cfsec import sec_decrypt_password




def main():
  # Disable SSL-Certificate validation
  from requests.packages.urllib3.exceptions import InsecureRequestWarning
  requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
  
  # Set abnormal log message (Exit with fail)
  ewf_log = 'Access code update procedure failed. See logs above to determine the reason'
  # Define default log file path
  log_path = this_path + '/logs/'+ cf.script_name() +'.log'
  cf.log_define_file(this_path + '/logs/'+ cf.script_name() +'.log')
  # Define param and custom files path
  param_path = this_path + '/params/' + cf.script_name() + '/'

  cf.log('--------------------------')
  cf.log('Launch hotspot code update procedure')

  if len(sys.argv) >= 2:
    cf.log('Reading settings', lvl=1)
    file_settings = param_path + sys.argv[1]
    settings = cf.get_settings(file_settings)
    if settings == False:
      cf.log('Cannot open file with mandatory settings: '+file_settings, lvl=2)
      cf.log_exit(ewf_log)
    else:
      cf.log('Mandatory settings received from: '+file_settings, lvl=2)
    
    if 'smtp_user' not in settings:
      settings['smtp_user'] = ''
    if 'smtp_auth' not in settings:
      settings['smtp_auth'] = False
    if 'mail_recepients' in settings:
      if isinstance(settings['mail_recepients'], str): settings['mail_recepients'] = [settings['mail_recepients']]
    
    dec_smtp_password = sec_decrypt_password(settings['decryption_key'], settings['smtp_password'])
    settings['dec_smtp_password'] = dec_smtp_password
    # Add exception
    
    dec_ise_api_password = sec_decrypt_password(settings['decryption_key'], settings['ise_api_password'])
    settings['ise_api_password'] = dec_ise_api_password
    # Add exception
    
    if len(sys.argv) >= 3:
      file_email_body = param_path + sys.argv[2]
      try:
        with open(file_email_body,'r') as f:
          email_body = f.read()
      except IOError as e:
        cf.log('Cannot open file with custom message body template: '+file_email_body, lvl=2)
        cf.log(str(e), lvl=3)
        cf.log_exit(ewf_log)
      
      
    else:
      email_body = False
  else:
    cf.log('Mandatory arguments are not defined in command line', lvl=1)
    cf.log_exit(ewf_log)
  
  

  
  
  cf.log('Defined settings:', lvl=1)
  cf.log('ISE HotSpot Portal Name: '+settings['hotspot_portal_name'], lvl=2)
  cf.log('ISE HotSpot Portal ID: '+settings['hotspot_portal_id'], lvl=2)
  
    
  ise = cfise.IseERSApi(settings['ise_api_pan'],settings['ise_api_username'], settings['ise_api_password'])
  ise.port(settings['ise_api_port'])

  
  cf.log('Reading HotSpot portal ID', lvl=1)
  hotspot_portal_id = ise.get_portal_id(settings['hotspot_portal_name'])
  if ise.error:
    cf.log(ise.error, lvl=2)
    cf.log_exit(ewf_log)
  cf.log('HotSpot Portal ID: '+hotspot_portal_id, lvl=2)

  
  cf.log('Reading old access code', lvl=1)
  hotspot_portal_code = ise.get_hotspot_access_code(hotspot_portal_id)
  if ise.error:
    cf.log(ise.error, lvl=2)
    cf.log_exit(ewf_log)
  cf.log('Old UAP access code: '+hotspot_portal_code, lvl=2)
  
  
  cf.log('Generating new access code', lvl=1)
  new_access_code = cf.generate_password(int(settings['access_code_length']))
  cf.log('New UAP access code: '+new_access_code, lvl=2)
  
  
  cf.log('Sending update API request', log_path, 1)
  ise.set_hotspot_access_code(hotspot_portal_id, settings['hotspot_portal_name'], new_access_code)
  if ise.error:
    cf.log(ise.error, lvl=2)
    cf.log_exit(ewf_log)
  
  
  
  
  
  if email_body != False:
    smtp_body = email_body.replace('$new_access_code', new_access_code)
    
    template_var_exp_period = re.compile(r'\[(?:[\s]*)\$access_code_expiration_date(?:[\s]*)=(?:[\s]*)(?P<ac_exp_period>[0-9]+)(?:[\s]*)\]')
    var_exp_period = template_var_exp_period.search(smtp_body)
    if var_exp_period:
      access_code_expiration_period = int(var_exp_period.group('ac_exp_period'))
      
      now = datetime.now()
      now += timedelta(days=access_code_expiration_period)
      access_code_expiration_date = now.strftime("%d.%m.%Y")
      
      smtp_body = smtp_body.replace(var_exp_period.group(0), access_code_expiration_date)
  else:
    smtp_body = new_access_code
    
  cf.log('Sending new access code via email', lvl=1)
  for smtp_recepient in settings['mail_recepients']:
    smtp_result = cf.send_mail_smtp(fromAddr=settings['smtp_sender'],toAddr=smtp_recepient,smtpServer=settings['smtp_server'],smtpPort = settings['smtp_port'],subject=settings['mail_subject'],message=smtp_body,username=settings['smtp_user'],password=settings['dec_smtp_password'],tls=settings['smtp_tls'],fAuth=settings['smtp_auth'])
    if smtp_result == 0:
      # Email sent successfully
      cf.log(smtp_recepient+' - [OK]', lvl=2)
    else:
      # Error occurred while sending Email
      cf.log(smtp_recepient+' - [ERROR]', lvl=2)
      cf.log(smtp_result,lvl=3)
    # Delay for 1 second to avoid email server broadcast
    time.sleep(1)

  cf.log('Hotspot ['+settings['hotspot_portal_name']+'] code updated successfully')


if __name__ == '__main__':
  main()