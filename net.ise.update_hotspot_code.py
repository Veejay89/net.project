#!/usr/bin/python3
# Copyright 2022 Sergey Malkov

"""
Module to update Cisco ISE HotSpot UAP Access Code
After updating, module might send new code by email if smtp server defined in params
"""

import base64
import requests
import json
import time
from datetime import datetime, timedelta
import re
import sys
# Import Custom Functions libraries
# sys.path[0] contains absolute path to directory contains running script 
this_path = sys.path[0]
sys.path.append(this_path+'/modules')
import cf
from cfsec import sec_decrypt_password



def setIseApiHeaders(usr,pwd):
  authString = usr + ':' + pwd
  b64AuthString = base64.b64encode(authString.encode('utf-8'))
  authHeader = 'Basic ' + b64AuthString.decode('utf-8')
  header = {'Authorization' : authHeader , 'Accept': 'application/json' , 'Content-Type': 'application/json'}
  return (header)


def rest_get(url, headers, verify=False):
  result = {
    'ok': False,
    'error': '',
    'data': ''
  }
  try:
    response = requests.get(url, headers=headers, verify=verify)
  except Exception as e:
    result['error'] = e
    return result
  
  if response.status_code != 200:
    result['error'] = 'HTTP response code: {}'.format(response.status_code)
    return result
    
  result['ok'] = True
  result['data'] = response.json()
  return result


def rest_put(url, data, headers, verify=False):
  result = {
    'ok': False,
    'error': '',
    'data': ''
  }
  try:
    response = requests.put(url, data=json.dumps(data), headers=headers, verify=verify)
  except Exception as e:
    result['error'] = e
    return result
  
  if response.status_code != 200:
    result['error'] = 'HTTP response code: {}'.format(response.status_code)
    return result
    
  result['ok'] = True
  result['data'] = response.json()
  return result




class IseERSApi:
  """docstring"""

  def __init__(self, fqdn, user, password):
    """Constructor"""
    self.api_fqdn = fqdn
    self.api_port = '9060'
    # Build HTTP headers for ERS API requests
    authString = '%s:%s' % (user,password)
    b64AuthString = base64.b64encode(authString.encode('utf-8'))
    authHeader = 'Basic ' + b64AuthString.decode('utf-8')
    self.api_headers = {'Authorization' : authHeader , 'Accept': 'application/json' , 'Content-Type': 'application/json'}
    self.error = False
  
  def port(self, port):
    self.api_port = str(port)
  
  def get_portal_id(self, name):
    self.error = False
    method_url = 'https://{}:{}/ers/config/portal'.format(self.api_fqdn, self.api_port)
  
    response = rest_get(method_url, self.api_headers)
    if not response['ok']:
      self.error = response['error']
      return False
  
    try:
      resources = response['data']['SearchResult']['resources']
      for res in resources:
        if res['name'] == name:
          pid = res['id']
    except:
      self.error = 'ISE ERS API error. Unable to get hotspot portal id from response'
      return False
  
    if pid != '':
      return pid
    else:
      self.error = 'Unable to find guest portal with defined HotSpot name'
      return False
  
  def get_hotspot_access_code(self, pid):
    self.error = False
    method_url = 'https://%s:%s/ers/config/hotspotportal/%s' % (self.api_fqdn, self.api_port, pid)
  
    response = rest_get(method_url, self.api_headers)
    if not response['ok']:
      self.error = response['error']
      return False
    
    try:
      code = response['data']['HotspotPortal']['settings']['aupSettings']['accessCode']
    except:
      self.error = 'ISE ERS API error. Unable to get hotspot portal access code from response'
      return False
    
    return code
  
  def set_hotspot_access_code(self, pid, name, code):
    self.error = False
    method_url = 'https://%s:%s/ers/config/hotspotportal/%s' % (self.api_fqdn, self.api_port, pid)
    
    method_data = {
      "HotspotPortal":
      { "id": pid,
        "name": name,
        "settings":
        { "aupSettings":
          { "accessCode": code,
            "requireAccessCode": "true"
          }
        }
      }
    }
    
    response = rest_put(method_url, method_data, self.api_headers)
    if not response['ok']:
      self.error = response['error']
      return False
    
    return True




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
  
  
 
  #ise_api_url = 'https://'+settings['ise_api_pan']+':'+settings['ise_api_port']+'/ers/config/hotspotportal/'+settings['hotspot_portal_id']
#  headers = setIseApiHeaders(settings['ise_api_username'], settings['ise_api_password'])
  
  
  cf.log('Defined settings:', lvl=1)
  cf.log('ISE HotSpot Portal Name: '+settings['hotspot_portal_name'], lvl=2)
  cf.log('ISE HotSpot Portal ID: '+settings['hotspot_portal_id'], lvl=2)
  #cf.log('ISE PAN API url: '+ise_api_url, log_path, 2)
  
  # Try to get defined Portal ID configuration URL (with Portal ID)
#  cf.log('Reading HotSpot portal ID', lvl=1)
#  errorCode = 0
#  ise_api_url = 'https://{}:{}/ers/config/portal'.format(settings['ise_api_pan'],settings['ise_api_port'])
  
#  response = rest_get(ise_api_url, headers=headers)
# if not response['ok']:
#   cf.log(response['error'], log_path, 2)
#   cf.log_exit(ewf_log, log_path)
  
#  try:
#    response = requests.get(ise_api_url, headers=headers, verify=False)
#  except Exception as e:
#    errorCode = e
#  if errorCode != 0:
#    cf.log(str(errorCode), log_path, 2)
#    cf.log_exit(ewf_log, log_path)
#  elif response.status_code != 200:
#    cf.log('Unable to get hotspot portal id. ERS API HTTP response-code: '+str(response.status_code), log_path, 2)
#    cf.log_exit(ewf_log, log_path)
  
#  jsonData = response.json()
#  hotspot_portal_id = ''
#  try:
#    #ise_resources = jsonData['SearchResult']['resources']
#    ise_resources = response['data']['SearchResult']['resources']
#    for res in ise_resources:
#      if res['name'] == settings['hotspot_portal_name']:
#        hotspot_portal_id = res['id']
#  except:
#    cf.log('Unable to get hotspot portal id. Update is not possible', log_path, 2)
#    cf.log_exit(ewf_log, log_path)
  
#  if hotspot_portal_id != '':
#    cf.log('HotSpot Portal ID: '+hotspot_portal_id, log_path, 2)
#  else:
#    cf.log('Unable to find hotspot portal id determined in settings. Update is not possible', log_path, 2)
#    cf.log_exit(ewf_log, log_path)
  
  
  ise = IseERSApi(settings['ise_api_pan'],settings['ise_api_username'], settings['ise_api_password'])
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
  
  
  
  
  
  
  #ise_resp = get_guestportal(settings['ise_api_pan'], settings['hotspot_portal_name'], settings['ise_api_username'], settings['ise_api_password'], settings['ise_api_port'])
  #if not ise_resp['ok']:
  #  cf.log(ise_resp['error'], lvl=2)
  #  cf.log_exit(ewf_log)
  
  
  #hotspot_portal_id = ise_resp['id']
  
#  cf.log('Reading old access code', lvl=1)
  
#  ise_resp = get_hotspot_access_code(settings['ise_api_pan'], hotspot_portal_id, settings['ise_api_username'], settings['ise_api_password'], settings['ise_api_port'])
#  if not ise_resp['ok']:
#    cf.log(ise_resp['error'], lvl=2)
#    cf.log_exit(ewf_log)
#  
#  cf.log('Old UAP access code: '+ise_resp['code'], lvl=2)
  
  #ise_api_url = 'https://{}:{}/ers/config/hotspotportal/{}'.format(settings['ise_api_pan'],settings['ise_api_port'],hotspot_portal_id)
#  ise_api_url = 'https://{}:{}/ers/config/hotspotportal/{}'.format(settings['ise_api_pan'],settings['ise_api_port'],ise_resp['id'])
  
  # Try to get current access code from Portal
#  cf.log('Reading old access code', lvl=1)
#  errorCode = 0
#  try:
#    response = requests.get(ise_api_url, headers=headers, verify=False)
#  except Exception as e:
#    errorCode = e
  # HTTP-request result handler
#  if errorCode != 0:
#    cf.log(str(errorCode), lvl=2)
#    cf.log_exit(ewf_log)
#  elif response.status_code != 200:
#    cf.log('Unable to get current access code information; HTTP response-code: '+str(response.status_code), lvl=2)
#    cf.log_exit(ewf_log)
  
  
# jsonData = response.json()
#  try:
#    old_access_code = jsonData['HotspotPortal']['settings']['aupSettings']['accessCode']
#  except:
#    cf.log('UAP access code is not defined for current portal. Update is not possible', lvl=2)
#    cf.log_exit(ewf_log)
#  cf.log('Old UAP access code: '+old_access_code, lvl=2)

 

  
  """
  # Try to set new access code to Portal
  cf.log('Sending update API request', log_path, 1)
  data = {
    "HotspotPortal":
    { "id": hotspot_portal_id,
      "name": settings['hotspot_portal_name'],
      "settings":
      { "aupSettings":
        { "accessCode": new_access_code,
          "requireAccessCode": "true"
        }
      }
    }
  }
  # Change UAP access code via API HTTP-request
  errorCode = 0
  try:
    response = requests.put(ise_api_url, data=json.dumps(data), headers=headers, verify=False)
  except Exception as e:
    errorCode = e
  # HTTP-request result handler
  if errorCode != 0:
    cf.log(str(errorCode), log_path, 2)
    cf.log_exit(ewf_log, log_path)
  elif response.status_code != 200:
    cf.log('Unable to set new access code to current portal; HTTP response-code: '+str(response.status_code), log_path, 2)
    cf.log_exit(ewf_log, log_path)
  """
  
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