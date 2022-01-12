#!/usr/bin/python3
# Copyright 2022 Sergey Malkov

"""

"""

import base64
import cf



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
  
    response = cf.rget(method_url, self.api_headers)
#    if not response['ok']:
    if response.error:
      self.error = response.error
      return False
  
    try:
#      resources = response['data']['SearchResult']['resources']
      resources = response.data['SearchResult']['resources']
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
  
    response = cf.rget(method_url, self.api_headers)
#    if not response['ok']:
    if response.error:
      self.error = response.error
      return False
    
    try:
      code = response.data['HotspotPortal']['settings']['aupSettings']['accessCode']
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
    
    response = cf.rput(method_url, method_data, self.api_headers)
    if response.error:
      self.error = response.error
      return False
    
    return True