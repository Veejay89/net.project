#!/usr/bin/python3
# Copyright 2022 Sergey Malkov

"""

"""

import sys
import base64
import re
import cf

from version import __version__


class Zabbix:
  """docstring"""
  
  def __init__(self, fqdn, port=443, token=None):
    """Constructor"""
    self.api_fqdn = fqdn
    self.api_fqdn = 'https://%s:%d/api_jsonrpc.php' % (fqdn, port)
    self.api_token = token
    self.api_headers = {'Content-Type': 'application/json-rpc', 'User-Agent': 'cfmodule/{}'.format(__version__)}
    self.error = False
  
  
  def set_token(self, token):
    self.api_token = str(token)


  def get_token(self, user='', password=''):
    """
    {'jsonrpc': '2.0', 'error': {'code': -32602, 'message': 'Invalid params.', 'data': 'Incorrect user name or password or account is temporarily blocked.'}, 'id': 1}
    {'jsonrpc': '2.0', 'result': 'xxxxxxxxx', 'id': 1}
    """
    self.error = False
    method_data = {
      "jsonrpc": "2.0",
      "method": "user.login",
      "params": {
        #"user": user, # Zabbix version < 6.5.10
        "username": user, # Zabbix version >= 6.5.10
        "password": password
      },
     "id": 1
    }
    
    response = cf.rget(self.api_fqdn, data=method_data, headers=self.api_headers)

    if response.error:
      self.error = response.error
      return False
   
    if 'result' in response.data:
      self.api_token = response.data['result']
    elif 'error' in response.data:
      self.error = response.data['error']['data']
    else:
      self.error = 'Unexpected error occured'
  
  
  def api_request(self, method, params=None):
    """Make request to Zabbix API.
    :type method: str
    :param method: ZabbixAPI method, like: `apiinfo.version`.
    :type params: str
    :param params: ZabbixAPI method arguments.
    """
    self.error = False
    
    method_data = {
      'jsonrpc': '2.0',
      'method': method,
      'params': params or {},
      'id': '1'
    }

    # apiinfo.version and user.login doesn't require auth token
    if self.api_token and (method not in ('apiinfo.version', 'user.login')):
      method_data['auth'] = self.api_token
    
    response = cf.rget(self.api_fqdn, data=method_data, headers=self.api_headers)
    
    if response.error:
      self.error = response.error
      return False
    
    if 'result' in response.data:
      result = response.data['result']
      return result
    elif 'error' in response.data:
      self.error = response.data['error']['data']
      return False
    else:
      self.error = 'Unexpected error occured'
      return False


  
  def get_groups_id(self, groups):
    """
    {'jsonrpc': '2.0', 'result': [{'groupid': '60', 'name': '_NET_SC_L3', 'internal': '0', 'flags': '0', 'uuid': '20b2f5e31f3a43a6a7aaab9d45ec75f6'}], 'id': 1}
    {'jsonrpc': '2.0', 'result': [], 'id': 1}
    """
    if isinstance(groups, str):
      groups = [groups]
    
    params = {
      "output": "extend",
      "filter": {
        "name": groups
      }
    }
    
    # self.error vipes by api_request call
    response = self.api_request('hostgroup.get', params)
    if self.error:
      return False
    
    result ={}
    for group in response:
      result[group['name']] = group['groupid']
    return result
  
  
  def get_net_in_groups(self, groups):
    """
    ['host_name'] = {
      group
      ip
    }
    """
    groups_ids = self.get_groups_id(groups)
    if self.error:
      return False 
    """
    {'hostid': '10893', 'name': 'RTR-DC-ISRv-02', 'groups': [{'groupid': '18', 'name': '_NET_SP_L3'}], 'inventory': {'type': '', 'type_full': '', 'name': '', 'alias': '', 'os': '', 'os_full': 'Cisco IOS Software [Amsterdam], Virtual XE Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 17.3.3, RELEASE SOFTWARE (fc7)\r\nTechnical Support: http://www.cisco.com/techsupport\r\nCopyright (c) 1986-2021 by Cisco Systems, Inc.\r\nCompiled Thu 04-Mar-21 12:4', 'os_short': '', 'serialno_a': '', 'serialno_b': '', 'tag': '', 'asset_tag': '', 'macaddress_a': '', 'macaddress_b': '', 'hardware': '', 'hardware_full': '', 'software': '', 'software_full': '', 'software_app_a': '', 'software_app_b': '', 'software_app_c': '', 'software_app_d': '', 'software_app_e': '', 'contact': '', 'location': '', 'location_lat': '', 'location_lon': '', 'notes': '', 'chassis': '', 'model': '', 'hw_arch': '', 'vendor': '', 'contract_number': '', 'installer_name': '', 'deployment_status': '', 'url_a': '', 'url_b': '', 'url_c': '', 'host_networks': '', 'host_netmask': '', 'host_router': '', 'oob_ip': '', 'oob_netmask': '', 'oob_router': '', 'date_hw_purchase': '', 'date_hw_install': '', 'date_hw_expiry': '', 'date_hw_decomm': '', 'site_address_a': '', 'site_address_b': '', 'site_address_c': '', 'site_city': '', 'site_state': '', 'site_country': '', 'site_zip': '', 'site_rack': '', 'site_notes': '', 'poc_1_name': '', 'poc_1_email': '', 'poc_1_phone_a': '', 'poc_1_phone_b': '', 'poc_1_cell': '', 'poc_1_screen': '', 'poc_1_notes': '', 'poc_2_name': '', 'poc_2_email': '', 'poc_2_phone_a': '', 'poc_2_phone_b': '', 'poc_2_cell': '', 'poc_2_screen': '', 'poc_2_notes': ''}, 'interfaces': [{'ip': '192.168.238.75'}]}
    """
    params = {
      "output": ["hostid","name"],
      "selectInterfaces": ["ip"],
      "groupids": list(groups_ids.values()),
      "selectGroups": ["groupid","name"],
      "selectInventory": ["os","os_full","os_short","software","software_full"],
      "preservekeys": True
    }
    _hosts = self.api_request('host.get', params)
    if self.error:
      return False
    
    templateSoftware = [
      re.compile(r'(?:.*Cisco )(?P<software>IOS|NX-OS)(?:.*Version )(?P<version>[0-9\.\(\)]{2,})(?:.*)'),
      re.compile(r'(?:.*Cisco )(?P<software>Adaptive Security Appliance|Firepower Threat Defense)(?:.*Version )(?P<version>[0-9\.\(\)]{2,})(?:.*)'),
      re.compile(r'(?P<software>VyOS|vyos) (?P<version>[0-9\.\(\)]{2,})(?:.*)'),
      # 02.08.23 Add Eltex Support from Zabbix Field
      re.compile(r'(?P<software>Eltex MES) (?P<version>[0-9\.\(\)]{2,})(?:.*)')
    ]
    
    hosts = dict()
    for host in _hosts.values():
      hosts[host['hostid']] = dict(name=host['name'],software='', version='')
      
      # Trying to get OS software of network device
      for inv in host['inventory']:
        for template in templateSoftware:
          m = re.match(template, host['inventory'][inv])
          if m:
            hosts[host['hostid']]['software'] = m.group('software')
            hosts[host['hostid']]['version'] = m.group('version')
            break
      
      # Search first group matching
      group = ''
      for _group in host['groups']:
        if _group['name'] in groups:
          group = _group['name']
          #if not group in hosts:
          #  hosts[group] = dict()
          break
      
      # Search first interface matching
      ip = host['interfaces'][0]['ip']
      
    
      hosts[host['hostid']]['group'] = group
      hosts[host['hostid']]['ip'] = ip

      """
      print ('-----')
      print ('  %s' % (host['name']))
      print ('  %s' % (group))
      print ('    %s' % (ip))
      print ('    %s' % (hosts[host['hostid']]['software']))
      print ('    %s' % (hosts[host['hostid']]['version']))
      """
    
    return hosts
  
  

if __name__ == '__main__':
#  main()
  cf.rdisablesslwarnings()
  zbx_user = input("Enter Zabbix user name [zbx_user]: ")
  zbx_password = input("Enter user password [zbx_password]: ")
  
  zbx = Zabbix('zabbix-prod-02.cplsb.ru')
  zbx.get_token(zbx_user, zbx_password)
  if zbx.error:
    print (zbx.error)
    sys.exit()
  
  temp = zbx.get_groups_id(['_NET_SC_L3','_NET_SP_L2'])
  if zbx.error:
    print (zbx.error)
    sys.exit()
  
  print (temp)
  print (list(temp.keys()))
  print (list(temp.values()))
  print ('-----')
  
  temp = zbx.get_net_in_groups(['_NET_PL_L3','_NET_SP_L3'])
  if zbx.error:
    print (zbx.error)
    sys.exit()
    
  print (temp)