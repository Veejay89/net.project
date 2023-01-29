#!/usr/bin/python3
# Copyright 2022 Sergey Malkov

"""
Module to work with encrypted passwords
"""


import sys
import os
import base64
import psutil
import re
from pathlib import Path
from dotenv import load_dotenv
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
# Import Custom Functions libraries
from cf import generate_password


def sec_salt():
  """
  Function returns salt value, based on CPU, RAM and disk size of current computing machine. Salt value will be different on one machine or another.
  """
  
  try:
    # Number of logical CPUs
    cpu_count = psutil.cpu_count()
    # Current CPU frequency expressed in Mhz
    # scpufreq(current=2095.078, min=0.0, max=0.0)
    scpufreq = psutil.cpu_freq()
    scpufreq_current = round(scpufreq.current)
    # Total physical memory (exclusive swap)
    # svmem(total=3919654912, available=3249811456, percent=17.1, used=267452416, free=118280192, active=324534272, inactive=3286798336, buffers=0, cached=3533922304, shared=164646912, slab=108077056)
    svmem = psutil.virtual_memory()
    svmem_total = svmem.total
    # Total Disk Usage
    # sdiskusage(total=9648996352, used=7591104512, free=2057891840, percent=78.7)
    sdiskusage = psutil.disk_usage('/')
    sdiskusage_total = sdiskusage.total
  except:
    return None
  salt = cpu_count*(scpufreq_current + svmem_total + sdiskusage_total)
  salt = str(salt) + str(scpufreq_current) + str(svmem_total) + str(sdiskusage_total)
  salt = bytes(salt, 'utf-8')
  #salt = salt.to_bytes(8, byteorder='big', signed=True)
  return salt


class Secret:
  """docstring"""
    
  def key_load(self):
    self.keys = dict()
    key_name_re = re.compile(r'^%s(?P<key_name>[A-Za-z0-9-_]+)$' % self.key_name_prepend)
    
    for k, v in os.environ.items():
      key_name = key_name_re.fullmatch(k)
      if key_name:
        self.keys[key_name.group('key_name')] = v
  
  
  def __init__(self, path=None, prepend=None):
    if path:
      self.dotenv_path = path + "/.env"
    else:
      self.dotenv_path = str(sys.path[0]) + "/.env"
    load_dotenv(self.dotenv_path)
    
    if prepend:
      self.key_name_prepend = prepend
    else:
      self.key_name_prepend = "cf_fernet_key_"
    
    self.key_load()
    
    self.key_salt = sec_salt()
    
    self.error = None
  
  
  def key_create(self, key_name=False):
    self.error = None
    
    key_name_re = re.compile(r'^[A-Za-z0-9-_]+$')
    if not key_name_re.fullmatch(key_name):
      self.error = "Key name value must contain only symbols and digits"
      return False
    
    if self.keys.get(key_name):
      self.error = "Fernet key with name '%s' already exists" % key_name
      return False
    
    key = generate_password(strLen=44,isLetters=True,isDigits=True,isPunctuation=True)
    if key_name:
      f = open(self.dotenv_path,'a')
      print(self.key_name_prepend+key_name+'='+key, file=f)
      f.close()
    return key
  
  
  def key_remove(self, key_name):
    self.error = None
    
    if self.keys.get(key_name) == None:
      self.error = "Key with name '%s' is not found in local environment storage" % key_name
      return False
    
    with open(self.dotenv_path) as f:
      lines = f.readlines()
    pattern = re.compile(re.escape(self.key_name_prepend+key_name))
    with open(self.dotenv_path, 'w') as f:
      for line in lines:
        result = pattern.search(line)
        if result is None:
          f.write(line)
    f.close()
    return True
  
  
  def key_wipe(self):
    self.error = None
    try:
      f = open(self.dotenv_path, 'w')
      f.close()
      return True
    except:
      self.error = "Undefined error"
      return False
  
  
  def key_init(self, key_name):
    # Get passphrase from local .env file
    passphrase = os.environ.get(self.key_name_prepend+key_name)
    
    if passphrase == None or self.key_salt == None:
      self.fkey = False
  
    try:
      kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=self.key_salt,
        iterations=390000,
      )
      key = base64.urlsafe_b64encode(kdf.derive(bytes(passphrase, encoding = "utf-8")))
      f = Fernet(key)
      self.fkey = f
    except:
      self.fkey = False
   
  
  def encrypt(self, dec_password):
    self.error = None
    
    if self.fkey == False:
      self.error = "Operation aborted. Fernet key is not initialized"
      return False
    # Trying to encrypt password with key
    try:
      enc_password = self.fkey.encrypt(dec_password.encode())
    except:
      self.error = "Undefined error"
      return False
    return enc_password.decode('utf-8')
  
  
  def decrypt(self, enc_password):
    self.error = None
    
    if self.fkey == False:
      self.error = "Operation aborted. Fernet key is not initialized"
      return False
    # Trying to decrypt password with key
    try:
      dec_password = self.fkey.decrypt(enc_password.encode())
    except:
      self.error = "Cannot decrypt password. Make sure that token was encrypted exactly with used Fernet secret key, exactly on this machine"
      return False
    return dec_password.decode('utf-8')