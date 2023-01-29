#!/usr/bin/python3
# Copyright 2022 Sergey Malkov

"""
Use this section to describe script functionalty

Examples:
  sec.key_init("test_key1")
  dec_password = sec.decrypt("FERNET_TOKEN")
"""

import os
import sys
import argparse
import re
import getpass
from dotenv import load_dotenv
# Import Custom Functions libraries
# sys.path[0] contains absolute path to directory contains running script 
this_path = sys.path[0]
sys.path.append(this_path+'/modules')
import cfsec


"""
Define mandatory and optional arguments using argparse module functions
"""
parser = argparse.ArgumentParser(description='Helper module for encrypted Fernet Key workflow')
parser.add_argument('--out', '-o', help="Display all decryption key names stored in .env file in this directory", action='store_true')
parser.add_argument('--new', '-n', help="Creates new Fernet key and writes it out in .env file. Use with --key.", action='store_true')
parser.add_argument('--remove', '-r', help="Removes existed Fernet key from .env file. Use with --key.", action='store_true')
parser.add_argument('--encrypt', '-e', help="Encryptes password and show it up. Use with --key.", action='store_true')
parser.add_argument('--decrypt', '-d', help="Decryptes password and show it up. Use with --key.", action='store_true')
parser.add_argument('--key', '-k', help="Secondary attribute for every Fernet operation.", type=str)
parser.add_argument('--wipe', '-w', help="Wipes out .env file. Irreversible operation.", action='store_true')
args = parser.parse_args()


def main_init():
  """docstring"""
  global fpwd
  fpwd = cfsec.Secret()
  

def main_preprocessing():
  """docstring"""
  pass


def main_process():
  """docstring"""
  
  if args.out:
    print('Custom environment file path: %s' % fpwd.dotenv_path)
    for k, v in fpwd.keys.items():
      print("  %s: %s" % (k, v))
    print('%s keys found' % len(fpwd.keys))

  if args.wipe:
    confirm = input(' Please, confirm environment file wipe (type "yes"): ')
    if confirm.lower() == 'yes':
      if fpwd.key_wipe():
        print("Local environment storage successfully wiped out")
      else:
        print(fpwd.error)
    else:
      print('Operation was not confirmed.')

  if args.new and args.key:
    if fpwd.key_create(key_name=args.key):
      print('New key "%s" successfully created in local environment storage' % args.key)
    else:
      print(fpwd.error)
  
  if args.remove and args.key:
    if fpwd.key_remove(key_name=args.key):
      print('Key "%s" successfully removed from local environment storage' % args.key)
    else:
      print(fpwd.error)
  
  if args.encrypt and args.key:
    password = ''
    while len(password)==0:
      password = getpass.getpass('Specify password as a plain-text: ')
      if len(password)==0:
        print('Invalid input. Password cannot be empty')
    
    fpwd.key_init(args.key)
    enc_password = fpwd.encrypt(password)
    
    #enc_password = cfsec.sec_encrypt_password(env_key_prepend+args.key, password)
    
    if enc_password:
      print('Password successfully encrypted. Fernet token:')
      print(enc_password)
    else:
      print(fpwd.error)
      #print('Cannot encrypt password with key %s. Make sure that used key is valid Fernet secret key.' % args.key)

  if args.decrypt and args.key:
    password = ''
    while len(password)==0:
      password = input('Specify token encrypted with Fernet algorythm: ')
      if len(password)==0:
        print('Invalid input. Token cannot be empty')
    
    fpwd.key_init(args.key)
    dec_password = fpwd.decrypt(password)
    
    #dec_password = cfsec.sec_decrypt_password(env_key_prepend+args.key, password)
    
    if dec_password:
      print('Token successfully decrypted.')
      print(dec_password)
    else:
       print(fpwd.error)


def main():
  main_init()
  main_preprocessing()
  main_process()
  

if __name__ == '__main__':
  main()