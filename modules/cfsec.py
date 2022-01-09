#!/usr/bin/python3
# Copyright 2022 Sergey Malkov

"""
Module to work with encrypted passwords
"""


import sys
from pathlib import Path
import os
from dotenv import load_dotenv
from cryptography.fernet import Fernet


def sec_encrypt_password(key_name,dec_password):
  # Get key from local .env file
  load_dotenv(dotenv_path)
  key = os.environ.get(key_name)
  if key == None:
    return False
  # Trying to encrypt password with key
  try:
    f = Fernet(key)
    enc_password = f.encrypt(dec_password.encode())
  except:
    return False
  return enc_password.decode('utf-8')


def sec_decrypt_password(key_name,enc_password):
  # Get key from local .env file
  load_dotenv(dotenv_path)
  key = os.environ.get(key_name)
  if key == None:
    return False
  # Trying to decrypt password with key
  try:
    f = Fernet(key)
    dec_password = f.decrypt(enc_password.encode())
  except:
    return False
  return dec_password.decode('utf-8')


def main():
  print("""
  This module provides options to generate Fernet keys, store it into .env file and use this key to encrypt plain text passwords.
  Open local .env file to get existed key names and use it in your script.
  1. Generate new key for python module and put it as .env variable
  2. Encrypt password for python module to use in script or other insecure areas 
  3. [decrypt_password] Test: decrypt password using defined key_name
  4. Quit module
  """)
  action = int(input("Select action: "))
  
  if action == 1:
    key_name = input("Enter user-friendly key name (use to call Fernet key value from script): ")
    key = Fernet.generate_key()

    f = open(dotenv_path,'a')
    print(key_name+'='+key.decode('utf-8'), file=f)
    # Decode to utf-8 removes b'' chars from written string
    f.close()
    
  if action == 2:
    key_name = input("Enter key name for encryption: ")
    dec_password = input("Enter password as plain text: ")

    enc_password = sec_encrypt_password(key_name,dec_password)
    
    if dec_password != False:
      print ('Encrypted password with key ['+key_name+']: '+str(enc_password))
    else:
      print ('An error occurred while encrypting password.')

    
  # Function decrypt_password usage example  
  if action == 3:
    key_name = input("Enter key name for decryption [key_name]: ")
    enc_password = input("Enter encrypted password [enc_password]: ")
  
    dec_password = sec_decrypt_password(key_name,enc_password)
  
    if dec_password != False:
      print ('Decrypted password (as plain-text) with key ['+key_name+']: '+str(dec_password))
    else:
      print ('An error occurred while decrypting password.')

    if action == 4:
      sys.exit()

this_path = sys.path[0]

if __name__ == '__main__':
  dotenv_path = str(Path(sys.path[0]).parent) + "/.env"
  main()
else:
  dotenv_path = str(sys.path[0]) + "/.env"