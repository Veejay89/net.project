#!/usr/bin/python3 -tt
# Copyright 2022 Sergey Malkov

"""
Custom functions module for network authomatization
"""

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
# datetime object containing current date and time
from datetime import datetime



def script_name():
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



def log(msg,file='cf_log.txt',lvl=0):
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


def log_exit(msg='',file='cf_log.txt'):
  if msg != '':
    log(msg,file)
  sys.exit()



def get_settings(file='_sample_get_settings.txt'):
  
  lines = []
  try:
    #f = open(file,'r')
    with open(file,'r') as f:
      lines = f.readlines()
  except IOError as e:
    return False

  templateAttribute = re.compile(r'^(?:[\s\t]*)(?P<attr_name>[A-Za-z-_]+)(?:[\s\t]*)=(?:[\s\t]*)(?P<attr_value>[A-Za-z0-9-_\.:/\\@\s\(\)=]+)(?:[\s\t]*)$')
  settings = {}
  
  #lines = f.readlines()
  for line in lines:
    line = line.strip()
    if line == '':
      # Empty line - ignore
      continue
    if line[0] == '#':
      # Commented string or value - ignore
      continue

    attr = templateAttribute.fullmatch(line)
    if attr == None:
      # Invalid attribute format
      continue
    attr_name = attr.group('attr_name')
    attr_value = attr.group('attr_value')
    
    #split_index = line.find('=')
    #attr_name = line[:split_index].strip()
    #attr_value = line[(split_index+1):].strip()
    
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



def is_valid_email(email):
  """ Returns True if addr is valid Email address or False - if not
  
  """
  
  # Compile a regular expression pattern into a regular expression object
  templateEmail = re.compile(r'([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+')
  # Compare whole email string with pattern
  if re.fullmatch(templateEmail, email):
    return True
  else:
    return False



def send_mail_smtp(fromAddr='',toAddr='',smtpServer='',smtpPort=587,subject='',message='',username='',password='',tls=True):
  """ Send single message via defined SMTP server.
  Use FOR and IN structure to send more than one message 
  """
  
  errorCode = 0
  resultErrorEN = {
    10: 'fromAddr value is not defined or have incorrect syntax',
    11: 'toAddr value is not defined or have incorrect syntax',
    12: 'smtpServer value is not defined or incorrect',
    14: 'subject text is not defined',
  }
  
  # Autocomplete known attributes:
  # gmail - used as short name for smtpServer
  if smtpServer.lower().find('gmail') >= 0:
    smtpServer = 'smtp.gmail.com'
    smtpPort = 587
    username = fromAddr # Just a pointer, keep in mind that strings are immunable
    tls = True
  
  # Base check-list of user-defined attributes
  if fromAddr == '' or is_valid_email(fromAddr) == False:
    errorCode = 10
  if toAddr == '' or is_valid_email(toAddr) == False:
    errorCode = 11
  if smtpServer == '':
    errorCode = 12
  if subject == '':
    errorCode = 14

  # Error interruption if base check-list is failed
  if errorCode != 0:
    return ('custom_functions.send_mail_smtp: ' + resultErrorEN[errorCode])
  
  # Send a message via algorythm of defined smtp server
  try:
    # Form Content-Type header if <html> tags exists in message
    content = ''
    if message.find('<html>') >= 0:
      content = 'Content-Type: text/html\n'
    # Form Email message in smtplib format w/ Content-Type if nesessary
    # message = 'Subject: {}\n\n{}'.format(subject, message)
    message = 'Subject: {}\nFrom: {}\nTo: {}\n{}\n{}'.format(subject, fromAddr, toAddr, content, message)
    
    # TLS Algorythm (f.e. used by GMail)
    if tls == True:
      conn = smtplib.SMTP(smtpServer,smtpPort)
      conn.ehlo()
      conn.starttls()
      conn.ehlo()
      conn.login(username, password)
      conn.sendmail(fromAddr, toAddr, message)
      conn.quit()
  except Exception as e:
    errorCode = e

  # Sending mail result handler
  if errorCode != 0:
    return ('custom_functions.send_mail_smtp.smtplib: ' + str(errorCode))
  else:
    return errorCode # = 0 by default


"""
Presented functions usage examples and test output
"""
if __name__ == '__main__':
  print ('Custom functions module test output section:')
  print ('--------------------------------------------')
  
  #print (generate_password())





  # send_mail_smtp() usage examples
  """
  # Define base send_mail_smtp attributes
  smtp_gmail = {
    'fromAddr': 'atlantisclub18@gmail.com',
    'toAddr': 'atlantisclub18@gmail.com',
    'smtpServer': 'smtp.gmail.com',
    #'smtpPort': 587,
    'subject': 'Test message via Python3',
    'message': '',
    #'username': '',
    'password': 'ugiqpokzvbswvtgf',
    #'tls': True
  }
  
  # Define plain text message body
  smtp_gmail['message'] = 'Simple text message'
  
  # Define HTML message body 
  #smtp_gmail['message'] = '<html><div style="color:red"<b>HTML message</b></div></html>'
  
  # Email send via GMail example  
  smtp_result = send_mail_smtp(fromAddr=smtp_gmail['fromAddr'],toAddr=smtp_gmail['toAddr'],smtpServer=smtp_gmail['smtpServer'],subject=smtp_gmail['subject'],message=smtp_gmail['message'],password=smtp_gmail['password'])

  # send_mail_smtp result handler example
  if smtp_result == 0:
    # Email sent successfully
    print ('send_mail_smtp: email send successfully')
  else:
    # Error occurred while sending Email
    print ('send_mail_smtp:' + smtp_result)
  """





  #get_settings(file) usage examples
  
  settings_result = get_settings()
  
  print (settings_result)
  
  # get_settings result handler example
  #if settings_result == 0:
    # Settings read successfully
  #  print ('get_settings: file read successfully')
  #else:
    # Error occurred while reading setting file
  #  print (str(settings_result))