try:
  import requests
  import configparser
  from requests.auth import HTTPDigestAuth
  import json
  import time
  import subprocess
  import copy
  import logging
  import pymongo
  import urllib3
  import os
  import sys
  import datetime
  import re
  from pymongo.errors import OperationFailure
  if sys.version_info[0] >= 3:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    urllib3.disable_warnings(urllib3.exceptions.SubjectAltNameWarning)
except ImportError as e:
  print(e)
  exit(1)

LOG_FILE = 'deployment_configs.log'
STANDARD_PROJECT = {"kerberos" : {"serviceName" : "mongodb"},"auth" : {"autoAuthMechanisms" : ["MONGODB-CR"],"autoAuthMechanism" : "MONGODB-CR"},"ssl" : {"clientCertificateMode" : "OPTIONAL","CAFilePath" : "/data/pki/ca.cert","autoPEMKeyFilePath" : "/etc/mongodb-mms/aa.pem"}}
STANDARD_PROCESS = { "authSchemaVersion" : 5, "kerberos" : { "keytab" : "/data/pki/server_keytab" }, "manualMode" : False, "disabled" : False, "logRotate" : { "timeThresholdHrs" : 24, "sizeThresholdMB" : 1000 }, "version" : "3.6.13-ent", "args2_6" : { "net" : { "ssl" : { "mode" : "requireSSL" }, "port" : 27017, "bindIpAll" : True }, "storage" : { "wiredTiger" : { "engineConfig" : { "directoryForIndexes" : True }}, "dbPath" : "/data/db", "directoryPerDB" : True }, "security" : { "encryptionKeyFile" : "/data/pki/mongodb_keyfile", "enableEncryption" : True }, "systemLog" : { "path" : "/data/logs/mongodb.log", "destination" : "file" } }, "featureCompatibilityVersion" : "3.6" }
waiver_processes = {"processes": {"version": "WAIVER"}}

# Get config setting from `event_watcher.config` file
if os.path.isfile('deployment_configs.conf') == False:
  logging.basicConfig(filename=LOG_FILE,level=logging.ERROR)
  logging.error('The `deployment_configs.conf` file must exist in the same directory as the Python script')
  print('\033[93m' + 'The `deployment_configs.conf` file must exist in the same directory as the Python script, exiting' + '\033[m')
  sys.exit(0)
config = configparser.ConfigParser()
config.read('deployment_configs.conf')
try:
  DEBUG = config.getboolean('general','debug', fallback=False)
  BASEURL = config.get('ops_manager','baseurl')
  USERNAME = config.get('ops_manager', 'username')
  TOKEN = config.get('ops_manager','token')
  OPS_MANAGER_SSL_PEM = config.get('ops_manager','ssl_pem_path',fallback=None)
  OPS_MANAGER_SSL_CA = config.get('ops_manager', 'ssl_ca_cert_path',fallback=None)
  AUDIT_DB_CONNECTION_STRING = config.get('audit_db','connection_string')
  AUDIT_DB_SSL = config.getboolean('audit_db','ssl_enabled',fallback=False)
  if AUDIT_DB_SSL is True:
    AUDIT_DB_SSL_PEM = config.get('audit_db','ssl_pem_path')
    AUDIT_DB_SSL_CA = config.get('audit_db', 'ssl_ca_cert_path')
  OPS_MANAGER_TIMEOUT = config.getint('ops_manager','timeout', fallback=1000)
  AUDIT_DB_TIMEOUT = config.getint('audit_db','timeout', fallback=1000)
  EXCLUDED_ROOT_KEYS = config.get('general','excluded_root_keys',fallback=[]).split(',')
except configparser.NoOptionError as e:
  logging.basicConfig(filename=LOG_FILE,level=logging.ERROR)
  logging.error('The config file must include the `BASEURL` option in the `audit_db` section')
  print('\033[91m' + "ERROR! The config file must include the `BASEURL` option in both the `ops_manager` and `audit_db` sections "
    ", such as:\n"
    + '\033[92m'
    "[ops_manager]\n"
    "baseurl=https://host:port/api/public/v1.0\n"
    "username=loud.sam\n"
    "token=8ce50f02-4292-460e-82a5-000a0742182a\n\n"
    "[audit_db]"
    "connection_string=mongodb://username:password@host:port/?replicaSet=replicasetname\n"
    "ssl_enabled=True\n"
    "ssl_pem_path=/data/pki/mongod3.mongodb.local.pem\n"
    "ssl_ca_cert_path=/data/pki/ca.cert\n"
    + '\033[m')
  sys.exit(1)
except configparser.NoSectionError as e:
  logging.basicConfig(filename=LOG_FILE,level=logging.ERROR)
  logging.error('The config file must include sections `audit_db` and `general`')
  print('\033[91m' + "ERROR! The config file must include sections `ops_manager`, `audit_db` and `general`, such as:\n"
    + '\033[92m'
    "[ops_manager]\n"
    "baseurl=https://host:port/api/public/v1.0\n"
    "timeout=1000\n"
    "username=loud.sam\n"
    "token=8ce50f02-4292-460e-82a5-000a0742182a\n\n"
    "[audit_db]\n"
    "connection_string=mongodb://username:password@host:port/?replicaSet=replicasetname\n"
    "ssl_enabled=True\n"
    "ssl_pem_path=/data/pki/mongod3.mongodb.local.pem\n"
    "ssl_ca_cert_path=/data/pki/ca.cert\n"
    "timeout=1000\n\n"
    "[general]\n"
    "debug=False"
    + '\033[m'
    )
  sys.exit(1)

if DEBUG == True:
  logging.basicConfig(filename=LOG_FILE,level=logging.DEBUG)
  logging.info("STARTING PROCESSING: %s" % datetime.datetime.now())
  logging.debug("AUDIT CONNECTION STRING: %s" % re.sub('//.+@', '//<REDACTED>@', AUDIT_DB_CONNECTION_STRING))
  logging.debug("OPS MANAGER CONNECTION STRING: %s" % re.sub('//.+@', '//<REDACTED>@',BASEURL))
  logging.debug("EXCLUDED KEYS: %s" % EXCLUDED_ROOT_KEYS)
  print("AUDIT CONNECTION STRING: %s" % re.sub('//.+@', '//<REDACTED>@', AUDIT_DB_CONNECTION_STRING))
  print("OPS MANAGER CONNECTION STRING: %s" % re.sub('//.+@', '//<REDACTED>@',BASEURL))
else:
  logging.basicConfig(filename=LOG_FILE,level=logging.INFO)
  logging.info("STARTING PROCESSING: %s" % datetime.datetime.now())

# conneciton to the audit database
try:
  if AUDIT_DB_SSL is True:
    if DEBUG is True:
      logging.debug("Using SSL/TLS to Audit DB")
      print("Using SSL/TLS to Audit DB")
    audit_client = pymongo.MongoClient(AUDIT_DB_CONNECTION_STRING, serverSelectionTimeoutMS=AUDIT_DB_TIMEOUT, ssl=True, ssl_certfile=AUDIT_DB_SSL_PEM, ssl_ca_certs=AUDIT_DB_SSL_CA)
  else:
    if DEBUG is True:
      logging.debug("Not ussing SSL/TLS to Audit DB")
      print("Not using SSL/TLS to Audit DB")
    audit_client = pymongo.MongoClient(AUDIT_DB_CONNECTION_STRING, serverSelectionTimeoutMS=AUDIT_DB_TIMEOUT)
  result = audit_client.admin.command('ismaster')
except (pymongo.errors.ServerSelectionTimeoutError, pymongo.errors.ConnectionFailure) as e:
  logging.error("Cannot connect to Audit DB, please check settings in config file: %s" %e)
  print("Cannot connect to Audit DB, please check settings in config file: %s" %e)
  sys.exit(1)
audit_db = audit_client['logging']
audit_collection = audit_db['configs']

def get(endpoint):
  resp = requests.get(BASEURL + '/api/public/v1.0' + endpoint, auth=HTTPDigestAuth(USERNAME, TOKEN), verify=OPS_MANAGER_SSL_CA, cert=OPS_MANAGER_SSL_PEM, timeout=OPS_MANAGER_TIMEOUT)
  if resp.status_code == 200:
    get_data = json.loads(resp.text)
    return get_data
  else:
    print("GET response was %s, not `200`" % resp.status_code)
    print(resp.text)
    raise requests.exceptions.RequestException

def check_dict(root, s_dict, comp_dict, waivers={}):
  failure_data = {"issue": [], "waiver": []}
  if type(s_dict) is dict:
    for ks, vs in s_dict.items():
      if root == '':
        k = ks
      else:
        k = root + '.' + ks
      vd = comp_dict.get(ks, None)
      if not vd:
        if DEBUG:
          print("\033[91mSadness: `%s: %s` is missing for the deployment\033[m" % (k,vs))
        failure_data['issue'].append("`%s: %s` is missing for the deployment" % (k,vs))
        continue
      if type(vs) is dict:
        if type(vd) is dict:
          temp_dict = check_dict(k, vs, vd, waivers)
          failure_data['waiver'].extend(temp_dict['waiver'])
          failure_data['issue'].extend(temp_dict['issue'])
        else:
          if DEBUG:
            print("\033[91mSadness: `%s: %s`, should be `%s`\033[m" % (k , vd, vs))
          failure_data['issue'].append("`%s: %s`, should be `%s`" % (k , vd, vs))
      elif type(vs) is list:
        if type(vd) is list:
          temp_dict = check_list(k, vs, vd, waivers)
          failure_data['waiver'].extend(temp_dict['waiver'])
          failure_data['issue'].extend(temp_dict['issue'])
        else:
          if DEBUG:
            print("\033[91mSadness: `%s: %s, should be %s`\033[m" % (k , vd, vs))
          failure_data['issue'].append("`%s: %s`, should be `%s`" % (k , vd, vs))
      elif vs != vd:
        try:
          x = reduce(dict.get, k.split("."), waivers)
          if x:
            if DEBUG:
              print("\033[93mWaiver: `%s: %s, should be %s`\033[m" % (k, vd, vs))
            failure_data['waiver'].append("`%s: %s`, standard is `%s`" % (k , vd, vs))
        except TypeError:
          if DEBUG:
            print("\033[91mSadness: `%s: %s, should be %s`\033[m" % (k , vd, vs))
          failure_data['issue'].append("`%s: %s`, should be `%s`" % (k , vd, vs))
  return failure_data


def check_list(k, s_array, d_array, waivers):
  failure_data = {"issue": [], "waiver": []}
  if type(s_array) is list and type(d_array) is list:
    s_array.sort()
    d_array.sort()
    for index, vs in enumerate(s_array):
      vd = d_array[index] if index < len(d_array) else None
      if not vd:
        if DEBUG:
          print("\033[91mSadness: `%s:%s` is missing for the deployment\033[m" % (k, vs))
        failure_data['issue'].append("`%s: %s` is missing for the deployment" % (k,vs))
        break
      if type(vs) is dict:
          if type(vd) is dict:
            temp_dict = check_dict(k, vs, vd, waivers)
            failure_data['waiver'].extend(temp_dict['waiver'])
            failure_data['issue'].extend(temp_dict['issue'])
          else:
            if DEBUG:
              print("\033[91mSadness: `%s: %s, should be %s`\033[m" % (k , vd, vs))
            failure_data['issue'].append("`%s: %s`, should be `%s`" % (k , vd, vs))
      if type(vs) is list:
          if type(vd) is list:
            temp_dict = check_list(k, vs, vd, waivers)
            failure_data['waiver'].extend(temp_dict['waiver'])
            failure_data['issue'].extend(temp_dict['issue'])
          else:
            if DEBUG:
              print("\033[91mSadness: `%s: %s, should be %s`\033[m" % (k , vd, vs))
            failure_data['issue'].append("`%s: %s`, should be `%s`" % (k , vd, vs))
      elif vs != vd:
        if DEBUG:
          print("\033[91mSadness: `%s: %s, should be %s`\033[m" % (k, d_array, s_array))
        failure_data['issue'].append("`%s: %s`, should be `%s`" % (k , vd, vs))
        break
  return failure_data

def main():
  DEPLOYMENTS = get('/groups')
  for deployment in DEPLOYMENTS['results']:
    desired_state = get('/groups/' + deployment['id'] + '/automationConfig')
    desired_state['compliance'] = []
    # Deep copy because Python does copy by reference
    deployment_compliance = check_dict('', STANDARD_PROJECT, desired_state, waiver_processes)
    deployment_compliance['host'] = 'Project Level'
    desired_state['compliance'].append(copy.deepcopy(deployment_compliance))
    # Determine if project has any members
    if desired_state['processes']:
      for instance in desired_state['processes']:
        compliance = check_dict("processes", STANDARD_PROCESS, instance, waiver_processes)
        if compliance:
          compliance['host'] = instance['hostname']
          if DEBUG:
            print("COMPLIANCE: %s" % compliance)
          # Deep copy because Python does copy by reference
          desired_state['compliance'].append(copy.deepcopy(compliance))
      print("FULL COMPLIANCE: %s" % desired_state['compliance'])
      desired_state['deployment'] = deployment['name'] + " - (ORG: " + deployment['orgId'] + ")"
      for remove_key in EXCLUDED_ROOT_KEYS:
        if remove_key in desired_state:
          desired_state.pop(remove_key)
          if DEBUG:
            print("Removed Key: %s" % remove_key)
      if 'key' in desired_state['auth']:
        desired_state['auth']['key'] = '<REDACTED>'
      if 'autoPwd' in desired_state['auth']:
        desired_state['auth']['autoPwd'] = '<REDACTED>'
      if 'ldap' in desired_state and 'bindQueryPassword' in desired_state['ldap']:
        desired_state['ldap']['bindQueryPassword'] = '<REDACTED>'
      for user in desired_state['auth']['usersWanted']:
        if 'pwd' in user:
          user['pwd'] = '<REDACTED>'
        if 'scramSha1Creds' in user:
          user['scramSha1Creds'] = '<REDACTED>'
        if 'scramSha256Creds' in user:
          user['scramSha256Creds'] = '<REDACTED>'

      # write results to audit db
      desired_state['ts'] = datetime.datetime.now()
      if DEBUG:
        print("RECORDED DATA: %s" % desired_state)
      try:
        audit_collection.insert_one(desired_state)
      except OperationFailure as e:
        print(e.details)
        logging.error(e.details)

if __name__ == "__main__": main()