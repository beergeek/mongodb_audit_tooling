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
  from pprint import pprint
  from bson.json_util import dumps, loads
  from pymongo.errors import OperationFailure,PyMongoError
  if sys.version_info[0] >= 3:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    urllib3.disable_warnings(urllib3.exceptions.SubjectAltNameWarning)
except ImportError as e:
  print(e)
  exit(1)

LOG_FILE = sys.path[0] + '/deployment_configs.log'
CONF_FILE = sys.path[0] + '/deployment_configs.conf'
waiver_processes = {"processes": {"version": "WAIVER"}}
ROLE_SEARCH_TERMS = []

def config_err_mesg(msg):
  err_msg = """\033[91mERROR! """ + str(msg) + """. The config file should look similar to (leave out SSL if not required):
    \033[92m
    [ops_manager]
    baseurl=https://host:port/api/public/v1.0
    username=loud.sam
    token=8ce50f02-4292-460e-82a5-000a0742182a
    ssl_ca_cert_path=/data/pki/ca.cert
    ssl_pem_path=/data/pki/mongod6.mongodb.local.pem

    [audit_db]
    connection_string=mongodb://auditwriter%%40MONGODB.LOCAL@mongod6.mongodb.local:27017/?replicaSet=repl0&authSource=$external&authMechanism=GSSAPI
    timeout=1000
    ssl_enabled=True
    ssl_ca_cert_path=/data/pki/ca.cert
    ssl_pem_path=/data/pki/mongod6.mongodb.local.pem

    [general]
    debug=false
    excluded_root_keys=mongoDbVersions,mongosqlds,backupVersions,agentVersion,monitoringVersions,uiBaseUrl,cpsModules,mongots,indexConfigs
    role_search_terms=Admin,schema

    [deployments]
    db_credentials=auditwriter%%40MONGODB.LOCAL
    non_om_deployments=mongod10.mongodb.local:27017/?replicaSet=appdb,mongod10.mongodb.local:27018/?replicaSet=oplogdb
    ssl_enabled=True
    ssl_ca_cert_path=/data/pki/ca.cert
    ssl_pem_path=/data/pki/mongod6.mongodb.local.pem
    auth_source=$external
    auth_method=GSSAPI
    \033[m"""
  return err_msg

# Get config setting from `event_watcher.config` file
if os.path.isfile(CONF_FILE) == False:
  logging.basicConfig(filename=LOG_FILE,level=logging.ERROR)
  logging.error('The `deployment_configs.conf` file must exist in the same directory as the Python script')
  print('\033[93m' + 'The `deployment_configs.conf` file must exist in the same directory as the Python script, exiting' + '\033[m')
  sys.exit(0)
config = configparser.ConfigParser()
config.read(CONF_FILE)
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
  OPS_MANAGER_TIMEOUT = config.getint('ops_manager','timeout', fallback=10)
  AUDIT_DB_TIMEOUT = config.getint('audit_db','timeout', fallback=10)
  EXCLUDED_ROOT_KEYS = config.get('general','excluded_root_keys',fallback=None)
  ROLE_SEARCH_TERMS = config.get('general','role_search_terms',fallback='schema').replace(',', '|')
  NON_OM_DEPLOYMENTS = config.get('deployments','non_om_deployments',fallback=None)
  DB_CREDENTIALS = config.get('deployments','db_credentials',fallback=None)
  AUTH_SOURCE = config.get('deployments','auth_source',fallback='$external')
  AUTH_METHOD = config.get('deployments','auth_method',fallback='GSSAPI')
  DEPLOY_DB_SSL = config.getboolean('deployments','ssl_enabled',fallback=False)
  if DEPLOY_DB_SSL is True:
    DEPLOY_DB_SSL_PEM = config.get('deployments','ssl_pem_path')
    DEPLOY_DB_SSL_CA = config.get('deployments', 'ssl_ca_cert_path')
  DEPLOY_DB_TIMEOUT = config.getint('deployments','timeout', fallback=10)
except (configparser.NoOptionError,configparser.NoSectionError) as e:
  logging.basicConfig(filename=LOG_FILE,level=logging.ERROR)
  logging.error(e)
  print(config_err_mesg(e))
  sys.exit(1)
  sys.exit(1)

if DEBUG == True:
  logging.basicConfig(filename=LOG_FILE,level=logging.DEBUG)
  logging.info("STARTING PROCESSING: %s" % datetime.datetime.now())
  logging.debug("AUDIT CONNECTION STRING: %s" % re.sub('//.+@', '//<REDACTED>@', AUDIT_DB_CONNECTION_STRING))
  logging.debug("OPS MANAGER CONNECTION STRING: %s" % re.sub('//.+@', '//<REDACTED>@',BASEURL))
  logging.debug("EXCLUDED KEYS: %s" % EXCLUDED_ROOT_KEYS)
  logging.debug("ROLE SEARCH TERMS: %s" % ROLE_SEARCH_TERMS)
  logging.debug("NON OM DEPLOYMETNS: %s" % NON_OM_DEPLOYMENTS)
  print("AUDIT CONNECTION STRING: %s" % re.sub('//.+@', '//<REDACTED>@', AUDIT_DB_CONNECTION_STRING))
  print("OPS MANAGER CONNECTION STRING: %s" % re.sub('//.+@', '//<REDACTED>@',BASEURL))
else:
  logging.basicConfig(filename=LOG_FILE,level=logging.INFO)
  logging.info("STARTING PROCESSING: %s" % datetime.datetime.now())

# connection to the audit database
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
archive_collection = audit_db['configs_archive']

def get(endpoint):
  resp = requests.get(BASEURL + '/api/public/v1.0' + endpoint, auth=HTTPDigestAuth(USERNAME, TOKEN), verify=OPS_MANAGER_SSL_CA, cert=OPS_MANAGER_SSL_PEM, timeout=OPS_MANAGER_TIMEOUT)
  if resp.status_code == 200:
    get_data = json.loads(resp.text)
    return get_data
  else:
    print("GET response was %s, not `200`" % resp.status_code)
    print(resp.text)
    raise requests.exceptions.RequestException

def get_standards():
  try:
    standard = audit_db.standards.find_one({"valid_to": {"$exists": False}})
    if standard is None:
      standard = {}
    if DEBUG:
      print("STANDARD: %s" % standard)
  except OperationFailure as e:
    print(e.details)
    logging.error(e.details)
  return standard

def get_waiver(deployment):
  try:
    waiver = audit_db.waivers.find_one({"deployment": deployment, "valid_to": {"$gt": datetime.datetime.now()}})
    if waiver is None:
      waiver = {}
    if DEBUG:
      print("WAIVER: %s" % waiver)
  except OperationFailure as e:
    print(e.details)
    logging.error(e.details)
  return waiver

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
          if DEBUG:
            print('Another dict')
          temp_dict = check_dict(k, vs, vd, waivers)
          failure_data['waiver'].extend(temp_dict['waiver'])
          failure_data['issue'].extend(temp_dict['issue'])
        else:
          if DEBUG:
            print("\033[91mSadness: `%s: %s`, should be `%s`\033[m" % (k , vd, vs))
          failure_data['issue'].append("`%s: %s`, should be `%s`" % (k , vd, vs))
      elif type(vs) is list:
        if type(vd) is list:
          if DEBUG:
            print('Another list')
          temp_dict = check_list(k, vs, vd, waivers)
          failure_data['waiver'].extend(temp_dict['waiver'])
          failure_data['issue'].extend(temp_dict['issue'])
        else:
          if DEBUG:
            print("\033[91mSadness: `%s: %s, should be %s`\033[m" % (k , vd, vs))
          failure_data['issue'].append("`%s: %s`, should be `%s`" % (k , vd, vs))
      elif vs != vd:
        try:
          if waivers[ks] == vd:
            if DEBUG:
              print("\033[93mWaiver: `%s: %s, should be %s`\033[m" % (k, vd, vs))
            failure_data['waiver'].append("`%s: %s`, standard is `%s`" % (k , vd, vs))
        except KeyError:
          if DEBUG:
            print("\033[91mSadness: `%s: %s, should be %s`\033[m" % (k , vd, vs))
          failure_data['issue'].append("`%s: %s`, should be `%s`" % (k , vd, vs))
  return failure_data


def check_list(k, s_array, d_array, waivers):
  failure_data = {"issue": [], "waiver": []}
  if type(s_array) is list and type(d_array) is list:
    if len(s_array) != len(d_array):
       failure_data['issue'].append("[`%s`] has too many elements" % ', '.join(map(str, d_array)))
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
            if DEBUG:
              print('Another dict')
            temp_dict = check_dict(k, vs, vd, waivers)
            failure_data['waiver'].extend(temp_dict['waiver'])
            failure_data['issue'].extend(temp_dict['issue'])
          else:
            if DEBUG:
              print("\033[91mSadness: `%s: %s, should be %s`\033[m" % (k , vd, vs))
            failure_data['issue'].append("`%s: %s`, should be `%s`" % (k , vd, vs))
      if type(vs) is list:
          if type(vd) is list:
            if DEBUG:
              print('Another list')
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

def process_aggregation(hostname, port, replica_set, pipeline_array):
  try:
    documents = []
    local_connection_string = "mongodb://" + DB_CREDENTIALS + "@" + hostname + ":" + str(port) + "/?replicaSet=" + replica_set + "&authSource=" + AUTH_SOURCE + "&authMechanism=" + AUTH_METHOD
    if DEPLOY_DB_SSL is True:
      if DEBUG is True:
        logging.debug("Using SSL/TLS to %s:%s" % (hostname,str(port)))
        print("Using SSL/TLS to %s:%s" % (hostname,str(port)))
      local = pymongo.MongoClient(local_connection_string, serverSelectionTimeoutMS=DEPLOY_DB_TIMEOUT, ssl=True, ssl_certfile=DEPLOY_DB_SSL_PEM, ssl_ca_certs=DEPLOY_DB_SSL_CA)
    else:
      if DEBUG is True:
        logging.debug("Not ussing SSL/TLS to %s:%s" % (hostname,str(port)))
        print("Not using SSL/TLS to %s:%s" % (hostname,str(port)))
      local = pymongo.MongoClient(local_connection_string, serverSelectionTimeoutMS=DEPLOY_DB_TIMEOUT)

    for data in loads(pipeline_array):
      results_array = []
      if 'database' in data:
        db = local[data['database']]
      else:
        db = local['admin']
      coll = db[data['collection']]
      query_data = coll.aggregate(data['pipeline'])
      for document in query_data:
        pprint(document)
        results_array.append(document)
      test_data = {'test_name': data['name'], 'issue': results_array}
      documents.append(test_data)
    local.close()
    #pprint(documents)
    return documents
  except (pymongo.errors.ServerSelectionTimeoutError, pymongo.errors.ConnectionFailure) as e:
    logging.error("Cannot connect to deployment %s: %s" % (replica_set,e))
    if DEBUG:
      print("Cannot connect to deployment %s: %s" % (replica_set, e))
    return ["Cannot connect to deployment %s on %s, connection failure" % (replica_set, hostname)]
  except (pymongo.errors.ConfigurationError, pymongo.errors.OperationFailure) as e:
    logging.error("Cannot execute on deployment %s: %s" % (replica_set,e))
    if DEBUG:
      print("Cannot execute on deployment %s: %s" % (replica_set,e))
    return ["Cannot execute on deployment %s on %s. This maybe a permissions issue" % (replica_set, hostname)]

def get_primary(deployment_id):
  primary = None
  cluster_list = get('/groups/' + deployment_id + '/clusters')
  for cluster in cluster_list['results']:
    host_list = get('/groups/' + deployment_id + '/hosts/?clusterId=' + cluster['id'])
    for host in host_list['results']:
      if host['typeName'] == 'REPLICA_PRIMARY' or host['typeName'] == 'SHARD_MONGOS':
        primary = host
        break
  return primary


def get_supplementry(id, pipeline):
  primary = get_primary(id)
  agg_output = process_aggregation(primary['hostname'], primary['port'], primary['replicaSetName'], pipeline)
  return agg_output



def check_user_waiver(user_dict, waiver_list):
  failure_data = {"issue": [], "waiver": []}
  if type(user_dict) is list and type(waiver_list) is list:
    for entry in user_dict:
      if type(entry) is dict:
        if 'user' in entry and entry['user'] in waiver_list:
          failure_data['waiver'].append(entry['user'] + " has a waiver for local login with:" + dumps(entry['mech']) + ' on ' + entry['db'])
        else:
          failure_data['issue'].append(entry['user'] + " has a local login with:" + dumps(entry['mech']) + "on " + entry['db'])
  return failure_data

def check_admin_waiver(admin_dict, waiver_list):
  failure_data = {"issue": [], "waiver": []}
  schema_pattern = re.compile(ROLE_SEARCH_TERMS)
  if type(admin_dict) is list and type(waiver_list) is list:
    for entry in admin_dict:
      if type(entry) is dict:
        if 'user' in entry and 'roles' in entry and type(entry['roles']) is list:
          for role in entry['roles']:
            if role['role'] == 'root' or schema_pattern.search(role['role']): 
              if entry['user'] in waiver_list:
                failure_data['waiver'].append(entry['user'] + " has a waiver for Admin access with:" + dumps(entry['roles']) + ' on ' + entry['db'])
              else:
                failure_data['issue'].append(entry['user'] + ' has Admin access with ' + dumps(entry['roles']) + ' on ' + entry['db'])
              break
      else:
        failure_data['issue'].append(entry)
  return failure_data

def get_non_om_deployments():
  deployments = []
  for deployment in NON_OM_DEPLOYMENTS.split(','):
    try:
      local_connection_string = "mongodb://" + deployment
      if DEPLOY_DB_SSL is True:
        if DEBUG is True:
          logging.debug("Using SSL/TLS to %s:%s" % deployment)
          print("Using SSL/TLS to %s:%s" % deployment)
        local = pymongo.MongoClient(local_connection_string, serverSelectionTimeoutMS=DEPLOY_DB_TIMEOUT, ssl=True, ssl_certfile=DEPLOY_DB_SSL_PEM, ssl_ca_certs=DEPLOY_DB_SSL_CA)
      else:
        if DEBUG is True:
          logging.debug("Not ussing SSL/TLS to %s" % deployment)
          print("Not using SSL/TLS to %s" % deployment)
        local = pymongo.MongoClient(local_connection_string, serverSelectionTimeoutMS=DEPLOY_DB_TIMEOUT)
      # we could use `local.nodes`, but this gives us more details
      deployment_details = local.admin.command('isMaster')
      deployments.append(
        { 
          'hosts': deployment_details['hosts'],
          'setName': deployment_details['setName'],
          'hostCounts': {
            'mongos': 0,
            'primary': len(local.primary),
            'secondaries': len(local.secondaries) - 1
          },
          'name': deployment_details['setName'],
          'orgId': 'Non Ops Manager Managed Environment'
        }
      )
      local.close()
    except (pymongo.errors.ServerSelectionTimeoutError, pymongo.errors.ConnectionFailure) as e:
      logging.error("Cannot connect to deployment %s: %s" % (deployment, e))
      if DEBUG:
        print("Cannot connect to deployment %s: %s" % (deployment, e))
      return None
    except (pymongo.errors.ConfigurationError, pymongo.errors.OperationFailure) as e:
      logging.error("Cannot execute on deployment %s: %s" % (deployment, e))
      if DEBUG:
        print("Cannot execute on deployment %s: %s" % (deployment, e))
      return None
  return deployments


# We need to retrieve the config from the non-Ops Manager managed instances and format the data like the Ops Manager managed instances for processes
def get_deployment_configs(deployment_dict):
  deployments_args = {'processes': [], 'ts': datetime.datetime.now()}
  deployments_args.update(copy.deepcopy(deployment_dict))
  try:
    for instance in deployment_dict['hosts']:
      local_connection_string = "mongodb://" + DB_CREDENTIALS + '@' + instance + '/?replicaSet=' + deployment_dict['setName'] + "&authSource=" + AUTH_SOURCE + "&authMechanism=" + AUTH_METHOD
      if DEPLOY_DB_SSL is True:
        if DEBUG is True:
          logging.debug("Using SSL/TLS to %s:%s" % instance)
          print("Using SSL/TLS to %s:%s" % instance)
        local = pymongo.MongoClient(local_connection_string, serverSelectionTimeoutMS=DEPLOY_DB_TIMEOUT, ssl=True, ssl_certfile=DEPLOY_DB_SSL_PEM, ssl_ca_certs=DEPLOY_DB_SSL_CA)
      else:
        if DEBUG is True:
          logging.debug("Not ussing SSL/TLS to %s" % instance)
          print("Not using SSL/TLS to %s" % instance)
        local = pymongo.MongoClient(local_connection_string, serverSelectionTimeoutMS=DEPLOY_DB_TIMEOUT)
      deployment_details = local.admin.command({ 'getCmdLineOpts': 1  })
      deployments_args['processes'].append({'args2_6': deployment_details['parsed'], 'hostname': instance.split(':')[0]})
      local.close()
  except (pymongo.errors.ServerSelectionTimeoutError, pymongo.errors.ConnectionFailure) as e:
    logging.error("Cannot connect to deployment %s: %s" % (instance, e))
    if DEBUG:
      print("Cannot connect to deployment %s: %s" % (instance, e))
    return None
  except (pymongo.errors.ConfigurationError, pymongo.errors.OperationFailure) as e:
    logging.error("Cannot execute on deployment %s: %s" % (instance, e))
    if DEBUG:
      print("Cannot execute on deployment %s: %s" % (instance, e))
    return None
  return deployments_args

def main():
  STANDARDS = get_standards()
  if DEBUG:
    print(STANDARDS)
  
  # Get all the deployments from Ops Manager
  DEPLOYMENTS = get('/groups')
  if DB_CREDENTIALS and NON_OM_DEPLOYMENTS:
    deploys = get_non_om_deployments()
    if type(deploys) is list:
      DEPLOYMENTS['results'].extend(deploys)

  for deployment in DEPLOYMENTS['results']:
    if 'hostCounts' in deployment and (deployment['hostCounts']['mongos'] > 0 or deployment['hostCounts']['primary'] > 0):
      # Get group from Ops Manager, if this deployment belongs to Ops Manager
      # otherwise we get the previous data
      if 'id' in deployment:
        desired_state = get('/groups/' + deployment['id'] + '/automationConfig')
        desired_state['source'] = 'OPS MANAGER'
      else:
        desired_state = copy.deepcopy(get_deployment_configs(deployment))
        if desired_state is None:
          continue
        desired_state['source'] = 'INSTANCE'
      desired_state['compliance'] = []
      compliance = []

      # determine if a waiver exists for this deployment
      waiver_details = get_waiver(deployment['name'] + " - (ORG: " + deployment['orgId'] + ")")
      if DEBUG:
        print("DEPLOYMENT NAME: %s" % deployment['name'])
        print("WAIVER: %s" % waiver_details)

      # Only check for compliance if there is a standard to check against
      if STANDARDS and DB_CREDENTIALS:
        if STANDARDS['supplementry_pipeline']:
          # check the users in a deployment locally at the deployment
          if 'id' in deployment:
            # For Ops Manager controlled
            compliance = get_supplementry(deployment['id'], STANDARDS['supplementry_pipeline'])
          else:
            # For non-Ops Manager deployments
            compliance = process_aggregation(desired_state['processes'][0]['hostname'],desired_state['processes'][0]['args2_6']['net']['port'],desired_state['processes'][0]['args2_6']['replication']['replSetName'], STANDARDS['supplementry_pipeline'])

          print(compliance)
          desired_state['compliance'].append({'host': 'Supplementry', 'issues': copy.deepcopy(compliance)})
        if 'project' not in waiver_details:
          waiver_details['project'] = {}
        deployment_compliance = check_dict('', STANDARDS['standard']['project'], desired_state, waiver_details['project'])
        deployment_compliance['host'] = 'Project Level'
        # Deep copy because Python does copy by reference
        desired_state['compliance'].append(copy.deepcopy(deployment_compliance))
      
      # Determine if project has any instances
      if desired_state['processes']:
        for instance in desired_state['processes']:
          # Only check for compliance if there is a standard to check against
          if STANDARDS:
            if 'processes' not in waiver_details:
              waiver_details['processes'] = {}
            compliance = check_dict("processes", STANDARDS['standard']['processes'], instance, waiver_details['processes'])
            # If we have a compliance issue or waiver in place we record that too
            if compliance:
              compliance['host'] = instance['hostname']
              if DEBUG:
                print("COMPLIANCE: %s" % compliance)
              # Deep copy because Python does copy by reference
              desired_state['compliance'].append(copy.deepcopy(compliance))
        desired_state['deployment'] = deployment['name'] + " - (ORG: " + deployment['orgId'] + ")"

        # Remove or redact data that is sensitive
        if EXCLUDED_ROOT_KEYS:
          for remove_key in EXCLUDED_ROOT_KEYS.split(','):
            if remove_key in desired_state:
              desired_state.pop(remove_key)
              if DEBUG:
                print("Removed Key: %s" % remove_key)
        if 'auth' in desired_state:
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
        try:
          for i in range(0,4):
            if 'issue' in compliance and len(compliance['issue']) > 0:
              # Get the current timestamp of the document so we can check if it is written before we modify
              current_state = audit_collection.find_one(
                {
                  "deployment": desired_state['deployment']
                },
                {
                  "start_datetime": 1, "ts": 1
                }
              )
              # set our schema version
              if 'schema_version' not in desired_state:
                desired_state['schema_version'] = 0

              # If we have a compliance issue increment the occurence counter.
              # Determine if the deployment already has a compliance issue occurring.
              # If not set the start date for the issue
              # If there is no compliance issue, reset the date and counter.
              if current_state and 'start_datetime' in current_state:
                if DEBUG:
                  print("RECORDED DATA: %s" % dumps(desired_state, indent=2))
                result = audit_collection.update_one(
                  {
                    "deployment": desired_state['deployment'],
                    "ts": current_state['ts']
                  },
                  {
                    "$set": desired_state,
                    "$inc": {"uncompliance_count": 1}
                  }
                )
              else:
                desired_state['start_datetime'] = desired_state['ts']
                if DEBUG:
                  print("RECORDED DATA: %s" % desired_state)
                result = audit_collection.update_one(
                  {
                    "deployment": desired_state['deployment'],
                    "ts": desired_state['ts']
                  },
                  {
                    "$set": desired_state,
                    "$inc": {"uncompliance_count": 1}
                  },
                  upsert=True
                )
            else:
              # No compliance issues
              desired_state['uncompliance_count'] = 0
              if DEBUG:
                print("RECORDED DATA: %s" % desired_state)
              result = audit_collection.update_one(
                {
                  "deployment": desired_state['deployment'],
                  "ts": current_state['ts']
                },
                {
                  "$set": desired_state,
                  "$unset": {"start_datetime": ""}
                },
                upsert=True
              )
            result = {}
            result['matched_count'] = 1
            if result['matched_count'] == 1 or result['upserted_id']:
              # update was successful, so write to archive as well, then exit the loop
              # retry if it was not successful
              archive_collection.insert_one(desired_state)
              break
            elif i == 4:
              print("Failed to update the correct document, exiting")
              raise PyMongoError("Failed to update the correct document, exiting")
        except OperationFailure as e:
          print(e.details)
          logging.error(e.details)
        except TypeError as e:
          print(e)

if __name__ == "__main__": main()