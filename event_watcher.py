import time, pymongo, configparser, os.path, sys, ast
from pprint import pprint
from pymongo.errors import DuplicateKeyError, OperationFailure

# Get config setting from `event_watcher.config` file
if os.path.isfile('event_watcher.conf') == False:
  print('\033[93m' + 'The `event_watcher.conf` file must exist in the same directory as the Python script, exiting' + '\033[m')
  sys.exit(0)
config = configparser.ConfigParser()
config.read('event_watcher.conf')
try:
  debug = config.getboolean('general','debug', fallback=False)
  ops_manager_connection_string = config.get('ops_manager_db','connection_string')
  audit_db_connection_string = config.get('audit_db','connection_string')
  ops_manager_timeout = config.getint('ops_manager_db','timeout', fallback=100000)
  audit_db_timeout = config.getint('audit_db','timeout', fallback=100000)
  pipeline = ast.literal_eval(config.get('ops_manager_db','event_pipeline',fallback=[]))
except configparser.NoOptionError as e:
  print(e)
  print('\033[91m' + "ERROR! The config file must include the `connection_string` option in both the `ops_manager_db` and `audit_db` sections "
    ", such as:\n"
    + '\033[92m'
    "[ops_manager_db]\n"
    "connection_string=mongodb://username:password@host:port/?replicaSet=replicasetname\n\n"
    "[audit_db]"
    "connection_string=mongodb://username:password@host:port/?replicaSet=replicasetname\n"
    + '\033[m')
  sys.exit(1)
except configparser.NoSectionError as e:
  print('\033[91m' + "ERROR! The config file must include sections `ops_manager_db`, `audit_db` and `general`, such as:\n"
    + '\033[92m'
    "[ops_manager_db]\n"
    "connection_string=mongodb://username:password@host:port/?replicaSet=replicasetname\n"
    "timeout=1000\n"
    "event_pipeline=\n\n"
    "[audit_db]\n"
    "connection_string=mongodb://username:password@host:port/?replicaSet=replicasetname\n"
    "timeout=1000\n\n"
    "[general]\n"
    "debug=False"
    + '\033[m'
    )
  sys.exit(1)

# Get resume token, is exists
if os.path.isfile('.event_resume_token'):
  token_file = open('.event_resume_token','r')
  resume_token = token_file.readline().strip()
  token_file.close()
else:
  resume_token = None

if debug == True:
  print("AUDIT CONNECTION STRING: %s" % audit_db_connection_string)
  print("CONNECTION STRING: %s" % ops_manager_connection_string)
  print("RESUME TOKEN: %s" % resume_token)

# connection to the Ops Manager replica set
ops_manager_client = pymongo.MongoClient(ops_manager_connection_string, serverSelectionTimeoutMS=ops_manager_timeout)
try:
  result = ops_manager_client.admin.command('ismaster')
except pymongo.errors.ServerSelectionTimeoutError as e:
  print("Cannot connect to Ops Manager DB, please check settings in config file: %s" %e)
  raise
except pymongo.errors.ConnectionFailure as e:
  print("Cannot connect to Ops Manager DB, please check settings in config file: %s" %e)
  raise
ops_manager_db = ops_manager_client['mmsdb']
ops_manager_collection = ops_manager_db['data.events']

# conneciton to the audit database
audit_client = pymongo.MongoClient(audit_db_connection_string, serverSelectionTimeoutMS=audit_db_timeout)
try:
  result = audit_client.admin.command('ismaster')
except pymongo.errors.ServerSelectionTimeoutError as e:
  print("Cannot connect to Audit DB, please check settings in config file: %s" %e)
  raise
except pymongo.errors.ConnectionFailure as e:
  print("Cannot connect to Audit DB, please check settings in config file: %s" %e)
  raise
audit_db = audit_client['logging']
audit_collection = audit_db['logs']

if resume_token:
  cursor = ops_manager_collection.watch(resume_after={'_data': resume_token})
else:
  cursor = ops_manager_collection.watch(pipeline=pipeline)
try:
  while True:
    document = next(cursor)
    resume_token = document.get("_id")['_data']
    if debug:
      print("RESUME_TOKEN: %s" % resume_token)
    document['tag'] = 'OPS EVENT'
    document['host'] = 'OPS MANAGER'
    document['source'] = 'OPS MANAGER EVENTS'
    audit_collection.insert_one(document)
except OperationFailure as e:
  print(e.details)
finally:
  if resume_token:
    outfile = open('.event_resume_token', 'w')
    outfile.write(resume_token)
    outfile.close()