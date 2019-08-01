import time, pymongo, configparser, os.path, sys, ast, json, logging, datetime, kerberos, re
from pprint import pprint
from pymongo.errors import DuplicateKeyError, OperationFailure

LOG_FILE = 'event_watcher.log'

# Get config setting from `event_watcher.config` file
if os.path.isfile('event_watcher.conf') == False:
  logging.basicConfig(filename=LOG_FILE,level=logging.ERROR)
  logging.error('The `event_watcher.conf` file must exist in the same directory as the Python script')
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
  temp_pipeline = config.get('ops_manager_db','event_pipeline',fallback=None)
  if temp_pipeline is not None:
    pipeline = ast.literal_eval(temp_pipeline)
  else:
    pipeline = []
except configparser.NoOptionError as e:
  logging.basicConfig(filename=LOG_FILE,level=logging.ERROR)
  logging.error('The config file must include the `connection_string` option in the `audit_db` section')
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
  logging.basicConfig(filename=LOG_FILE,level=logging.ERROR)
  logging.error('The config file must include sections `audit_db` and `general`')
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
  logging.basicConfig(filename=LOG_FILE,level=logging.DEBUG)
  logging.info("STARTING PROCESSING: %s" % datetime.datetime.now())
  logging.debug("AUDIT CONNECTION STRING: %s" % re.sub('//.+@', '//<REDACTED>@', audit_db_connection_string))
  logging.debug("CONNECTION STRING: %s" % re.sub('//.+@', '//<REDACTED>@',ops_manager_connection_string))
  logging.debug("RESUME TOKEN: %s" % resume_token)
  logging.debug("PIPELINE: %s" % pipeline)
  print("AUDIT CONNECTION STRING: %s" % re.sub('//.+@', '//<REDACTED>@', audit_db_connection_string))
  print("CONNECTION STRING: %s" % re.sub('//.+@', '//<REDACTED>@',ops_manager_connection_string))
  print("RESUME TOKEN: %s" % resume_token)
  print("PIPELINE: %s" % pipeline)
else:
  logging.basicConfig(filename=LOG_FILE,level=logging.INFO)
  logging.info("STARTING PROCESSING: %s" % datetime.datetime.now())

# connection to the Ops Manager replica set
ops_manager_client = pymongo.MongoClient(ops_manager_connection_string, serverSelectionTimeoutMS=ops_manager_timeout)
try:
  result = ops_manager_client.admin.command('ismaster')
except (pymongo.errors.ServerSelectionTimeoutError, pymongo.errors.ConnectionFailure) as e:
  logging.error("Cannot connect to Ops Manager DB, please check settings in config file: %s" %e)
  print('\033[91m' + "Cannot connect to Ops Manager DB, please check settings in config file: %s" %e)
  print('\033[m')
  sys.exit(1)
ops_manager_db = ops_manager_client['mmsdb']
ops_manager_collection = ops_manager_db['data.events']

# conneciton to the audit database
audit_client = pymongo.MongoClient(audit_db_connection_string, serverSelectionTimeoutMS=audit_db_timeout)
try:
  result = audit_client.admin.command('ismaster')
except (pymongo.errors.ServerSelectionTimeoutError, pymongo.errors.ConnectionFailure) as e:
  logging.error("Cannot connect to Audit DB, please check settings in config file: %s" %e)
  print("Cannot connect to Audit DB, please check settings in config file: %s" %e)
  sys.exit(1)
audit_db = audit_client['logging']
audit_collection = audit_db['logs']

if resume_token:
  cursor = ops_manager_collection.watch(resume_after={'_data': resume_token},pipeline=pipeline)
else:
  cursor = ops_manager_collection.watch(pipeline=pipeline)
try:
  while True:
    document = next(cursor)
    resume_token = document.get("_id")['_data']
    document['tag'] = 'OPS EVENT'
    document['host'] = 'OPS MANAGER'
    document['source'] = 'OPS MANAGER EVENTS'
    if debug:
      logging.debug("RESUME_TOKEN: %s" % resume_token)
      print("RESUME_TOKEN: %s" % resume_token)
      print("DOCUMENT: %s" % document)
    audit_collection.insert_one(document)
except OperationFailure as e:
  print(e.details)
  logging.error(e.details)
finally:
  if resume_token:
    outfile = open('.event_resume_token', 'w')
    outfile.write(resume_token)
    outfile.close()
  logging.info("TERMINATING PROCESSING: %s" % datetime.datetime.now())