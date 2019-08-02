try:
  import time, pymongo, configparser, os.path, sys, ast, json, logging, datetime, kerberos, re
  from pymongo.errors import DuplicateKeyError, OperationFailure
except ImportError as e:
  print(e)
  exit(1)

LOG_FILE = 'config_watcher.log'

# Get config setting from `config_watcher.config` file
if os.path.isfile('config_watcher.conf') == False:
  logging.basicConfig(filename=LOG_FILE,level=logging.ERROR)
  logging.error('The `config_watcher.conf` file must exist in the same directory as the Python script')
  print('\033[93m' + 'The `config_watcher.conf` file must exist in the same directory as the Python script, exiting' + '\033[m')
  sys.exit(0)
config = configparser.ConfigParser()
config.read('config_watcher.conf')
try:
  DEBUG = config.getboolean('general','debug', fallback=False)
  OPS_MANAGER_CONNECTION_STRING = config.get('ops_manager_db','connection_string')
  OPS_MANAGER_SSL = config.getboolean('ops_manager_db','ssl_enabled',fallback=False)
  if OPS_MANAGER_SSL is True:
    OPS_MANAGER_SSL_PEM = config.get('ops_manager_db','ssl_pem_path')
    OPS_MANAGER_SSL_CA = config.get('ops_manager_db', 'ssl_ca_cert_path')
  AUDIT_DB_CONNECTION_STRING = config.get('audit_db','connection_string')
  AUDIT_DB_SSL = config.getboolean('audit_db','ssl_enabled',fallback=False)
  if AUDIT_DB_SSL is True:
    AUDIT_DB_SSL_PEM = config.get('audit_db','ssl_pem_path')
    AUDIT_DB_SSL_CA = config.get('audit_db', 'ssl_ca_cert_path')
  OPS_MANAGER_TIMEOUT = config.getint('ops_manager_db','timeout', fallback=10000)
  AUDIT_DB_TIMEOUT = config.getint('audit_db','timeout', fallback=10000)
  temp_pipeline = config.get('ops_manager_db','event_pipeline',fallback=None)
  if temp_pipeline is not None:
    PIPELINE = ast.literal_eval(temp_pipeline)
  else:
    PIPELINE = []
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
if os.path.isfile('.config_resume_token'):
  token_file = open('.config_resume_token','r')
  resume_token = token_file.readline().strip()
  token_file.close()
else:
  resume_token = None

if DEBUG == True:
  logging.basicConfig(filename=LOG_FILE,level=logging.DEBUG)
  logging.info("STARTING PROCESSING: %s" % datetime.datetime.now())
  logging.debug("AUDIT CONNECTION STRING: %s" % re.sub('//.+@', '//<REDACTED>@', AUDIT_DB_CONNECTION_STRING))
  logging.debug("OPS MANAGER CONNECTION STRING: %s" % re.sub('//.+@', '//<REDACTED>@',OPS_MANAGER_CONNECTION_STRING))
  logging.debug("RESUME TOKEN: %s" % resume_token)
  logging.debug("PIPELINE: %s" % PIPELINE)
  print("AUDIT CONNECTION STRING: %s" % re.sub('//.+@', '//<REDACTED>@', AUDIT_DB_CONNECTION_STRING))
  print("OPS MANAGER CONNECTION STRING: %s" % re.sub('//.+@', '//<REDACTED>@',OPS_MANAGER_CONNECTION_STRING))
  print("RESUME TOKEN: %s" % resume_token)
  print("PIPELINE: %s" % PIPELINE)
else:
  logging.basicConfig(filename=LOG_FILE,level=logging.INFO)
  logging.info("STARTING PROCESSING: %s" % datetime.datetime.now())

# connection to the Ops Manager replica set
try:
  if OPS_MANAGER_SSL is True:
    if DEBUG is True:
      logging.debug("Using SSL/TLS to OM DB")
      print("Using SSL/TLS to OM DB")
    ops_manager_client = pymongo.MongoClient(OPS_MANAGER_CONNECTION_STRING, serverSelectionTimeoutMS=OPS_MANAGER_TIMEOUT, ssl=True, ssl_certfile=OPS_MANAGER_SSL_PEM, ssl_ca_certs=OPS_MANAGER_SSL_CA)
  else:
    if DEBUG is True:
      logging.debug("Not ussing SSL/TLS to OM DB")
      print("Not using SSL/TLS to OM DB")
    ops_manager_client = pymongo.MongoClient(OPS_MANAGER_CONNECTION_STRING, serverSelectionTimeoutMS=OPS_MANAGER_TIMEOUT)
  result = ops_manager_client.admin.command('ismaster')
except (pymongo.errors.ServerSelectionTimeoutError, pymongo.errors.ConnectionFailure) as e:
  logging.error("Cannot connect to Ops Manager DB, please check settings in config file: %s" %e)
  print('\033[91m' + "Cannot connect to Ops Manager DB, please check settings in config file: %s" %e)
  print('\033[m')
  sys.exit(1)
ops_manager_db = ops_manager_client['cloudconf']
ops_manager_collection = ops_manager_db['config.appState']

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
audit_collection = audit_db['logs']

if resume_token:
  cursor = ops_manager_collection.watch(resume_after={'_data': resume_token},pipeline=PIPELINE)
else:
  cursor = ops_manager_collection.watch(pipeline=PIPELINE)
try:
  while True:
    document = next(cursor)
    resume_token = document.get("_id")['_data']
    document['tag'] = 'OPS EVENT'
    document['host'] = 'OPS MANAGER'
    document['source'] = 'OPS MANAGER CONFIG'
    if DEBUG:
      logging.debug("RESUME_TOKEN: %s" % resume_token)
      print("RESUME_TOKEN: %s" % resume_token)
      print("DOCUMENT: %s" % document)
    audit_collection.insert_one(document)
except OperationFailure as e:
  logging.error(e.details)
  print(e.details)
finally:
  if resume_token:
    outfile = open('.config_resume_token', 'w')
    outfile.write(resume_token)
    outfile.close()
  logging.info("TERMINATING PROCESSING: %s" % datetime.datetime.now())