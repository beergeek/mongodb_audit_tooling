try:
  import ast
  import configparser
  import datetime
  import json
  import kerberos
  import logging
  import os.path
  import pymongo
  import re
  import signal
  import sys
  import time
  from pymongo.errors import DuplicateKeyError, OperationFailure
except ImportError as e:
  print(e)
  exit(1)

def write_resume_token(signum, frame):
  if resume_token:
    outfile = open(sys.path[0] + '/.event_resume_token', 'w')
    outfile.write(resume_token)
    outfile.close()
    logging.info("RESUME TOKEN: %s" % (resume_token))
  logging.info("TERMINATING PROCESSING: %s" % datetime.datetime.now())
  sys.exit(0)

# global varible
resume_token = None
signal.signal(signal.SIGINT, write_resume_token)
signal.signal(signal.SIGTERM, write_resume_token)

# Get config setting from `event_watcher.config` file
def get_config():
  LOG_FILE = sys.path[0] + '/event_watcher.log'
  CONF_FILE = sys.path[0] + '/event_watcher.conf'
  if os.path.isfile(CONF_FILE) == False:
    logging.basicConfig(filename=LOG_FILE,level=logging.ERROR)
    logging.error('The `event_watcher.conf` file must exist in the same directory as the Python script')
    print('\033[93m' + 'The `event_watcher.conf` file must exist in the same directory as the Python script, exiting' + '\033[m')
    sys.exit(1)

  config = configparser.ConfigParser()
  config.read(CONF_FILE)
  config_options = {}
  try:
    config_options['DEBUG'] = config.getboolean('general','debug', fallback=False)
    config_options['OPS_MANAGER_SSL_CONNECTION_STRING'] = config.get('ops_manager_db','connection_string')
    config_options['OPS_MANAGER_SSL'] = config.getboolean('ops_manager_db','ssl_enabled',fallback=False)
    if config_options['OPS_MANAGER_SSL'] is True:
      config_options['OPS_MANAGER_SSL_PEM'] = config.get('ops_manager_db','ssl_pem_path')
      config_options['OPS_MANAGER_SSL_CA'] = config.get('ops_manager_db', 'ssl_ca_cert_path')
    config_options['AUDIT_DB_CONNECTION_STRING'] = config.get('audit_db','connection_string')
    config_options['AUDIT_DB_SSL'] = config.getboolean('audit_db','ssl_enabled',fallback=False)
    if config_options['AUDIT_DB_SSL'] is True:
      config_options['AUDIT_DB_SSL_PEM'] = config.get('audit_db','ssl_pem_path')
      config_options['AUDIT_DB_SSL_CA'] = config.get('audit_db', 'ssl_ca_cert_path')
    config_options['OPS_MANAGER_TIMEOUT'] = config.getint('ops_manager_db','timeout', fallback=10)
    config_options['AUDIT_DB_TIMEOUT'] = config.getint('audit_db','timeout', fallback=10)
    temp_pipeline = config.get('ops_manager_db','event_pipeline',fallback=None)
    if temp_pipeline is not None:
      config_options['PIPELINE'] = ast.literal_eval(temp_pipeline)
    else:
      config_options['PIPELINE'] = []
  except configparser.NoOptionError:
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
  except configparser.NoSectionError:
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
  return config_options

# Get resume token, is exists
def get_resume_token():
  if os.path.isfile(sys.path[0] + '.event_resume_token'):
    token_file = open(sys.path[0] + '.event_resume_token','r')
    retrieved_token = token_file.readline().strip()
    token_file.close()
  else:
    retrieved_token = None
  return retrieved_token

# Record our startup and config
def record_startup(config_array, debug=False):
  if debug == True:
    logging.info("STARTING PROCESSING: %s" % datetime.datetime.now())
    logging.debug("AUDIT CONNECTION STRING: %s" % re.sub('//.+@', '//<REDACTED>@', config_array['AUDIT_DB_CONNECTION_STRING']))
    logging.debug("OPS MANAGER CONNECTION STRING: %s" % re.sub('//.+@', '//<REDACTED>@',config_array['OPS_MANAGER_SSL_CONNECTION_STRING']))
    logging.debug("RESUME TOKEN: %s" % resume_token)
    logging.debug("PIPELINE: %s" % config_array['PIPELINE'])
    print("AUDIT CONNECTION STRING: %s" % re.sub('//.+@', '//<REDACTED>@', config_array['AUDIT_DB_CONNECTION_STRING']))
    print("OPS MANAGER CONNECTION STRING: %s" % re.sub('//.+@', '//<REDACTED>@',config_array['OPS_MANAGER_SSL_CONNECTION_STRING']))
    print("RESUME TOKEN: %s" % resume_token)
    print("PIPELINE: %s" % config_array['PIPELINE'])
  else:
    logging.info("STARTING PROCESSING: %s" % datetime.datetime.now())

# connection to the Ops Manager replica set
def om_db_client(om_db_data, debug=False):
  try:
    if om_db_data['OPS_MANAGER_SSL'] is True:
      if debug is True:
        logging.debug("Using SSL/TLS to OM DB")
        print("Using SSL/TLS to OM DB")
      ops_manager_client = pymongo.MongoClient(om_db_data['OPS_MANAGER_SSL_CONNECTION_STRING'], serverSelectionTimeoutMS=om_db_data['OPS_MANAGER_TIMEOUT'], ssl=True, ssl_certfile=om_db_data['OPS_MANAGER_SSL_PEM'], ssl_ca_certs=om_db_data['OPS_MANAGER_SSL_CA'])
    else:
      if debug is True:
        logging.debug("Not using SSL/TLS to OM DB")
        print("Not using SSL/TLS to OM DB")
      ops_manager_client = pymongo.MongoClient(om_db_data['OPS_MANAGER_SSL_CONNECTION_STRING'], serverSelectionTimeoutMS=om_db_data['OPS_MANAGER_TIMEOUT'])
    result = ops_manager_client.admin.command('ismaster')
  except (pymongo.errors.ServerSelectionTimeoutError, pymongo.errors.ConnectionFailure) as e:
    logging.error("Cannot connect to Ops Manager DB, please check settings in config file: %s" %e)
    print('\033[91m' + "Cannot connect to Ops Manager DB, please check settings in config file: %s" %e)
    print('\033[m')
    sys.exit(1)
  om_db = ops_manager_client['mmsdb']
  om_collection = om_db['data.events']
  return om_collection

# connection to the audit database
def audit_db_client(audit_db_data, debug=False):
  try:
    if audit_db_data['AUDIT_DB_SSL'] is True:
      if debug is True:
        logging.debug("Using SSL/TLS to Audit DB")
        print("Using SSL/TLS to Audit DB")
      audit_client = pymongo.MongoClient(audit_db_data['AUDIT_DB_CONNECTION_STRING'], serverSelectionTimeoutMS=audit_db_data['AUDIT_DB_TIMEOUT'], ssl=True, ssl_certfile=audit_db_data['AUDIT_DB_SSL_PEM'], ssl_ca_certs=audit_db_data['AUDIT_DB_SSL_CA'])
    else:
      if debug is True:
        logging.debug("Not using SSL/TLS to Audit DB")
        print("Not using SSL/TLS to Audit DB")
      audit_client = pymongo.MongoClient(audit_db_data['AUDIT_DB_CONNECTION_STRING'], serverSelectionTimeoutMS=audit_db_data['AUDIT_DB_TIMEOUT'])
    result = audit_client.admin.command('ismaster')
  except (pymongo.errors.ServerSelectionTimeoutError, pymongo.errors.ConnectionFailure) as e:
    logging.error("Cannot connect to Audit DB, please check settings in config file: %s" %e)
    print("Cannot connect to Audit DB, please check settings in config file: %s" %e)
    sys.exit(1)
  audit_db = audit_client['logging']
  audit_collection = audit_db['logs']
  return audit_collection

def main():
  # declare our log path
  LOG_FILE = sys.path[0] + '/event_watcher.log'

  # get our config
  config_data = get_config()

  # retrieve and add our resume token to the config data
  # `resume_token` is a global variable so exit handlers can grab it easily
  global resume_token
  config_data['resume_token'] = get_resume_token()
  resume_token = config_data['resume_token']

  # setup logging
  debug = config_data['DEBUG']
  if debug == True:
    logging.basicConfig(filename=LOG_FILE,level=logging.DEBUG)
  else:
    logging.basicConfig(filename=LOG_FILE,level=logging.INFO)

  # log our startup and the various settings
  record_startup(config_data, debug)

  # Connect to the mongodb database
  audit_collection = audit_db_client(config_data, debug)
  ops_manager_collection = om_db_client(config_data, debug)

  if resume_token:
    cursor = ops_manager_collection.watch(resume_after={'_data': resume_token},pipeline=config_data['PIPELINE'])
  else:
    cursor = ops_manager_collection.watch(pipeline=config_data['PIPELINE'])
  try:
    while True:
      document = next(cursor)
      resume_token = document.get("_id")['_data']
      document['tag'] = 'OPS EVENT'
      document['host'] = 'OPS MANAGER'
      document['source'] = 'DEPLOYMENT EVENT'
      document['ts'] = document['fullDocument']['cre']
      # retrieve the array of users so our subsequent querying is easier and faster
      document['users_array'] = []
      if document['fullDocument']['un']:
        document['users_array'].append(document['fullDocument']['un'])
      document['schema_version'] = 0
      if debug:
        logging.debug("RESUME_TOKEN: %s" % resume_token)
        print("RESUME_TOKEN: %s" % resume_token)
        print("DOCUMENT: %s" % document)
      audit_collection.insert_one(document)
  except OperationFailure as e:
    print(e.details)
    logging.error(e.details)


if __name__ == "__main__":
  logger = logging.getLogger(__name__)
  main()