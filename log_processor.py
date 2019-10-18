try:
  import argparse
  import configparser
  import datetime
  import json
  import kerberos
  import logging
  import os
  import pymongo
  import re
  import signal
  import socket
  import sys
  import sys
  import time
  from pymongo.errors import DuplicateKeyError, OperationFailure, InvalidDocument
  from bson.json_util import loads
except ImportError as e:
  print(e)
  sys.exit(1)

def write_resume_token(signum, frame):
  if resume_token:
    if sys.version_info[0] < 3:
      p = format(time.mktime(resume_token.timetuple()), '.1f')
    else:
      p = datetime.datetime.timestamp(resume_token)
    outfile = open(sys.path[0] + '/.log_tokens', 'w')
    outfile.write(p)
    outfile.close()
    logging.info("RESUME TOKEN: %s %s" % (resume_token, p))
  logging.info("TERMINATING PROCESSING: %s" % datetime.datetime.now())
  sys.exit(0)

# global varible
resume_token = None
signal.signal(signal.SIGINT, write_resume_token)
signal.signal(signal.SIGTERM, write_resume_token)

class UTC(datetime.tzinfo):
  """UTC"""

  def utcoffset(self, dt):
    return datetime.timedelta(0)

  def tzname(self, dt):
    return "UTC"

  def dst(self, dt):
    return datetime.timedelta(hours=1)

def get_cmd_args():
  parser = argparse.ArgumentParser(description='Script to process MongoDB audit log')
  parser.add_argument('--config','-c', dest='config_file', default=sys.path[0] + '/log_processor.conf', required=False, help="Alternative location for the config file")
  parser.add_argument('--log','-l', dest='log_file', default=sys.path[0] + '/log_processor.log', required=False, help="Alternative location for the log file")
  return parser.parse_args()

def get_config(args):
  CONF_FILE = args.config_file
  LOG_FILE = args.log_file
  # Get config setting from `log_processor.config` file
  if os.path.isfile(CONF_FILE) == False:
    logging.basicConfig(filename=LOG_FILE,level=logging.ERROR)
    logging.error('The config file must exist in the same directory as the Python script')
    print('\033[93m' + 'The config file must exist in the same directory as the Python script, exiting' + '\033[m')
    sys.exit(1)

  config = configparser.ConfigParser()
  config.read(CONF_FILE)
  config_options = {}
  try:
    config_options['debug'] = config.getboolean('general','debug', fallback=False)
    config_options['audit_db_connection_string'] = config.get('audit_db','connection_string')
    config_options['audit_db_ssl'] = config.getboolean('audit_db','ssl_enabled',fallback=False)
    if config_options['audit_db_ssl'] is True:
      config_options['audit_db_ssl_pem'] = config.get('audit_db','ssl_pem_path', fallback=None)
      config_options['audit_db_ssl_ca'] = config.get('audit_db', 'ssl_ca_cert_path')
    config_options['audit_db_timeout'] = config.getint('audit_db','timeout', fallback=10)
    config_options['elevated_ops_events'] = config.get('general','elevated_ops_events',fallback='').split(',')
    config_options['elevated_config_events'] = config.get('general','elevated_config_events',fallback='').split(',')
    config_options['elevated_app_events'] = config.get('general','elevated_app_events',fallback='').split(',')
    config_options['audit_log'] = config.get('general','audit_log',fallback=sys.path[0] + "/audit.log")
  except (configparser.NoOptionError,configparser.NoSectionError) as e:
    logging.basicConfig(filename=LOG_FILE,level=logging.ERROR)
    logging.error("The config file is missing data: %s" % e)
    print("""\033[91mERROR! The config file is missing an option: %s.
It should be in the following format:
\033[92m
[audit_db]
connection_string=mongodb://auditor%%40MONGODB.LOCAL@audit.mongodb.local:27017/?replicaSet=repl0&authSource=$external&authMechanism=GSSAPI
timeout=1000
ssl_enabled=True
ssl_pem_path=/data/pki/mongod3.mongodb.local.pem
ssl_ca_cert_path=/data/pki/ca.ce\n
[general]
debug=true
audit_log=/data/logs/audit_log
elevated_config_events=shutdown,setParameter,setFeatureCompatibilityVersion,addShard,addShardToZone,balancerStart,balancerStop,enableSharding,flushRouterConfig,moveChunk,mergeChunks,removeShard,removeShardFromZone,setShardVersion,shardCollection,splitChunk,unsetSharding,updateZoneKeyRange,replSetReconfig,replSetInitiate
elevated_ops_events=createUser,deleteUser
elevated_app_events=dropCollection,dropDatabase
\033[m""" % e)
    sys.exit(1)
  return config_options

def create_tz_dtg(temp_time):
  if sys.version_info[0] < 3:
    utc_time = datetime.datetime.fromtimestamp(float(temp_time), UTC())
  else:
    utc_time = datetime.datetime.fromtimestamp(float(temp_time),datetime.timezone.utc)
  return utc_time

def get_resume_token():
  # Get resume token, is exists
  if os.path.isfile(sys.path[0] + '/.log_tokens'):
    try:
      token_file = open(sys.path[0] + '/.log_tokens','r')
      temp_line = token_file.readline().strip()
      token = create_tz_dtg(temp_line)
    except ValueError:
      print('\033[91m' + "Incorrect format for timestamp: %s, reprocessing all data" % temp_line)
      print('\033[m')
      token = create_tz_dtg(0)
    finally:
      token_file.close()
  else:
    token = create_tz_dtg(0)
  return token

# Record our startup and config
def record_startup(config_array, debug=False):
  if debug == True:
    logging.info("STARTING PROCESSING: %s" % datetime.datetime.now())
    logging.debug("AUDIT CONNECTION STRING: %s" % re.sub('//.+@', '//<REDACTED>@', config_array['audit_db_connection_string']))
    logging.debug("AUDIT LOG: %s" % config_array['audit_log'])
    logging.debug("CONFIG EVENTS: %s" % config_array['elevated_config_events'])
    logging.debug("OPS EVENTS: %s" % config_array['elevated_ops_events'])
    logging.debug("APP EVENTS: %s" % config_array['elevated_app_events'])
    logging.debug("RESUME TOKEN: %s" % config_array['resume_token'])
    print("AUDIT CONNECTION STRING: %s" % re.sub('//.+@', '//<REDACTED>@', config_array['audit_db_connection_string']))
    print("AUDIT LOG: %s" % config_array['audit_log'])
    print("OPS EVENTS: %s" % config_array['elevated_ops_events'])
    print("APP EVENTS: %s" % config_array['elevated_app_events'])
    print("RESUME TOKEN: %s" % config_array['resume_token'])
  else:
    logging.info("STARTING PROCESSING: %s" % datetime.datetime.now())

# Connect to MongoDB
def audit_db_client(audit_db_data, debug=False):
  try:
    if audit_db_data['audit_db_ssl'] is True:
      if debug is True:
        logging.debug("Using SSL/TLS")
        print("Using SSL/TLS")
      if audit_db_data['audit_db_ssl_pem'] is not None:
        client = pymongo.MongoClient(audit_db_data['audit_db_connection_string'], serverSelectionTimeoutMS=audit_db_data['audit_db_timeout'], ssl=True, ssl_certfile=audit_db_data['audit_db_ssl_pem'], ssl_ca_certs=audit_db_data['audit_db_ssl_ca'])
      else:
        client = pymongo.MongoClient(audit_db_data['audit_db_connection_string'], serverSelectionTimeoutMS=audit_db_data['audit_db_timeout'], ssl=True, ssl_ca_certs=audit_db_data['audit_db_ssl_ca'])
    else:
      if debug is True:
        logging.debug("Not ussing SSL/TLS")
        print("Not using SSL/TLS")
      client = pymongo.MongoClient(audit_db_data['audit_db_connection_string'], serverSelectionTimeoutMS=audit_db_data['audit_db_timeout'])
    client.admin.command('ismaster')
  except (pymongo.errors.ServerSelectionTimeoutError, pymongo.errors.ConnectionFailure) as e:
    logging.error("Cannot connect to Audit DB, please check settings in config file: %s" %e)
    print("Cannot connect to DB, please check settings in config file: %s" %e)
    raise
  db = client['logging']
  collection = db['logs']
  return collection

# check if our keys are valid for BSON
def clean_data(unclean_json, debug=False):
  if type(unclean_json) is dict:
    for k, v in unclean_json.items():
      if debug:
        logging.debug("KEY: %s" % k)
        print("KEY: %s" % k)
      if type(v) is dict:
        v = clean_data(v, debug)
      if type(v) is list:
        v = clean_list_data(v, debug)
      if k[0] in [ '$', '*'] and k not in ['$data', '$code', '$binary','$decimal128', '$int64', '$min_key','$max_key','$objectid','$regex', '$timestamp']:
        if debug:
          logging.debug("ISSUE: %s" % k)
          print('\03393m' + ("ISSUE: %s" % k) + '\033[m')
        unclean_json[k[1:]] = unclean_json.pop(k)
        k = k[1:]
      unclean_json[k.replace('.','_')] = unclean_json.pop(k)
  return unclean_json

# Diving further down the rabbit hole
def clean_list_data(unclean_data, debug=False):
  if type(unclean_data) is list:
    for value in unclean_data:
      if debug:
        logging.debug("ELEMENT: %s" % value)
        print("ELEMENT: %s" % value)
      if type(value) is dict:
        if debug:
          logging.debug("ANOTHER DICT: %s" % value)
          print("ANOTHER DICT: %s" % value)
        unclean_data[unclean_data.index(value)] = clean_data(value, debug)
  return unclean_data

def main():
  # get our config
  args = get_cmd_args()
  config_data = get_config(args)

  # retrieve and add our resume token to the config data
  # `resume_token` is a global variable so exit handlers can grab it easily
  global resume_token
  config_data['resume_token'] = get_resume_token()
  resume_token = config_data['resume_token']

  # setup logging
  debug = config_data['debug']
  if debug == True:
    logging.basicConfig(filename=args.log_file,level=logging.DEBUG)
  else:
    logging.basicConfig(filename=args.log_file,level=logging.INFO)

  # log our startup and the various settings
  record_startup(config_data, debug)

  # Connect to the mongodb database
  audit_db = audit_db_client(config_data, debug)

  # set for a new start or restart
  restart = True

  # if no audit file we will just wait to see if one turns up :-)
  while os.path.isfile(config_data['audit_log']) == False:
    time.sleep(10)
  f = open(config_data['audit_log'], "rb")

  # start reading our audit log
  while 1:
    where = f.tell()
    line = f.readline()
    if not line:
        time.sleep(1)
        f.seek(where)
    else:
      try:
        # retrieve line
        unclean_line = loads(line)
        if config_data['debug']:
          print("CURRENT TS: %s" % unclean_line['ts'])
        
        # check if this was our last resume token or restart is not true
        # On restart we do not want to process the same data again
        if (unclean_line['ts'] > resume_token) or restart == False:
          # we know we are now not in the restart for first start state, so declare that
          restart = False
          # clean line (if required) to remove some un-BSON key names
          clean_line = clean_data(unclean_line, debug)
          # retrieve the array of users so our subsequent querying is easier and faster
          clean_line['users_array'] = []
          for user_data in clean_line['users']:
            clean_line['users_array'].append(user_data['user'])
          # Insert tags as required
          if ('command' in clean_line['param'] and clean_line['param']['command'] in config_data['elevated_config_events']) or clean_line['atype'] in config_data['elevated_config_events']:
            clean_line['tag'] = 'CONFIG EVENT'
          if 'command' in clean_line['param'] and clean_line['param']['command'] in config_data['elevated_ops_events']:
            clean_line['tag'] = 'OPS EVENT'
          elif 'command' in clean_line['param'] and clean_line['param']['command'] in config_data['elevated_app_events']:
            clean_line['tag'] = 'APP EVENT'
          clean_line['host'] = socket.gethostname()
          clean_line['source'] = 'DATABASE AUDIT'
          # set schema version
          clean_line['schema_version'] = 0
          # Get our newest resume token
          resume_token = clean_line['ts']
          if debug:
            print(clean_line)
            print("RESUME TOKEN: %s" % resume_token)
          # insert data
          audit_db.insert_one(clean_line)
        else:
          if debug is True:
            print("Datestamp already seen: %s" % unclean_line['ts'])
            logging.debug("Datestamp already seen: %s" % unclean_line['ts'])
      except OperationFailure as e:
        print('\033[91m' + ("Operational Error: %s\nDocument: %s" % (e, unclean_line)) + '\033[m')
        logging.error("Operational Error: %s\nDocument: %s" % (e, unclean_line))
      except ValueError as e:
        print('\033[91m' + ("Value Error: %s\nDocument: %s" % (e, unclean_line)) + '\033[m')
        logging.error("Value Error: %s\nDocument: %s" % (e, unclean_line))
        continue
      except InvalidDocument as e:
        print('\033[91m' + ("Document Error: %s\nDocument: %s" % (e, unclean_line)) + '\033[m')
        logging.error("Document Error: %s\nDocument: %s" % (e, unclean_line))
        continue

if __name__ == "__main__":
  logger = logging.getLogger(__name__)
  main()