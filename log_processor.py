import time, pymongo, configparser, os, sys, json, socket, logging, datetime, kerberos
from pymongo.errors import DuplicateKeyError, OperationFailure

LOG_FILE = 'log_progressor.log'

# Get config setting from `log_processor.config` file
if os.path.isfile('log_processor.conf') == False:
  logging.basicConfig(filename=LOG_FILE,level=logging.ERROR)
  logging.error('The `log_processor.conf` file must exist in the same directory as the Python script')
  print('\033[93m' + 'The `log_processor.conf` file must exist in the same directory as the Python script, exiting' + '\033[m')
  sys.exit(0)
config = configparser.ConfigParser()
config.read('log_processor.conf')
try:
  debug = config.getboolean('general','debug', fallback=False)
  audit_db_connection_string = config.get('audit_db','connection_string')
  audit_db_timeout = config.getint('audit_db','timeout', fallback=100000)
  elevated_ops_events = config.get('general','elevated_ops_events',fallback='').split(',')
  elevated_app_events = config.get('general','elevated_app_events',fallback='').split(',')
  audit_log = config.get('general','audit_log',fallback='audit.log')
except configparser.NoOptionError as e:
  logging.basicConfig(filename=LOG_FILE,level=logging.ERROR)
  logging.error('The config file must include the `connection_string` option in the `audit_db` section')
  print('\033[91m' + "ERROR! The config file must include the `connection_string` option in the `audit_db` section "
    ", such as:\n"
    + '\033[92m'
    "[audit_db]"
    "connection_string=mongodb://username:password@host:port/?replicaSet=replicasetname\n"
    + '\033[m')
  sys.exit(1)
except configparser.NoSectionError as e:
  logging.basicConfig(filename=LOG_FILE,level=logging.ERROR)
  logging.error('The config file must include sections `audit_db` and `general`')
  print('\033[91m' + "ERROR! The config file must include sections `audit_db` and `general`, such as:\n"
    + '\033[92m'
    "[audit_db]\n"
    "connection_string=mongodb://username:password@host:port/?replicaSet=replicasetname\n"
    "timeout=1000\n\n"
    "[general]\n"
    "debug=False"
    + '\033[m'
    )
  sys.exit(1)
config = configparser.ConfigParser()
config.read('mongodb.config')

if debug == True:
  logging.basicConfig(filename=LOG_FILE,level=logging.DEBUG)
  logging.info("STARTING PROCESSING: %s" % datetime.datetime.now())
  logging.debug("AUDIT CONNECTION STRING: %s" % audit_db_connection_string)
  logging.debug("AUDIT LOG: %s" % audit_log)
  logging.debug("OPS EVENTS: %s" % elevated_ops_events)
  logging.debug("APP EVENTS: %s" % elevated_app_events)
  print("AUDIT CONNECTION STRING: %s" % audit_db_connection_string)
  print("AUDIT LOG: %s" % audit_log)
  print("OPS EVENTS: %s" % elevated_ops_events)
  print("APP EVENTS: %s" % elevated_app_events)
else:
  logging.basicConfig(filename=LOG_FILE,level=logging.INFO)
  logging.info("STARTING PROCESSING: %s" % datetime.datetime.now())

client = pymongo.MongoClient(audit_db_connection_string,serverSelectionTimeoutMS=audit_db_timeout)
try:
  result = client.admin.command('ismaster')
except (pymongo.errors.ServerSelectionTimeoutError, pymongo.errors.ConnectionFailure) as e:
  logging.error("Cannot connect to Audit DB, please check settings in config file: %s" %e)
  print("Cannot connect to DB, please check settings in config file: %s" %e)
  raise
db = client['logging']
collection = db['logs']

def clean_data(unclean_json):
  if type(unclean_json) is dict:
    for k, v in unclean_json.items():
      if debug:
        logging.debug("KEY: %s" % k)
        print("KEY: %s" % k)
      if type(v) is dict:
        v = clean_data(v)
      if type(v) is list:
        v = clean_list_data(v)
      if k[0] in [ '$', '*']:
        if debug:
          logging.debug("ISSUE: %s" % k)
          print('\033[91m' + ("ISSUE: %s" % k) + '\033[m')
        unclean_json[k[1:]] = unclean_json.pop(k)
  return unclean_json

def clean_list_data(unclean_data):
  if type(unclean_data) is list:
    for index, value in unclean_data:
      if debug:
        logging.debug("ELEMENT: %s" % value)
        print("ELEMENT: %s" % value)
      if type(value) is dict:
        print("ANOTHER DICT: %s" % value)
        unclean_data[index] = clean_data(value)
  return unclean_data

while os.path.isfile(audit_log) == False:
  time.sleep(10)
f = open(audit_log, "r")
while 1:
  try:
    where = f.tell()
    line = f.readline()
    if not line:
        time.sleep(1)
        f.seek(where)
    else:
        # Insert tags as required
        dirty_line = json.loads(line)
        clean_line = clean_data(dirty_line)
        if clean_line['atype'] in elevated_ops_events:
          clean_line['tag'] = 'OPS EVENT'
        elif clean_line['atype'] in elevated_app_events:
          clean_line['tag'] = 'APP EVENT'
        clean_line['host'] = socket.gethostname()
        clean_line['source'] = 'DATABASE AUDIT'
        try:
          # insert data
          if debug:
            print(clean_line)
          collection.insert_one(clean_line)
        except OperationFailure as e:
          print(e.details)
  except ValueError as e:
    print(e)
    continue
  finally:
    logging.info("TERMINATING PROCESSING: %s" % datetime.datetime.now())
    