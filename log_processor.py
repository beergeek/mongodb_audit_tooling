import time, pymongo, configparser, os, sys, json, socket
from pymongo.errors import DuplicateKeyError, OperationFailure

# Get config setting from `log_processor.config` file
if os.path.isfile('log_processor.conf') == False:
  print('\033[93m' + 'The `log_processor.conf` file must exist in the same directory as the Python script, exiting' + '\033[m')
  sys.exit(0)
config = configparser.ConfigParser()
config.read('log_processor.conf')
try:
  debug = config.getboolean('general','debug', fallback=False)
  audit_db_connection_string = config.get('audit_db','connection_string')
  audit_db_timeout = config.getint('audit_db','timeout', fallback=100000)
  elevated_ops_events = config.get('general','elevated_ops_events',fallback=[])
  elevated_app_events = config.get('general','elevated_app_events',fallback=[])
  audit_log = config.get('general','audit_log',fallback='audit.log')
except configparser.NoOptionError as e:
  print(e)
  print('\033[91m' + "ERROR! The config file must include the `connection_string` option in the `audit_db` section "
    ", such as:\n"
    + '\033[92m'
    "[audit_db]"
    "connection_string=mongodb://username:password@host:port/?replicaSet=replicasetname\n"
    + '\033[m')
  sys.exit(1)
except configparser.NoSectionError as e:
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
  print("AUDIT CONNECTION STRING: %s" % audit_db_connection_string)
  print("AUDIT LOG: %s" % audit_log)

client = pymongo.MongoClient(audit_db_connection_string,serverSelectionTimeoutMS=audit_db_timeout)
try:
  result = client.admin.command('ismaster')
except pymongo.errors.ServerSelectionTimeoutError as e:
  print("Cannot connect to DB, please check settings in config file: %s" %e)
  raise
except pymongo.errors.ConnectionFailure as e:
  print("Cannot connect to DB, please check settings in config file: %s" %e)
  raise
db = client['logging']
collection = db['logs']

def clean_data(unclean_json):
  if type(unclean_json) is dict:
    for k, v in unclean_json.items():
      if type(v) is dict:
        v = clean_data(v)
      if k[0] in [ '$', '*']:
        if debug:
          print("ISSUE: %s" % k)
        unclean_json[k[1:]] = unclean_json.pop(k)
  return unclean_json

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
            print("DATA: %s" % clean_line)
          collection.insert_one(clean_line)
        except OperationFailure as e:
          print(e.details)
  except ValueError as e:
    print(e)
    continue