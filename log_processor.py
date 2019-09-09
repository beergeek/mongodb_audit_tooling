try:
  import time, pymongo, configparser, os, sys, json, socket, logging, datetime, kerberos, re
  from pymongo.errors import DuplicateKeyError, OperationFailure
  from bson.json_util import loads
  import sys
except ImportError as e:
  print(e)
  exit(1)

LOG_FILE = sys.path[0] + '/log_processor.log'
CONF_FILE = sys.path[0] + '/log_processor.conf'
ZERO = datetime.timedelta(0)
HOUR = datetime.timedelta(hours=1)

class UTC(datetime.tzinfo):
  """UTC"""

  def utcoffset(self, dt):
    return ZERO

  def tzname(self, dt):
    return "UTC"

  def dst(self, dt):
    return ZERO

# Get config setting from `log_processor.config` file
if os.path.isfile(CONF_FILE) == False:
  logging.basicConfig(filename=LOG_FILE,level=logging.ERROR)
  logging.error('The `log_processor.conf` file must exist in the same directory as the Python script')
  print('\033[93m' + 'The `log_processor.conf` file must exist in the same directory as the Python script, exiting' + '\033[m')
  sys.exit(0)
config = configparser.ConfigParser()
config.read(CONF_FILE)
try:
  debug = config.getboolean('general','debug', fallback=False)
  audit_db_connection_string = config.get('audit_db','connection_string')
  audit_db_ssl = config.getboolean('audit_db','ssl_enabled',fallback=False)
  if audit_db_ssl is True:
    audit_db_ssl_pem = config.get('audit_db','ssl_pem_path')
    audit_db_ssl_ca = config.get('audit_db', 'ssl_ca_cert_path')
  audit_db_timeout = config.getint('audit_db','timeout', fallback=100000)
  elevated_ops_events = config.get('general','elevated_ops_events',fallback='').split(',')
  elevated_config_events = config.get('general','elevated_config_events',fallback='').split(',')
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

def create_tz_dtg(temp_time):
  if sys.version_info[0] < 3:
    utc_time = datetime.datetime.fromtimestamp(float(temp_time), UTC())
  else:
    utc_time = datetime.datetime.fromtimestamp(float(temp_time),datetime.datetime.timezone.utc)
  return utc_time

# Get resume token, is exists
if os.path.isfile('.log_tokens'):
  try:
    token_file = open('.log_tokens','r')
    temp_line = token_file.readline().strip()
    resume_token = create_tz_dtg(temp_line)
  except ValueError as e:
    print('\033[91m' + "Incorrect format for timestamp: %s, reprocessing all data" % temp_line)
    print('\033[m')
    resume_token = create_tz_dtg(0)
  finally:
    token_file.close()
else:
  resume_token = create_tz_dtg(0)

if debug == True:
  logging.basicConfig(filename=LOG_FILE,level=logging.DEBUG)
  logging.info("STARTING PROCESSING: %s" % datetime.datetime.now())
  logging.debug("AUDIT CONNECTION STRING: %s" % re.sub('//.+@', '//<REDACTED>@', audit_db_connection_string))
  logging.debug("AUDIT LOG: %s" % audit_log)
  logging.debug("CONFIG EVENTS: %s" % elevated_config_events)
  logging.debug("OPS EVENTS: %s" % elevated_ops_events)
  logging.debug("APP EVENTS: %s" % elevated_app_events)
  logging.debug("RESUME TOKEN: %s" % resume_token)
  print("AUDIT CONNECTION STRING: %s" % re.sub('//.+@', '//<REDACTED>@', audit_db_connection_string))
  print("AUDIT LOG: %s" % audit_log)
  print("OPS EVENTS: %s" % elevated_ops_events)
  print("APP EVENTS: %s" % elevated_app_events)
  print("RESUME TOKEN: %s" % resume_token)
else:
  logging.basicConfig(filename=LOG_FILE,level=logging.INFO)
  logging.info("STARTING PROCESSING: %s" % datetime.datetime.now())

try:
  if audit_db_ssl is True:
    if debug is True:
      logging.debug("Using SSL/TLS")
      print("Using SSL/TLS")
    client = pymongo.MongoClient(audit_db_connection_string, serverSelectionTimeoutMS=audit_db_timeout, ssl=True, ssl_certfile=audit_db_ssl_pem, ssl_ca_certs=audit_db_ssl_ca)
  else:
    if debug is True:
      logging.debug("Not ussing SSL/TLS")
      print("Not using SSL/TLS")
    client = pymongo.MongoClient(audit_db_connection_string, serverSelectionTimeoutMS=audit_db_timeout)
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
      if k[0] in [ '$', '*'] and k not in ['$data', '$code', '$binary','$decimal128', '$int64', '$min_key','$max_key','$objectid','$regex', '$timestamp']:
        if debug:
          logging.debug("ISSUE: %s" % k)
          print('\033[91m' + ("ISSUE: %s" % k) + '\033[m')
        unclean_json[k[1:]] = unclean_json.pop(k)
  return unclean_json

def clean_list_data(unclean_data):
  if type(unclean_data) is list:
    for value in unclean_data:
      if debug:
        logging.debug("ELEMENT: %s" % value)
        print("ELEMENT: %s" % value)
      if type(value) is dict:
        if debug:
          logging.debug("ANOTHER DICT: %s" % value)
          print("ANOTHER DICT: %s" % value)
        unclean_data[unclean_data.index(value)] = clean_data(value)
  return unclean_data

# set for a new start or restart
restart = True
while os.path.isfile(audit_log) == False:
  time.sleep(10)
f = open(audit_log, "rb")
try:
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
        if debug:
          print("CURRENT TS: %s" % unclean_line['ts'])

        # check if this was our last resume token or restart is not true
        # On restart we do not want to process the same data again
        if (unclean_line['ts'] > resume_token) or restart == False:
          restart = False
          # clean line (if required)
          clean_line = clean_data(unclean_line)

          # Insert tags as required
          if ('command' in clean_line['param'] and clean_line['param']['command'] in elevated_config_events) or clean_line['atype'] in elevated_config_events:
            clean_line['tag'] = 'CONFIG EVENT'
          if 'command' in clean_line['param'] and clean_line['param']['command'] in elevated_ops_events:
            clean_line['tag'] = 'OPS EVENT'
          elif 'command' in clean_line['param'] and clean_line['param']['command'] in elevated_app_events:
            clean_line['tag'] = 'APP EVENT'
          clean_line['host'] = socket.gethostname()
          clean_line['source'] = 'DATABASE AUDIT'
          resume_token = clean_line['ts']
          # set schema version
          clean_line['schema_version'] = 0
          try:
            # insert data
            if debug:
              print(clean_line)
              print("RESUME TOKEN: %s" % resume_token)
            collection.insert_one(clean_line)
          except OperationFailure as e:
            print(e.details)
        else:
          if debug is True:
            print("Datestamp already seen: %s" % unclean_line['ts'])
      except ValueError as e:
        print('\033[91m' + ("Value Error: %s\nDocument: %s" % (e, unclean_line)) + '\033[m')
        continue
finally:
  if resume_token:
    if sys.version_info[0] < 3:
      p = format(time.mktime(resume_token.timetuple()), '.1f')
    else:
      p = datetime.datetime.timestamp(resume_token)
    if debug is True:
      print("OUT TOKEN: %s" % p)
    outfile = open('.log_tokens', 'w')
    outfile.write(p)
    outfile.close()
  logging.info("TERMINATING PROCESSING: %s" % datetime.datetime.now())