try:
  from flask import Flask, render_template, request
  import configparser
  import json
  import time
  import copy
  import logging
  import pymongo
  import os
  import sys
  import re
  import ast
  import datetime
  from pprint import pprint
  from pymongo import ReturnDocument
  from pymongo.errors import OperationFailure
  from bson.json_util import dumps, loads
  from bson.objectid import ObjectId
except ImportError as e:
  print(e)
  exit(1)

LOG_FILE = sys.path[0] + '/reporter.log'
CONF_FILE = sys.path[0] + '/reporter.conf'

# Get config setting from `event_watcher.config` file
if os.path.isfile(CONF_FILE) == False:
  logging.basicConfig(filename=LOG_FILE,level=logging.ERROR)
  logging.error('The `reporter.conf` file must exist in the same directory as the Python script')
  print('\033[93m' + 'The `reporter.conf` file must exist in the same directory as the Python script, exiting' + '\033[m')
  sys.exit(0)
config = configparser.ConfigParser()
config.read(CONF_FILE)
try:
  DEBUG = config.getboolean('general','debug', fallback=False)
  AUDIT_DB_CONNECTION_STRING = config.get('audit_db','connection_string')
  AUDIT_DB_SSL = config.getboolean('audit_db','ssl_enabled',fallback=False)
  if AUDIT_DB_SSL is True:
    AUDIT_DB_SSL_PEM = config.get('audit_db','ssl_pem_path')
    AUDIT_DB_SSL_CA = config.get('audit_db', 'ssl_ca_cert_path')
  OPS_MANAGER_TIMEOUT = config.getint('ops_manager','timeout', fallback=10)
  AUDIT_DB_TIMEOUT = config.getint('audit_db','timeout', fallback=10)
except (configparser.NoOptionError,configparser.NoSectionError) as e:
  logging.basicConfig(filename=LOG_FILE,level=logging.ERROR)
  logging.error("The config file is missing data: %s" % e)
  print("""\033[91mERROR! The config file is missing data: %s
\033[92m
[audit_db]
connection_string=mongodb://web_user%%40MONGODB.LOCAL@mongod6.mongodb.local:27017/?replicaSet=repl0&authSource=$external&authMechanism=GSSAPI
timeout=10
ssl_enabled=True
ssl_ca_cert_path=/data/pki/ca.cert
ssl_pem_path=/data/pki/mongod6.mongodb.local.pem

[general]
debug=false
\033[m""" % e)
  sys.exit(1)
app = Flask(__name__)

if DEBUG == True:
  logging.basicConfig(filename=LOG_FILE,level=logging.DEBUG)
  logging.info("STARTING PROCESSING: %s" % datetime.datetime.now())
  logging.debug("AUDIT CONNECTION STRING: %s" % re.sub('//.+@', '//<REDACTED>@', AUDIT_DB_CONNECTION_STRING))
  print("AUDIT CONNECTION STRING: %s" % re.sub('//.+@', '//<REDACTED>@', AUDIT_DB_CONNECTION_STRING))
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
      logging.debug("Not using SSL/TLS to Audit DB")
      print("Not using SSL/TLS to Audit DB")
    audit_client = pymongo.MongoClient(AUDIT_DB_CONNECTION_STRING, serverSelectionTimeoutMS=AUDIT_DB_TIMEOUT)
  result = audit_client.admin.command('ismaster')
except (pymongo.errors.ServerSelectionTimeoutError, pymongo.errors.ConnectionFailure) as e:
  logging.error("Cannot connect to Audit DB, please check settings in config file: %s" %e)
  print("Cannot connect to Audit DB, please check settings in config file: %s" %e)
  sys.exit(1)
audit_db = audit_client['logging']
audit_collection = audit_db['logs']
config_collection = audit_db['configs']
config_archive_collection = audit_db['configs_archive']
standards_collection = audit_db['standards']
standards_archive_collection = audit_db['standards_archive']
waivers_collection = audit_db['waivers']
waivers_archive_collection = audit_db['waivers_archive']

# main route 
@app.route("/")
def index():
  try: 
    # list of users
    # Index: {"users_array": 1} on `loggig.configs`
    output0 = list(audit_collection.distinct("users_array"))
    output0 = [ elem for elem in output0 if elem != None]
    output0.append('ALL USERS')
    # Multikey indexes can't be used for distinct
    output1 = list(audit_collection.distinct("fullDocument.clusterConfig.cluster.processes.hostname"))
    output1.append('OPS MANAGER')
    # Index: {"deployment": 1} on `logging.configs`
    output2 = list(config_collection.distinct("deployment"))
    return render_template('index.html', users=output0, hosts=output1, deployments=output2)
  except OperationFailure as e:
    print(e.details)
    logging.error(e.details)

@app.route("/user_report", methods=['GET'])
def get_user():
  try:
    if request.args['user'] == 'ALL USERS':
      match = {
        "$match": {
          "$and": [
            {"ts": {"$gt":  datetime.datetime.strptime(request.args['dtg_fixed_low'], "%a, %d %b %Y %H:%M:%S %Z")}},
            {"ts": {"$lte": datetime.datetime.strptime(request.args['dtg_fixed_high'], "%a, %d %b %Y %H:%M:%S %Z")}}
          ]
        }
      }
    else:
      match = {
        "$match": {
          "$and": [
            {"ts": {"$gt":  datetime.datetime.strptime(request.args['dtg_fixed_low'], "%a, %d %b %Y %H:%M:%S %Z")}},
            {"ts": {"$lte": datetime.datetime.strptime(request.args['dtg_fixed_high'], "%a, %d %b %Y %H:%M:%S %Z")}}
          ],
          "$or": [
            {"users.user": request.args['user']},
            {"fullDocument.un": request.args['user']}
          ]
        }
      }
    user_pipeline = [
      match, 
      {
        "$project": {
          "_id": 1,
          "ts": 1,
          "source": 1,
          "Changes": {"$ifNull": [{"$arrayElemAt": ["$fullDocument.deploymentDiff.diffs.status",0]}, "$param.command"]},
          "Hosts": {"$ifNull": ["$fullDocument.clusterConfig.cluster.processes.hostname","$host"]},
          "Type": {"$ifNull": ["$fullDocument._t", "$atype"]},
          "Other": "$fullDocument.et",
          "user": {"$ifNull": ["$users.user","$fullDocument.un"]}
        }
      },
      {
        "$sort": {
          "ts": -1
        }
      },
      {
        "$limit": 100
      }
    ]

    # Indexes { users.user: 1, ts: 1 }, { fullDocument.un: 1, ts: 1 } on `logging.logs`
    event_output = list(audit_collection.aggregate(user_pipeline,batchSize=100))
    events = []
    for event in event_output:
      events.append(event)
      if 'Changes' in event:
        event['Changes'] = dumps(event['Changes'], indent=2)
      elif 'Other' in event:
        event['Changes'] = dumps(event['Other'], indent=2)
      if 'Hosts' in event:
        event['Hosts'] = dumps(event['Hosts'], indent=2)
      if 'user' in event:
        event['user'] = dumps(event['user'], indent=2)
    return render_template('user_events.html', events=events, low_date=request.args['dtg_fixed_low'], high_date=request.args['dtg_fixed_high'], user=request.args['user'])
  except OperationFailure as e:
    print(e.details)
    logging.error(e.details)


@app.route("/user_event_details/<oid>", methods=['GET'])
def get_user_event_details(oid):
  try:
    if ObjectId.is_valid(oid):
      host_data = audit_collection.find_one({"_id": ObjectId(oid)})
    else:
      host_data = audit_collection.find_one({"_id": ast.literal_eval(oid)})
    formatted = dumps(host_data, indent=2)
    return render_template('user_event_details_data.html', data=formatted, dtg=host_data['ts'])
  except OperationFailure as e:
    print(e.details)

@app.route("/host_report", methods=['GET'])
def get_host():
  try:
    host_search = re.compile("^%s" % request.args['host'])
    if request.args['host'] == 'OPS MANAGER':
      host_pipeline = [
        {
          "$match": {
            "$and": [
              {"ts": {"$gt":  datetime.datetime.strptime(request.args['dtg_fixed_low_host'], "%a, %d %b %Y %H:%M:%S %Z")}},
              {"ts": {"$lte": datetime.datetime.strptime(request.args['dtg_fixed_high_host'], "%a, %d %b %Y %H:%M:%S %Z")}}
            ],
            "source": "OPS MANAGER CONFIG",
            "tag": "OPS EVENT"
          }
        }, 
        {
          "$project": {
            "ts": 1,
            "source": 1,
            "User": {
              "$ifNull": [{ "$arrayElemAt": [ "$users.user", 0 ] }, "$fullDocument.un"]
            },
            "Events": "$fullDocument",
            "Hosts": "$host",
            "Type": "$operationType"
          }
        },
        {
          "$sort": {
            "ts": -1
          }
        },
        {
          "$limit": 100
        }
      ]
    else:
      host_pipeline = [
        {
          "$match": {
            "$and": [
              {"ts": {"$gt":  datetime.datetime.strptime(request.args['dtg_fixed_low_host'], "%a, %d %b %Y %H:%M:%S %Z")}},
              {"ts": {"$lte": datetime.datetime.strptime(request.args['dtg_fixed_high_host'], "%a, %d %b %Y %H:%M:%S %Z")}}
            ],
            "$or": [
              {
                "source": 'DEPLOYMENT EVENT',
                "$or": [
                  {
                    "fullDocument.deploymentDiff.diffs.processes.id": host_search,
                    "fullDocument.deploymentDiff.diffs.params": {
                      "$eq": []
                    }
                  },
                  {
                    "fullDocument.clusterConfig.cluster.processes.hostname": host_search,
                    "fullDocument.deploymentDiff.diffs.params": {
                      "$ne": []
                    }
                  }
                ]
              },
              {
                "source": "DATABASE AUDIT",
                "tag": "CONFIG EVENT"
              }
            ]
          }
        }, 
        {
          "$project": {
            "ts": 1,
            "source": 1,
            "User": {
              "$ifNull": [{ "$arrayElemAt": [ "$users.user", 0 ] }, "$fullDocument.un"]
            },
            "Events": {
              "$ifNull": ["$param.command",{"$arrayElemAt": ["$fullDocument.deploymentDiff.diffs.status",0]}]
            },
            "Hosts": {
              "$ifNull": ["$host","$fullDocument.clusterConfig.cluster.processes.hostname"]
            },
            "Type": {
              "$ifNull": ["$atype","Ops Manager-originated"]
            }
          }
        },
        {
          "$sort": {
            "ts": -1
          }
        },
        {
          "$limit": 100
        }
      ]

    # Indexes { fullDocument.deploymentDiff.diffs.processes.id: 1, source: 1, ts: 1 }, { fullDocument.clusterConfig.cluster.processes.hostname: 1, source: 1, ts: 1 }, { source: 1, tag: 1, ts: 1 } on `logging.logs`
    event_output = list(audit_collection.aggregate(host_pipeline,batchSize=100))
    events = []
    for event in event_output:
      if not ObjectId.is_valid(event['_id']):
        event['_id'] = event['_id']
      if 'Events' in event:
        event['Events'] = dumps(event['Events'], indent=2)
      else:
        event['Event'] = 'None'
      events.append(event)
    return render_template('host_events.html', events=events, low_date=request.args['dtg_fixed_low_host'], high_date=request.args['dtg_fixed_high_host'], host=request.args['host'])
  except OperationFailure as e:
    print(e.details)

@app.route("/host_event_details/<oid>", methods=['GET'])
def get_host_event_details(oid):
  try:
    if ObjectId.is_valid(oid):
      host_data = audit_collection.find_one({"_id": ObjectId(oid)})
    else:
      host_data = audit_collection.find_one({"_id": ast.literal_eval(oid)})
    formatted = dumps(host_data, indent=2)
    if 'fullDocument' in host_data and 'deploymentDiff' in host_data['fullDocument']:
      formatted_diff = dumps(host_data['fullDocument']['deploymentDiff']['diffs'], indent=2)
    elif 'fullDocument' in host_data and '_id' in host_data['fullDocument']:
      formatted_diff = dumps(host_data['fullDocument'], indent=2)
    else:
      formatted_diff = 'No data'
    return render_template('host_event_details_data.html', data=formatted, diff=formatted_diff, dtg=host_data['ts'])
  except OperationFailure as e:
    print(e.details)

@app.route("/deployment_report", methods=["GET"])
def get_deployment():
  try:
    if 'latest_iscc' in request.args:
      deployment_pipeline = [
        {
          "$match": {
            "deployment": request.args["deployment"]
          }
        },
        {
          "$project": {
            "hosts": "$processes.hostname",
            "ts": 1,
            "compliance": 1,
            "uncompliance_count": 1,
            "start_datetime": 1
          }
        },
        {
          "$sort": {
            "ts": -1
          }
        },
        {
          "$limit": 100
        }
      ]
      event_output = list(config_collection.aggregate(deployment_pipeline))
      title = 'Latest report'
      counts = True
      search_type = 'latest'
    else:
      deployment_pipeline = [
        {
          "$match": {
            "deployment": request.args["deployment"],
            "$and": [
              {"ts": {"$gt":  datetime.datetime.strptime(request.args['dtg_fixed_low_deployment'], "%a, %d %b %Y %H:%M:%S %Z")}},
              {"ts": {"$lte": datetime.datetime.strptime(request.args['dtg_fixed_high_deployment'], "%a, %d %b %Y %H:%M:%S %Z")}}
            ],
          }
        },
        {
          "$project": {
            "hosts": "$processes.hostname",
            "ts": 1,
            "compliance": 1,
            "uncompliance_count": 1,
            "start_datetime": 1
          }
        },
        {
          "$sort": {
            "ts": -1
          }
        },
        {
          "$limit": 100
        }     
      ]
      # Index { deployment: 1, ts: 1 } on `logging.configs_archive`
      event_output = list(config_archive_collection.aggregate(deployment_pipeline,batchSize=100))
      title = 'Between ' + request.args['dtg_fixed_low_deployment'] + ' and ' + request.args['dtg_fixed_high_deployment']
      counts = False
      search_type = 'range'

    events = []
    for event in event_output:
      for host in event['compliance']:
        if host['host'] == 'Supplementry':
          host = dumps(host)
      temp_config = {}
      temp_config['out_of_spec'] = []
      temp_config['out_of_spec'] = event['compliance']
      temp_config['hosts'] = dumps(event['hosts'], indent=2)
      temp_config['ts'] = event['ts']
      temp_config['_id'] = event['_id']
      if 'uncompliance_count' in event:
        temp_config['uncompliance_count'] = event['uncompliance_count']
      else:
        temp_config['uncompliance_count'] = 0
      if 'start_datetime' in event:
        temp_config['start_datetime'] = event['start_datetime']
      else:
        temp_config['start_datetime'] = ''
      events.append(temp_config)
      if DEBUG:
        print(event)
    if DEBUG:
      print(events)
    return render_template('deployment_events.html', counts=counts, title=title, events=events, deployment=request.args['deployment'], type=search_type)
  except OperationFailure as e:
    print(e.details)


@app.route("/deployment_event_details", methods=['GET'])
def get_deployment_event_details():
  try:
    if request.args['search_type'] == 'latest':
      coll = config_collection
    else:
      coll = config_archive_collection
    if ObjectId.is_valid(request.args['oid']):
      deployment_data = coll.find_one({"_id": ObjectId(request.args['oid'])},{"compliance": 0})
    else:
      deployment_data = coll.find_one({"_id": ast.literal_eval(request.args['oid'])},{"compliance": 0})
    formatted = dumps(deployment_data, indent=2)
    return render_template('deployment_event_details_data.html', data=formatted, dtg=deployment_data['ts'], oid=deployment_data['deployment'])
  except OperationFailure as e:
    print(e.details)

@app.route("/admin", methods=['GET'])
def admin_tasks():
  try:
    # Index {'valid_to': 1} on `logging.standards`
    standards = standards_collection.find_one({"valid_to": {"$exists": False}})
    deployments = list(config_collection.distinct("deployment"))
    if type(standards) is not dict:
      standard_id = ''
      standards = {}
    else:
      standard_id = standards['_id']
    if 'standard' not in standards:
      standards_data = ''
    else:
      standards_data = dumps(standards['standard'], indent=2)
    if 'supplementry_pipeline' not in standards:
      supp_data = ''
    else:
      supp_data = dumps(loads(standards['supplementry_pipeline']), indent=2)
    return render_template('admin_tasks.html', standards=standards_data, supplementry_pipeline=supp_data, deployments=deployments, standard_id=standard_id)
  except OperationFailure as e:
    print(e.details)

@app.route("/update_standard", methods=['POST'])
def update_standard():
  try:
    oid = request.form['oid']
    standard_data = {}
    try:
      standard_data['standard'] = loads(request.form['standard'])
    except ValueError as e:
      return render_template('badness.html', message="The standard is not correct: %s" % e)

    if request.form['supplementry_pipeline']:
      try:
        # Let's see if we can even load the string as JSON and if certain keys exist.
        supplementry_pipeline = loads('{"pipelines": %s}' % request.form['supplementry_pipeline'])
      except ValueError as e:
        return render_template('badness.html', message="The supplementry pipeline is not correct: %s" % e)
      for query in supplementry_pipeline['pipelines']:
        if 'name' not in query or 'collection' not in query or 'pipeline' not in query:
          return render_template('badness.html', message='The supplementry pipeline requires at least a `name`, `collection` and a `pipeline` key/value pair, with a possible `database` key/value pair.')
    if request.form['supplementry_pipeline'] != '':
      standard_data['supplementry_pipeline'] = re.sub(r'\s|  ','', request.form['supplementry_pipeline'])
    if '_id' in standard_data['standard']:
      standard_data['standard'].pop('_id')
    standard_data['valid_from'] = datetime.datetime.now()
    standard_data['schema_version'] = 0
    if not ObjectId.is_valid(oid):
      oid = ObjectId()
    response_update = standards_collection.update_one({"_id": ObjectId(oid)}, {"$set": standard_data}, upsert=True)
    standard_data['valid_to'] = datetime.datetime.now()
    standards_archive_collection.insert_one(standard_data)
    if response_update.modified_count == 1 or response_update.upserted_id:
      new_standard = standards_collection.find_one({"_id": ObjectId(oid)})
      outcome = 'Success!'
    else:
      new_standard = standards_collection.find_one({"valid_to": {"$exists": False}})
      outcome = "We have an issue!"
    if 'supplementry_pipeline' in new_standard and new_standard['supplementry_pipeline'] != '':
      new_standard['supplementry_pipeline'] = dumps(loads(new_standard['supplementry_pipeline']), indent=2)
    else:
      new_standard['supplementry_pipeline'] = ''
    return render_template('new_standard.html', outcome=outcome, new_standard=dumps(new_standard, indent=2))
  except OperationFailure as e:
    print(e.details)

@app.route("/deployment_waivers", methods=['GET'])
def deployment_waiver():
  try:
    # Index {'deployment': 1, 'valid_from': 1, 'valid_to': 1} on `logging.waivers`
    waiver_details = waivers_collection.find_one({"deployment": request.args['deployment'], "valid_from": {"$lte": datetime.datetime.now()}, "valid_to": {"$gt": datetime.datetime.now()}})
    details = {}
    try:
      if 'GSSAPI' in waiver_details['project']['auth']['deploymentAuthMechanisms']:
        details['gssapi_checked'] = 'checked'
    except (KeyError, TypeError):
      pass
    try:
      if 'MONGODB-CR' in waiver_details['project']['auth']['deploymentAuthMechanisms']:
        details['scram_sha_1_checked'] = 'checked'
    except (KeyError, TypeError):
      pass
    try:
      if 'SCRAM-SHA-256' in waiver_details['project']['auth']['deploymentAuthMechanisms']:
        details['scram_sha_256_checked'] = 'checked'
    except (KeyError, TypeError):
      pass
    try:
      if 'PLAIN' in waiver_details['project']['auth']['deploymentAuthMechanisms']:
        details['ldap_checked'] = 'checked'
    except (KeyError, TypeError):
      pass
    try:
      details['start'] = datetime.datetime.strftime(waiver_details['valid_from'], "%a, %d %b %Y %H:%M:%S %Z") + " GMT"
    except (KeyError, TypeError):
      details['start'] = datetime.datetime.now()
    try:
      details['end'] = datetime.datetime.strftime(waiver_details['valid_to'], "%a, %d %b %Y %H:%M:%S %Z") + " GMT"
    except (KeyError, TypeError):
      details['end'] = datetime.datetime.now() + datetime.timedelta(days=30)
    try:
      details['comments'] = waiver_details['comments']
    except (KeyError, TypeError):
      pass
    try:
        details['last_changed'] = waiver_details['changed_datetime']
    except (KeyError, TypeError):
      pass
    try:
      details['version'] = waiver_details['processes']['version']
    except (KeyError, TypeError):
      pass
    try:
      details['supplementry_pipeline'] = waiver_details['supplementry_waiver_list']
    except (KeyError, TypeError):
      pass
    return render_template("waiver_details.html", details=details, deployment=request.args['deployment'])
  except OperationFailure as e:
    print(e.details)

@app.route("/update_waiver", methods=['POST'])
def update_waiver():
  try:
    deployment = request.form['deployment']
    end_date = datetime.datetime.strptime(request.form['end'], "%a, %d %b %Y %H:%M:%S %Z")
    start_date = datetime.datetime.strptime(request.form['start'], "%a, %d %b %Y %H:%M:%S %Z")
    auth = []

    if request.form['supplementry_waiver']:
      try:
        #Needs to convert to dictionary
        supplementry_waiver_list = request.form['supplementry_waiver'].split('\r\n')
      except ValueError as e:
        return render_template('badness.html', message="The supplementry pipeline is not correct: %s" % e)
    else:
      supplementry_waiver_list = []

    if 'GSSAPI' in request.form:
      auth.append('GSSAPI')
    if 'SCRAM-SHA-1' in request.form:
      auth.append('MONGODB-CR')
    if 'SCRAM-SHA-256' in request.form:
      auth.append('SCRAM-SHA-256')
    if 'LDAP' in request.form:
      auth.append('PLAIN')
    update_details = {"deployment": deployment,"valid_to": end_date, "valid_from": start_date, "project" : {"auth": {"deploymentAuthMechanisms": auth}}, "changed_datetime": datetime.datetime.now(),"comments": request.form['comments'], "supplementry_waivers": supplementry_waiver_list}
    new_waiver = {"deployment": deployment, "valid_to": end_date, "valid_from": start_date, "project" : {"auth": {"deploymentAuthMechanisms": auth}}, "changed_datetime": datetime.datetime.now(), "supplementry_waivers": supplementry_waiver_list}
    if 'version' in request.form:
      if 'processes' not in update_details:
        update_details['processes'] = {}
      if 'processes' not in new_waiver:
        new_waiver['processes'] = {}
      update_details['processes']['version'] = request.form['version']
      new_waiver['processes']['version'] = request.form['version']
    update_details['schema_version'] = 0
    new_waiver['schema_version'] = 0
    # Index {"deployment": 1} on `logging.waivers`
    details = waivers_collection.find_one_and_update({"deployment": deployment},{"$set": update_details}, upsert=True, return_document=ReturnDocument.AFTER)
    waivers_archive_collection.insert_one(new_waiver)
    return render_template('new_waiver.html', new_waiver=dumps(details, indent=2))
  except OperationFailure as e:
    print(e.details)

if __name__ == "__main__":
   app.run(host='0.0.0.0', port=8000, debug=DEBUG)