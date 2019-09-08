try:
  from flask import Flask, render_template, request, current_app, redirect, url_for
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
  from pymongo.errors import OperationFailure
  from bson.json_util import dumps
  from bson.objectid import ObjectId
except ImportError as e:
  print(e)
  exit(1)

LOG_FILE = 'reporter.log'

# Get config setting from `event_watcher.config` file
if os.path.isfile('reporter.conf') == False:
  logging.basicConfig(filename=LOG_FILE,level=logging.ERROR)
  logging.error('The `reporter.conf` file must exist in the same directory as the Python script')
  print('\033[93m' + 'The `reporter.conf` file must exist in the same directory as the Python script, exiting' + '\033[m')
  sys.exit(0)
config = configparser.ConfigParser()
config.read('reporter.conf')
try:
  DEBUG = config.getboolean('general','debug', fallback=False)
  AUDIT_DB_CONNECTION_STRING = config.get('audit_db','connection_string')
  AUDIT_DB_SSL = config.getboolean('audit_db','ssl_enabled',fallback=False)
  if AUDIT_DB_SSL is True:
    AUDIT_DB_SSL_PEM = config.get('audit_db','ssl_pem_path')
    AUDIT_DB_SSL_CA = config.get('audit_db', 'ssl_ca_cert_path')
  OPS_MANAGER_TIMEOUT = config.getint('ops_manager','timeout', fallback=1000)
  AUDIT_DB_TIMEOUT = config.getint('audit_db','timeout', fallback=1000)
except configparser.NoOptionError as e:
  logging.basicConfig(filename=LOG_FILE,level=logging.ERROR)
  logging.error('The config file must include the `connection_string` option in the `audit_db` section')
  print('\033[91m' + "ERROR! The config file must include the `connection_string` option in both the `audit_db` section "
    ", such as:\n"
    + '\033[92m'
    "[audit_db]"
    "connection_string=mongodb://username:password@host:port/?replicaSet=replicasetname\n"
    "ssl_enabled=True\n"
    "ssl_pem_path=/data/pki/mongod3.mongodb.local.pem\n"
    "ssl_ca_cert_path=/data/pki/ca.cert\n"
    + '\033[m')
  sys.exit(1)
except configparser.NoSectionError as e:
  logging.basicConfig(filename=LOG_FILE,level=logging.ERROR)
  logging.error('The config file must include sections `audit_db` and `general`')
  print('\033[91m' + "ERROR! The config file must include sections `audit_db`, and `general`, such as:\n"
    + '\033[92m'
    "[audit_db]\n"
    "connection_string=mongodb://username:password@host:port/?replicaSet=replicasetname\n"
    "ssl_enabled=True\n"
    "ssl_pem_path=/data/pki/mongod3.mongodb.local.pem\n"
    "ssl_ca_cert_path=/data/pki/ca.cert\n"
    "timeout=1000\n\n"
    "[general]\n"
    "debug=False"
    + '\033[m'
    )
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
config_collection = audit_db['configs']
standards_collection = audit_db['standards']
waivers_collection = audit_db['waivers']

# main route 
@app.route("/")
def index():
  try:
    user_list_pipeline = [
      {
        "$project": {
          "User": { 
            "$ifNull": ['$users.user', '$fullDocument.un']
          }
        }
      },
      {
        "$group": {
          "_id": "$User"
        }
      },
      {
        "$project": {
          "Users": {
            "$cond": {
              "if": {
                "$eq": [
                  {
                    "$type": "$_id"
                  },
                  "array"
                ]
              },
              "then": {
                "$arrayElemAt": ["$_id",0]
              },
              "else": "$_id"
            }
          },
          "_id": 0
        }
      }
    ]
    output0 = list(audit_collection.aggregate(user_list_pipeline))
    users = []
    for user in output0:
      if 'Users' in user:
        users.append(user['Users'])
    output1 = list(audit_collection.distinct("fullDocument.clusterConfig.cluster.processes.hostname"))
    hosts = []
    for host in output1:
      hosts.append(host)
    output2 = list(config_collection.distinct("deployment"))
    deployments = []
    for deployment in output2:
      deployments.append(deployment)
    return render_template('index.html', users=users, hosts=hosts, deployments=deployments)
  except OperationFailure as e:
    print(e.details)
    logging.error(e.details)

@app.route("/user_report", methods=['GET'])
def get_user():
  try:
    user_pipeline = [
      {
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
      }, 
      {
        "$project": {
          "_id": 1,
          "ts": 1,
          "source": 1,
          "Changes": {"$ifNull": [{"$arrayElemAt": ["$fullDocument.deploymentDiff.diffs.status",0]}, "$param.command"]},
          "Hosts": {"$ifNull": ["$fullDocument.clusterConfig.cluster.processes.hostname","$host"]},
          "Type": {"$ifNull": ["$fullDocument._t", "$atype"]},
          "Other": "$fullDocument.et"
        }
      },
      {
        "$sort": {
          "ts": -1
        }
      }
    ]

    print(user_pipeline)
    event_output = list(audit_collection.aggregate(user_pipeline))
    events = []
    for event in event_output:
      events.append(event)
      if 'Changes' in event:
        event['Changes'] = dumps(event['Changes'], indent=2)
      elif 'Other' in event:
        event['Changes'] = dumps(event['Other'], indent=2)
      if 'Hosts' in event:
        event['Hosts'] = dumps(event['Hosts'], indent=2)
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
    host_search = re.compile("^%s" %request.args['host'])
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
      }
    ]

    event_output = list(audit_collection.aggregate(host_pipeline))
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
    return render_template('host_event_details_data.html', data=formatted, dtg=host_data['ts'])
  except OperationFailure as e:
    print(e.details)

@app.route("/deployment_report", methods=["GET"])
def get_deployment():
  try:
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
          "compliance": 1
        }
      },
      {
        "$sort": {
          "ts": -1
        }
      }
    ]

    event_output = list(config_collection.aggregate(deployment_pipeline))
    events = []
    for event in event_output:
      temp_config = {}
      temp_config['out_of_spec'] = []
      temp_config['out_of_spec'] = event['compliance']
      temp_config['hosts'] = dumps(event['hosts'], indent=2)
      temp_config['ts'] = event['ts']
      temp_config['_id'] = event['_id']
      events.append(temp_config)
    return render_template('deployment_events.html', events=events, low_date=request.args['dtg_fixed_low_deployment'], high_date=request.args['dtg_fixed_high_deployment'], deployment=request.args['deployment'])
  except OperationFailure as e:
    print(e.details)



@app.route("/deployment_event_details/<oid>", methods=['GET'])
def get_deployment_event_details(oid):
  try:
    if ObjectId.is_valid(oid):
      deployment_data = config_collection.find_one({"_id": ObjectId(oid)},{"compliance": 0})
    else:
      deployment_data = config_collection.find_one({"_id": ast.literal_eval(oid)},{"compliance": 0})
    formatted = dumps(deployment_data, indent=2)
    return render_template('deployment_event_details_data.html', data=formatted, dtg=deployment_data['ts'], oid=deployment_data['deployment'])
  except OperationFailure as e:
    print(e.details)

@app.route("/admin", methods=['GET'])
def admin_tasks():
  try:
    standards = dumps(standards_collection.find_one({"valid_to": {"$exists": False}}), indent=2)
    deployments = list(waivers_collection.distinct("deployment"))
    return render_template('admin_tasks.html', standards=standards, deployments=deployments)
  except OperationFailure as e:
    print(e.details)


if __name__ == "__main__":
   app.run(host='0.0.0.0', port=8000, debug=DEBUG)