# MongoDB Auditing Tools

This repo contains several Python scripts designed to retrieve logging data from MongoDB databases and from Ops Manager (via change streams).

The following tools are in this repository:

* log_processor (to process the audit logs from MongoDB instance and forward to a MongoDB audit database)
* config_watcher (to retrieve configuration changes to Ops Manager and forward to a MongoDB audit database)
* event_watcher (to retrieve audit events from Ops Manager and forward to a MongoDB audit database)
* deployment_configs (to retrieve all the deployment configurations from Ops Manager)
* reporter (basic Flask app to query and display various reports and admin tasks)

# Details

## log_processor

This script reads the MongoDB audit log and sends each entry, after formatting, to a MongoDB 'audit' database.

The data from the MongoDB databases must be in JSON format and written out to a file. The process for doing this can be found in the [MongoDB documentation](https://docs.mongodb.com/manual/core/auditing/).

The script uses a configuration file (`log_processor.conf`) that must reside in the same location as the script.

The configuration file has the following format (__NOTE__: none of the string have quotes):

```shell
[audit_db]
connection_string=mongodb://<USERNAME>:<PASSWORD>@<HOST>:<PORT>/?replicaSet=<REPLICA_SET_NAME>&<OTHER_OPTIONS>
timeout=<TIMEOUT_VALUE>
ssl_enabled=<BOOLEAN_VALUE>
ssl_pem_path=<PATH_TO_PEM_FILE>
ssl_ca_cert_path=<PATH_TO_CA_CERT>

[general]
debug=<BOOLEAN_VALUE>
audit_log=<AUDIT_LOG_PATH>
elevated_ops_events=<COMMA_SEPARATED_LIST>
elevated_app_events=<COMMA_SEPARATED_LIST>
elevated_config_events=<COMMA_SEPARATED_LIST>
```

Example:

```shell
[audit_db]
connection_string=mongodb://auditor%%40MONGODB.LOCAL@audit.mongodb.local:27017/?replicaSet=repl0&authSource=$external&authMechanism=GSSAPI
timeout=1000
ssl_enabled=True
ssl_pem_path=/data/pki/mongod3.mongodb.local.pem
ssl_ca_cert_path=/data/pki/ca.cert

[general]
debug=true
audit_log=/data/logs/audit_log
elevated_config_events=shutdown,setParameter,setFeatureCompatibilityVersion,addShard,addShardToZone,balancerStart,balancerStop,enableSharding,flushRouterConfig,moveChunk,mergeChunks,removeShard,removeShardFromZone,setShardVersion,shardCollection,splitChunk,unsetSharding,updateZoneKeyRange,replSetReconfig,replSetInitiate
elevated_ops_events=createUser,deleteUser
elevated_app_events=dropCollection,dropDatabase
```

NOTE that URL encoded special characters require double `%`, e.g `@` would be `%%40` (such as the MongoDB connection string).

Both sections are mandatory, as well as the `connection_string` option, but the `timeout` and `debug` are option (having defaults of 10 seconds and `false` respectivetly). SSL/TLS settings are optional, but if `ssl_enabled` is `True` then `ssl_pem_path` and `ssl_ca_cert_path` must exist.

The `elevated_app_events`, `elevated_config_events` `elevated_ops_events` are comma separated lists of events that will be either tagged as `APP EVENT`, `CONFIG EVENT` or `OPS EVENT` respectively for easy querying in the audit database. The list of events are available in the [MongoDB documentation](https://docs.mongodb.com/manual/reference/audit-message/#audit-event-actions-details-and-results).

The `audit_log` option, which is optional, is the path, including file name, to the MongoDB instance audit log, the default is `audit.log` in the directory where the script resides.

### Setup

This script resides on each server of the deployment.

The following non-standard Python modules are required (and dependancies):

* [pymongo](https://pypi.org/project/pymongo/)
* [kerberos](https://pypi.org/project/kerberos/)
* [configparser](https://pypi.org/project/configparser/)

The mongod config file should have something similar to the following for auditing:

```JSON
auditLog:
  destination: file
  filter: "{$or: [{'param.command': {$nin: ['_isSelf','appendOplogNote','buildInfo','getMore','isMaster','ismaster','ping','replSetGetStatus','saslContinue','saslStart']},$or: [{'users.user': {$nin: ['__system','mms-backup-agent','mms-monitoring-agent','mms-automation']},'roles.role': {$in: ['root',/Admin/]}}]},{'users.user': 'mms-automation','param.command': {$nin: ['_isSelf','appendOplogNote','buildInfo','getMore','isMaster','ismaster','ping','replSetGetStatus','saslContinue','saslStart','listIndexes','getLog','serverStatus','collstats','listCollections','killCursors','getCmdLineOpts','hostInfo','getParameter','connPoolStats','find','dbstats','listDatabases']}},{'atype': {$in: ['addShard','createCollection','createDatabase','createIndex','createRole','createUser','dropAllRolesFromDatabase','dropAllUsersFromDatabase','dropCollection','dropDatabase','dropIndex','dropRole','dropUser','enableSharding','grantPrivilegesToRole','grantRolesToRole','grantRolesToUser','removeShard','renameCollection','replSetReconfig','revokePrivilegesFromRole','revokeRolesFromRole','revokeRolesFromUser','shardCollection','shutdown','updateRole','updateUser']}}]}"
  format: JSON
  path: /data/logs/audit.log
setParameter:
  auditAuthorizationSuccess: "true"
```

The script and config file must be located in the same directory. A systemD service file can be created to run these scripts automatically on start:

```shell
[Unit]
Description=Watcher Script for MongoDB Auditing
After=network.target

[Service]
User=mongod
Group=mongod
Environment="KRB5_CLIENT_KTNAME=/data/pki/audit.keytab"
ExecStart=/bin/python /data/logs/log_processor.py
Type=simple

[Install]
WantedBy=multi-user.target
```

## config_watcher

This script retrieve Ops Manager configuration modifications from the Ops Manager application database via a change stream on the `cloudconf.config.appState` database/collection. The events are formatted and inserted into a MongoDB 'audit' database.

The script uses a configuration file (`config_watcher.conf`) that must reside in the same location as the script.

The configuration file has the following format (__NOTE__: none of the string have quotes):

```shell
[audit_db]
connection_string=mongodb://<USERNAME>:<PASSWORD>@<HOST>:<PORT>/?replicaSet=<REPLICA_SET_NAME>&<OTHER_OPTIONS>
timeout=<TIMEOUT_VALUE>
ssl_enabled=<BOOLEAN_VALUE>
ssl_pem_path=<PATH_TO_PEM_FILE>
ssl_ca_cert_path=<PATH_TO_CA_CERT>

[ops_manager_db]
connection_string=mongodb://<USERNAME>:<PASSWORD>@<HOST>:<PORT>/?replicaSet=<REPLICA_SET_NAME>&<OTHER_OPTIONS>
timeout=<TIMEOUT_VALUE>
event_pipeline=<MONGODB_PIPELINE>
ssl_enabled=<BOOLEAN_VALUE>
ssl_pem_path=<PATH_TO_PEM_FILE>
ssl_ca_cert_path=<PATH_TO_CA_CERT>

[general]
debug=<BOOLEAN_VALUE>
```

Example:
```shell
[ops_manager_db]
connection_string=mongodb://admin:superpassword@mongod0.mongodb.local:27017/?replicaSet=appdb
timeout=1000
ssl_enabled=True
ssl_ca_cert_path=/data/pki/ca.cert
ssl_pem_path=/data/pki/mongod6.mongodb.local.pem

[audit_db]
connection_string=mongodb://auditor%%40MONGODB.LOCAL@audit.mongodb.local:27017/?replicaSet=repl0&authSource=$external&authMechanism=GSSAPI
timeout=1000
ssl_enabled=True
ssl_ca_cert_path=/data/pki/ca.cert
ssl_pem_path=/data/pki/mongod6.mongodb.local.pem

[general]
debug=True
```

NOTE that URL encoded special characters require double `%`, e.g `@` would be `%%40`.

An example that is similar to this script can be found in the section below.

Both sections are mandatory, as well as the `connection_string` option, but the `timeout` and `debug` are option (having defaults of 10 seconds and `false` respectivetly). The optional `event_pipeline` is a change stream pipeline to filter events. SSL/TLS settings for both databases are optional, but if `ssl_enabled` is `True` then `ssl_pem_path` and `ssl_ca_cert_path` must exist. SSL/TLS default is `False`.

### Setup

This script should reside on a single server, most likely one of the Audit DB nodes.

The following non-standard Python modules are required (and dependancies):

* [pymongo](https://pypi.org/project/pymongo/)
* [kerberos](https://pypi.org/project/kerberos/)
* [configparser](https://pypi.org/project/configparser/)

The script and config file must be located in the same directory. A systemD service file can be created to run these scripts automatically on start:

```shell
[Unit]
Description=Watcher Script for MongoDB Auditing
After=network.target

[Service]
User=mongod
Group=mongod
Environment="KRB5_CLIENT_KTNAME=/data/pki/audit.keytab"
ExecStart=/bin/python /data/scripts/config_watcher.py
Type=simple

[Install]
WantedBy=multi-user.target
```

## event_watcher

This script retrieve events from the Ops Manager application database via a change stream on the `mmsdb.data.events` database/collection. The events are formatted and inserted into a MongoDB 'audit' database.

The script uses a configuration file (`event_watcher.conf`) that must reside in the same location as the script.

The configuration file has the following format (__NOTE__: none of the string have quotes):

```shell
[audit_db]
connection_string=mongodb://<USERNAME>:<PASSWORD>@<HOST>:<PORT>/?replicaSet=<REPLICA_SET_NAME>&<OTHER_OPTIONS>
timeout=<TIMEOUT_VALUE>
ssl_enabled=<BOOLEAN_VALUE>
ssl_pem_path=<PATH_TO_PEM_FILE>
ssl_ca_cert_path=<PATH_TO_CA_CERT>

[ops_manager_db]
connection_string=mongodb://<USERNAME>:<PASSWORD>@<HOST>:<PORT>/?replicaSet=<REPLICA_SET_NAME>&<OTHER_OPTIONS>
timeout=<TIMEOUT_VALUE>
event_pipeline=<MONGODB_PIPELINE>
ssl_enabled=<BOOLEAN_VALUE>
ssl_pem_path=<PATH_TO_PEM_FILE>
ssl_ca_cert_path=<PATH_TO_CA_CERT>

[general]
debug=<BOOLEAN_VALUE>
```

An example:

```shell
[audit_db]
connection_string=mongodb://auditor%%40MONGODB.LOCAL@om.mongodb.local:27017/?replicaSet=repl0&authSource=$external&authMechanism=GSSAPI
timeout=2000
ssl_enabled=True
ssl_pem_path=/data/pki/mongod3.mongodb.local.pem
ssl_ca_cert_path=/data/pki/ca.cert

[ops_manager_db]
connection_string=mongodb://auditwriter%%40MONGODB.LOCAL@audit.mongodb.local:27017?replicaSet=audit&authSource=$external&authMechanism=GSSAPI
timeout=1000
event_pipeline=[{'$match': {'fullDocument.un': {$in: ['ivan','vigyan','mac','loudSam']}}]
ssl_enabled=True
ssl_pem_path=/data/pki/mongod3.mongodb.local.pem
ssl_ca_cert_path=/data/pki/ca.cert

[general]
debug=False
```

NOTE that URL encoded special characters require double `%`, e.g `@` would be `%%40`.

An example that is similar to this script can be found in the section below.

Both sections are mandatory, as well as the `connection_string` option, but the `timeout` and `debug` are option (having defaults of 10 seconds and `false` respectivetly). The optional `event_pipeline` is a change stream pipeline to filter events. SSL/TLS settings for both databases are optional, but if `ssl_enabled` is `True` then `ssl_pem_path` and `ssl_ca_cert_path` must exist. SSL/TLS default is `False`.

### Setup

This script should reside on a single server, most likely one of the Audit DB nodes.

The following non-standard Python modules are required (and dependancies):

* [pymongo](https://pypi.org/project/pymongo/)
* [kerberos](https://pypi.org/project/kerberos/)
* [configparser](https://pypi.org/project/configparser/)

The script and config file must be located in the same directory. A systemD service file can be created to run these scripts automatically on start:

```shell
[Unit]
Description=Watcher Script for MongoDB Auditing
After=network.target

[Service]
User=mongod
Group=mongod
Environment="KRB5_CLIENT_KTNAME=/data/pki/audit.keytab"
ExecStart=/bin/python /data/scripts/event_watcher.py
Type=simple

[Install]
WantedBy=multi-user.target
```

## deployment_configs

The script retrieves the deployment configurations from Ops Manager via the API.

The script uses a configuration file (`deployment_configs.conf`) that must reside in the same location as the script.

The configuration file has the following format (__NOTE__: none of the string have quotes):

```shell
[ops_manager]
baseurl=https://<HOST>:<PORT>
username=<API_USERNAME>
token=<API_USER_TOKEN>
timeout=<TIMEOUT_VALUE>
ssl_pem_path=<PATH_TO_PEM_FILE>
ssl_ca_cert_path=<PATH_TO_CA_CERT>

[audit_db]
connection_string=mongodb://<USERNAME>:<PASSWORD>@<HOST>:<PORT>/?replicaSet=<REPLICA_SET_NAME>&<OTHER_OPTIONS>
timeout=<TIMEOUT_VALUE>
ssl_enabled=<BOOLEAN_VALUE>
ssl_pem_path=<PATH_TO_PEM_FILE>
ssl_ca_cert_path=<PATH_TO_CA_CERT>

[general]
debug=<BOOLEAN_VALUE>
exclude_root_keys=<COMMA_SEPARATED_LIST>
role_search_term=<COMMA_SEPARATED_LIST>

[deployments]
db_credentials=auditwriter%%40MONGODB.LOCAL
non_om_deployments=mongod10.mongodb.local:27017/?replicaSet=appdb,mongod10.mongodb.local:27018/?replicaSet=oplogdb
ssl_enabled=True
ssl_ca_cert_path=/data/pki/ca.cert
ssl_pem_path=/data/pki/mongod6.mongodb.local.pem
auth_source=$external
auth_method=GSSAPI
```

Example:

```shell
[ops_manager]
baseurl=https://mongod0.mongodb.local:8443
username=auditor
token=8ce50f02-4292-460e-82a5-000a074218ba
timeout=1000
ssl_ca_cert_path=/data/pki/ca.cert
ssl_pem_path=/data/pki/auditor.mongodb.local.pem

[audit_db]
connection_string=mongodb://auditwriter%%40MONGODB.LOCAL@audit.mongodb.local:27017/?replicaSet=repl0&authSource=$external&authMechanism=GSSAPI
timeout=1000
ssl_enabled=true
ssl_ca_cert_path=/data/pki/ca.cert
ssl_pem_path=/data/pki/auditor.mongodb.local.pem

[general]
debug=false
excluded_root_keys=mongoDbVersions,mongosqlds,backupVersions,agentVersion,monitoringVersions,uiBaseUrl,cpsModules,mongots,indexConfigs
role_search_terms=Admin,schema

[deployments]
db_credentials=auditwriter%%40MONGODB.LOCAL
non_om_deployments=mongod10.mongodb.local:27017/?replicaSet=appdb,mongod10.mongodb.local:27018/?replicaSet=oplogdb
ssl_enabled=True
ssl_ca_cert_path=/data/pki/ca.cert
ssl_pem_path=/data/pki/mongod6.mongodb.local.pem
auth_source=$external
auth_method=GSSAPI
```

NOTE that URL encoded special characters require double `%`, e.g `@` would be `%%40`.

All sections are mandatory. The `baseurl`, `username`, and `token` options within the `ops_manager` section and `connection_string` option within `audit_db` section are mandatory. The `timeout` and `debug` options (having defaults of 10 and `false` respectivetly) are optional.

Both the `ops_manager` and `audit_db` sections have the optional `ssl_ca_cert_path` and `ssl_pem_path` settings. The `audit_db` section also has `ssl_enabled` which must be set to `True` for SSL/TLS. For the Ops Manager API the SSL/TLS setting is determined by using `https` in the `baseurl` optional.

The `excluded_root_keys` option is a comma separated list of root-level keys to exclude when saving the configs to the audit db; this is purely to exclude unwanted or needed data and is optional.

The `role_search_term` is a comma separated list of regex terms to use to search for users who have admin-like privileges that should not.

### Setup

This script should reside on a single server, most likely one of the Audit DB nodes.

The following non-standard Python modules are required (and dependancies):

* [pymongo](https://pypi.org/project/pymongo/)
* [kerberos](https://pypi.org/project/kerberos/)
* [configparser](https://pypi.org/project/configparser/)
* [requests](https://pypi.org/project/requests2/)

The script and config file must be located in the same directory. This script can be run from cron or Control-M at the frequency desired, such as:

```shell
KRB5_CLIENT_KTNAME=/data/scripts/audit.keytab
00 * * * * python /data/scripts/deployment_configs.py
```

## reporter

The reporter script is a basic Python Flask application used to query and display reports relating to the auditing. The application also provides the ability to configure a standard to compare configurations against and the ability ti created waivers per deployment.

The configuration file must reside in the same directory as the Python script and is name `repoprter.conf`.

The following is the basic configuration:

```shell
[audit_db]
connection_string=mongodb://<USERNAME>:<PASSWORD>@<HOST>:<PORT>/?replicaSet=<REPLICA_SET_NAME>&<OTHER_OPTIONS>
timeout=<TIMEOUT_VALUE>
ssl_enabled=<BOOLEAN_VALUE>
ssl_pem_path=<PATH_TO_PEM_FILE>
ssl_ca_cert_path=<PATH_TO_CA_CERT>

[general]
debug=<BOOLEAN_VALUE>
```

Example:

```shell
[audit_db]
connection_string=mongodb://web_user%%40MONGODB.LOCAL@mongod6.mongodb.local:27017/?replicaSet=repl0&authSource=$external&authMechanism=GSSAPI
timeout=10
ssl_enabled=True
ssl_ca_cert_path=/data/pki/ca.cert
ssl_pem_path=/data/pki/mongod6.mongodb.local.pem

[general]
debug=false
```

The application listens on port 8000 via HTTP, the script can be modified manually to change port and use HTTPS if desired.

### Setup

The script can run on any Linux node that has access to the Audit DB.

The following non-standard Python modules are required (and dependancies):

* [pymongo](https://pypi.org/project/pymongo/)
* [kerberos](https://pypi.org/project/kerberos/)
* [configparser](https://pypi.org/project/configparser/)
* [flask](https://pypi.org/project/Flask/)

The script and config file must be located in the same directory.

The Flask application can be run standalone for via a setup with a web server and WSGI.

The application is contained within the `flask directory` and can be run in the foreground with `env KRB5_CLIENT_KTNAME=/data/pki/audit.keytab python /data/scripts/flask/reporter.py` or `env KRB5_CLIENT_KTNAME=/data/pki/audit.keytab python3 /data/scripts/flask/reporter.py`.

The website has a link for `http://<website>:8000/admin` for managing the standard and supplementry pipeline, as well as waivers.

The standard is in the Ops Manager-like format, with `processes` and `project` keys. The value for `processes` is the same as that for Ops Manager managed hosts. The project covers the overall project settings similar to Ops Manager.

Example:

```JSON
{
  "project": {
    "ssl": {
      "clientCertificateMode": "OPTIONAL", 
      "CAFilePath": "/data/pki/ca.cert", 
      "autoPEMKeyFilePath": "/etc/mongodb-mms/aa.pem"
    }, 
    "kerberos": {
      "serviceName": "mongodb"
    }, 
    "auth": {
      "deploymentAuthMechanisms": [
        "MONGODB-CR", 
        "SCRAM-SHA-256", 
        "SCRAM-SHA-256"
      ], 
      "autoAuthMechanism": "MONGODB-CR"
    }
  }, 
  "valid_from": {
    "$date": 1568352456013
  }, 
  "processes": {
    "authSchemaVersion": 5.0, 
    "kerberos": {
      "keytab": "/data/pki/server_keytab"
    }, 
    "featureCompatibilityVersion": "4.0", 
    "disabled": false, 
    "logRotate": {
      "timeThresholdHrs": 24.0, 
      "sizeThresholdMB": 1000.0
    }, 
    "version": "4.0.12-ent", 
    "args2_6": {
      "net": {
        "ssl": {
          "mode": "preferSSL", 
          "disabledProtocols": "TLS1_0,TLS1_1"
        }, 
        "port": 27017, 
        "bindIpAll": true
      }, 
      "storage": {
        "wiredTiger": {
          "engineConfig": {
            "directoryForIndexes": true
          }
        }, 
        "directoryPerDB": true
      }, 
      "security": {
        "encryptionKeyFile": "/data/pki/mongodb_keyfile", 
        "enableEncryption": true
      }, 
      "systemLog": {
        "destination": "file"
      }
    }, 
    "manualMode": false
  }, 
  "_id": {
    "$oid": "5d75c89f0caa1e7b707ba511"
  }, 
  "schema_version": 0
}
```

## Permissions

For all of the scripts, the user that is writing to the MongoDB audit database must have `readWrite` permissions on the `logging` database and `log` collection.

For the `log_processor` script the user executing the script will need to be able to read the database audit log.

For the `config_watcher` script the user will need to have `read` privileges on the `config.appState` collection within the `cloudconf` database in the Ops Manager application database.

For the `event_watcher` script the user will need to have `read` privileges on the `data.events` collection within the `mmsdb` database in the Ops Manager application database.

For the `deployment_configs` script will only retrieve deployments that the API user has permissions to access. The user will also need the following access on all deployments:

```JSON
{
  "roles": [
    {"role": "readAnyDatabase", "db": "admin"},
    {"role": "clusterMonitor", "db": "admin"},
    {"role": "backup", "db": "admin"}
  ],
  "privileges" : [
  	{
  		"resource" : {
  			"db" : "admin",
  			"collection" : "system.users"
  		},
  		"actions" : [
  			"viewRole",
  			"viewUser"
  		]
    }
  ]
}
```

For the `reporter` script the 

The `reporter` script user that accesses the audit db will need the following privileges:

```JSON
{
  "privileges": [
  	{
  		"resource" : {
  			"db" : "logging",
  			"collection" : "standards"
  		},
  		"actions" : [
        "find",
        "insert",
        "update",
  		]
  	},
  	{
  		"resource" : {
  			"db" : "logging",
  			"collection" : "standards_archive"
  		},
  		"actions" : [
        "find",
        "insert"
  		]
  	},
  	{
  		"resource" : {
  			"db" : "logging",
  			"collection" : "waivers"
  		},
  		"actions" : [
        "find",
        "insert",
        "update",
  		]
  	},
  	{
  		"resource" : {
  			"db" : "logging",
  			"collection" : "waivers_archive"
  		},
  		"actions" : [
        "find",
        "insert"
  		]
  	},
  	{
  		"resource" : {
  			"db" : "logging",
  			"collection" : "logs"
  		},
  		"actions" : [
  			"find",
  			"insert",
  			"update"
  		]
  	},
  	{
  		"resource" : {
  			"db" : "logging",
  			"collection" : "configs"
  		},
  		"actions" : [
  			"find",
  			"insert",
  			"update"
  		]
  	},
  	{
  		"resource" : {
  			"db" : "logging",
  			"collection" : "configs_archive"
  		},
  		"actions" : [
  			"find",
  			"insert"
  		]
  	}
  ]
}
```

