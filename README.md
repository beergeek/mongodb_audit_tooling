# MongoDB Auditing Tools

This repo contains several Python scripts designed to retrieve logging data from MongoDB databases and from Ops Manager (via change streams).

The following tools are in this repository:

* log_processor (to process the audit logs from MongoDB instance and forward to a MongoDB audit database)
* config_watcher (to retrieve configuration changes to Ops Manager and forward to a MongoDB audit database)
* event_watcher (to retrieve audit events from Ops Manager and forward to a MongoDB audit database)
* deployment_configs (to retrieve all the deployment configurations from Ops Manager)

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
debug=True
audit_log=/data/logs/audit_log
elevated_ops_events=shutdown
elevated_app_events=dropCollection,dropDatabase
```

NOTE that URL encoded special characters require double `%`, e.g `@` would be `%%40` (such as the MongoDB connection string).

Both sections are mandatory, as well as the `connection_string` option, but the `timeout` and `debug` are option (having defaults of 10 seconds and `false` respectivetly). SSL/TLS settings are optional, but if `ssl_enabled` is `True` then `ssl_pem_path` and `ssl_ca_cert_path` must exist.

The `elevated_app_events` and `elevated_ops_events` are comma separated lists of events that will be either tagged as `APP EVENT` or `OPS EVENT` respectively for easy querying in the audit database. The `audit_log` option, which is optional, is the path, including file name, to the MongoDB instance audit log, the default is `audit.log` in the directory where the script resides.

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

NOTE that URL encoded special characters require double `%`, e.g `@` would be `%%40`.

An example that is similar to this script can be found in the section below.

Both sections are mandatory, as well as the `connection_string` option, but the `timeout` and `debug` are option (having defaults of 10 seconds and `false` respectivetly). The optional `event_pipeline` is a change stream pipeline to filter events. SSL/TLS settings for both databases are optional, but if `ssl_enabled` is `True` then `ssl_pem_path` and `ssl_ca_cert_path` must exist. SSL/TLS default is `False`.

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
event_pipeline=[{'$match': {'fullDocument.un': {$in: ['ivan','vigyan','mac']}}]
ssl_enabled=True
ssl_pem_path=/data/pki/mongod3.mongodb.local.pem
ssl_ca_cert_path=/data/pki/ca.cert

[general]
debug=False
```

NOTE that URL encoded special characters require double `%`, e.g `@` would be `%%40`.

An example that is similar to this script can be found in the section below.

Both sections are mandatory, as well as the `connection_string` option, but the `timeout` and `debug` are option (having defaults of 10 seconds and `false` respectivetly). The optional `event_pipeline` is a change stream pipeline to filter events. SSL/TLS settings for both databases are optional, but if `ssl_enabled` is `True` then `ssl_pem_path` and `ssl_ca_cert_path` must exist. SSL/TLS default is `False`.

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
ssl_enabled=True
ssl_ca_cert_path=/data/pki/ca.cert
ssl_pem_path=/data/pki/auditor.mongodb.local.pem

[general]
debug=True
```

NOTE that URL encoded special characters require double `%`, e.g `@` would be `%%40`.

All sections are mandatory. The `baseurl`, `username`, and `token` options within the `ops_manager` section and `connection_string` option within `audit_db` section are mandatory. The the `timeout` and `debug` options (having defaults of 10 and `false` respectivetly) are optional.

Both the `ops_manager` and `audit_db` sections have the optional `ssl_ca_cert_path` and `ssl_pem_path` settings. The `audit_db` section also has `ssl_enabled` which must be set to `True` for SSL/TLS. For the Ops Manager API the SSL/TLS setting is determined by using `https` in the `baseurl` optional.

## Permissions

For all of the scripts, the user that is writing to the MongoDB audit database must have `readWrite` permissions on the `logging` database and `log` collection.

For the `log_processor` script the user executing the script will need to be able to read the database audit log.

For the `config_watcher` script the user will need to have `read` privileges on the `config.appState` collection within the `cloudconf` database in the Ops Manager application database.

For the `event_watcher` script the user will need to have `read` privileges on the `data.events` collection within the `mmsdb` database in the Ops Manager application database.

For the `deployment_configs` script will only retrieve deployments that the API user has permissions to access.

## Setup

The following non-standard Python modules are required:

* pymongo
* kerberos
* configparser
* bson
* requests

