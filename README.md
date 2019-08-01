# MongoDB Auditing Tools

This repo contains several Python scripts designed to retrieve logging data from MongoDB databases and from Ops Manager (via change streams).

The following tools are in this repository:

* log_processor (to process the audit logs from MongoDB instance and forward to a MongoDB audit database)
* config_watcher (to retrieve configuration changes to Ops Manager and forward to a MongoDB audit database)
* event_watcher (to retrieve audit events from Ops Manager and forward to a MongoDB audit database)

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

[general]
debug=<BOOLEAN_VALUE>
audit_log=<AUDIT_LOG_PATH>
elevated_ops_events=<COMMA_SEPARATED_LIST>
elevated_app_events=<COMMA_SEPARATED_LIST>
```

Example:

```shell
[audit_db]
connection_string=mongodb://auditor%%40MONGODB.LOCAL@mongod0.mongodb.local:27017/?replicaSet=repl0&authSource=$external&authMechanism=GSSAPI
timeout=1000

[general]
debug=True
audit_log=/data/logs/audit_log
elevated_ops_events=shutdown
elevated_app_events=dropCollection,dropDatabase
```

NOTE that URL encoded special characters require double `%`, e.g `@` would be `%%40`.

Both sections are mandatory, as well as the `connection_string` option, but the `timeout` and `debug` are option (having defaults of 1000 and False respectivetly).

The `elevated_app_events` and `elevated_ops_events` are comma separated lists of events that will be either tagged as `APP EVENT` or `OPS EVENT` respectively for easy querying in the audit database. The `audit_log` option, which is optional, is the path, including file name, to the MongoDB instance audit log, the default is `audit.log` in the directory where the script resides.

## config_watcher

This script retrieve Ops Manager configuration modifications from the Ops Manager application database via a change stream on the `cloudconf.config.appState` database/collection. The events are formatted and inserted into a MongoDB 'audit' database.

The script uses a configuration file (`config_watcher.conf`) that must reside in the same location as the script.

The configuration file has the following format (__NOTE__: none of the string have quotes):

```shell
[audit_db]
connection_string=mongodb://<USERNAME>:<PASSWORD>@<HOST>:<PORT>/?replicaSet=<REPLICA_SET_NAME>&<OTHER_OPTIONS>
timeout=<TIMEOUT_VALUE>

[ops_manager_db]
connection_string=mongodb://<USERNAME>:<PASSWORD>@<HOST>:<PORT>/?replicaSet=<REPLICA_SET_NAME>&<OTHER_OPTIONS>
timeout=<TIMEOUT_VALUE>
event_pipeline=<MONGODB_PIPELINE>

[general]
debug=<BOOLEAN_VALUE>
```

NOTE that URL encoded special characters require double `%`, e.g `@` would be `%%40`.

An example that is similar to this script can be found in the section below.

Both sections are mandatory, as well as the `connection_string` option, but the `timeout` and `debug` are option (having defaults of 1000 and False respectivetly). The optional `event_pipeline` is a change stream pipeline to filter events.

## event_watcher

This script retrieve events from the Ops Manager application database via a change stream on the `mmsdb.data.events` database/collection. The events are formatted and inserted into a MongoDB 'audit' database.

The script uses a configuration file (`event_watcher.conf`) that must reside in the same location as the script.

The configuration file has the following format (__NOTE__: none of the string have quotes):

```shell
[audit_db]
connection_string=mongodb://<USERNAME>:<PASSWORD>@<HOST>:<PORT>/?replicaSet=<REPLICA_SET_NAME>&<OTHER_OPTIONS>
timeout=<TIMEOUT_VALUE>

[ops_manager_db]
connection_string=mongodb://<USERNAME>:<PASSWORD>@<HOST>:<PORT>/?replicaSet=<REPLICA_SET_NAME>&<OTHER_OPTIONS>
timeout=<TIMEOUT_VALUE>
event_pipeline=<MONGODB_PIPELINE>

[general]
debug=<BOOLEAN_VALUE>
```

An example:

```shell
[audit_db]
connection_string=mongodb://auditor%%40MONGODB.LOCAL@om.mongodb.local:27017/?replicaSet=repl0&authSource=$external&authMechanism=GSSAPI
timeout=2000

[ops_manager_db]
connection_string=mongodb://auditwriter%%40MONGODB.LOCAL@audit.mongodb.local:27017?replicaSet=audit&authSource=$external&authMechanism=GSSAPI
timeout=1000
event_pipeline=[{'$match': {'fullDocument.un': {$in: ['ivan','vigyan','mac']}}]

[general]
debug=False
```

NOTE that URL encoded special characters require double `%`, e.g `@` would be `%%40`.

Both sections are mandatory, as well as the `connection_string` option, but the `timeout` and `debug` are option (having defaults of 1000 and False respectivetly). The optional `event_pipeline` is a change stream pipeline to filter events.

## Permissions

For all of the scripts, the user that is writing to the MongoDB audit database must have `readWrite` permissions on the `logging` database and `log` collection.

For the `log_processor` script the user executing the script will need to be able to read the database audit log.

For the `config_watcher` script the user will need to have `read` privileges on the `config.appState` collection within the `cloudconf` database in the Ops Manager application database.

For the `event_watcher` script the user will need to have `read` privileges on the `data.events` collection within the `mmsdb` database in the Ops Manager application database.