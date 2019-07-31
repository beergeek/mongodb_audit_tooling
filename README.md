# MongoDB Auditing Tools

This repo contains several Python scripts designed to retrieve logging data from MongoDB databases and from Ops Manager (via change streams).

The following tools are in this repository:

* log_processor (to process the audit logs from MongoDB instance and forward to a MongoDB audit database)
* config_watcher (to retrieve configuration changes to Ops Manager and forward to a MongoDB audit database)
* event_watcher (to retrieve audit events from Ops Manager and forward to a MongoDB audit database)

# Setup

## log_processor

This script reads the MongoDB audit log and sends each entry, after formatting, to a MongoDB 'audit' database.

The data from the MongoDB databases must be in JSON format and written out to a file. The process for doing this can be found in the [MongoDB documentation](https://docs.mongodb.com/manual/core/auditing/).

The script uses a configuration file (`log_processor.conf`) that must reside in the same location as the script.

The configuration file has the following format (__NOTE__: none of the string have quotes):

```shell
[audit_db]
connection_string=mongodb://<USERNAME>:<PASSWORD>@<HOST>:<PORT>/?replicaSet=<REPLICA_SET_NAME>
timeout=<TIMEOUT_VALUE>

[general]
debug=<BOOLEAN_VALUE>
elevated_ops_events=<COMMA_SEPARATED_LIST>
elevated_app_events=<COMMA_SEPARATED_LIST>
```

Both sections are mandatory, as well as the `connection_string` option, but the `timeout` and `debug` are option (having defaults of 1000 and False respectivetly). The `elevated_app_events` and `elevated_ops_events` are comma separated lists of events that will be either tagged as `APP EVENT` or `OPS EVENT` respectively for easy querying in the audit database.

## config_watcher

This script retrieve Ops Manager configuration modifications from the Ops Manager application database via a change stream on the `cloudconf.config.appState` database/collection. The events are formatted and inserted into a MongoDB 'audit' database.

The script uses a configuration file (`config_watcher.conf`) that must reside in the same location as the script.

The configuration file has the following format (__NOTE__: none of the string have quotes):

```shell
[audit_db]
connection_string=mongodb://<USERNAME>:<PASSWORD>@<HOST>:<PORT>/?replicaSet=<REPLICA_SET_NAME>
timeout=<TIMEOUT_VALUE>

[ops_manager_db]
connection_string=mongodb://<USERNAME>:<PASSWORD>@<HOST>:<PORT>/?replicaSet=<REPLICA_SET_NAME>
timeout=<TIMEOUT_VALUE>
event_pipeline=<MONGODB_PIPELINE>

[general]
debug=<BOOLEAN_VALUE>
```

Both sections are mandatory, as well as the `connection_string` option, but the `timeout` and `debug` are option (having defaults of 1000 and False respectivetly). The optional `event_pipeline` is a change stream pipeline to filter events.

## event_watcher

This script retrieve events from the Ops Manager application database via a change stream on the `mmsdb.data.events` database/collection. The events are formatted and inserted into a MongoDB 'audit' database.

The script uses a configuration file (`event_watcher.conf`) that must reside in the same location as the script.

The configuration file has the following format (__NOTE__: none of the string have quotes):

```shell
[audit_db]
connection_string=mongodb://<USERNAME>:<PASSWORD>@<HOST>:<PORT>/?replicaSet=<REPLICA_SET_NAME>
timeout=<TIMEOUT_VALUE>

[ops_manager_db]
connection_string=mongodb://<USERNAME>:<PASSWORD>@<HOST>:<PORT>/?replicaSet=<REPLICA_SET_NAME>
timeout=<TIMEOUT_VALUE>
event_pipeline=<MONGODB_PIPELINE>

[general]
debug=<BOOLEAN_VALUE>
```

Both sections are mandatory, as well as the `connection_string` option, but the `timeout` and `debug` are option (having defaults of 1000 and False respectivetly). The optional `event_pipeline` is a change stream pipeline to filter events.

## Permissions

For all of the scripts, the user that is writing to the MongoDB audit database must have `readWrite` permissions on the `logging` database and `log` collection.

For the `log_processor` script the user executing the script will need to be able to read the database audit log.

For the `config_watcher` script the user will need to have `read` privileges on the `config.appState` collection within the `cloudconf` database in the Ops Manager application database.

For the `event_watcher` script the user will need to have `read` privileges on the `data.events` collection within the `mmsdb` database in the Ops Manager application database.