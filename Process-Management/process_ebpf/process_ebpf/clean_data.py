#!/usr/bin/env python
# coding=utf-8
file = open("config.json", "rb")
fileJson = json.load(file)
db_port = fileJson['db_port']
db_host = fileJson['db_host']
db_user = fileJson['user']
db_passwd = fileJson['password']
process_db_name = fileJson['process_db_name']
file.close() 
#连接数据库
client = InfluxDBClient(db_host, db_port, db_user, db_passwd, process_db_name)

