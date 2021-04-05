#!/usr/bin/python
# -*- coding:utf-8 -*-


from __future__ import print_function
from bcc import BPF, PerfType, PerfSWConfig
from time import sleep, strftime
from tempfile import NamedTemporaryFile
from time import sleep
import signal
import argparse
import json
from db_module import write2db
import time
import psutil
import random
import json
import os
from influxdb import InfluxDBClient

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

frequency = 20
interval = 99999999

# init BPF program
b = BPF(src_file="runqlen.c")
b.attach_perf_event(ev_type=PerfType.SOFTWARE,
    ev_config=PerfSWConfig.CPU_CLOCK, fn_name="do_perf_event",
    sample_period=0, sample_freq=frequency)


# data structure from template
class lmp_data(object):
    def __init__(self,a,b):
            self.glob = a
            self.runqlen = b

data_struct = {"measurement":'runqlenTable',
                "tags":['glob'],
                "fields":['runqlen']}

def print_event(cpu, data, size):
    global start
    event = b["result"].event(data)
    test_data = lmp_data('glob', event.len)
    write2db(data_struct, test_data, client)

b["result"].open_perf_buffer(print_event)
while 1:
    b.perf_buffer_poll()
    try:
        pass
    except KeyboardInterrupt:
        exit()
