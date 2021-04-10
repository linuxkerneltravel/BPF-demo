#!/usr/bin/python
#encoding: utf-8
from bcc import BPF
from const import DatabaseType
from init_db import influx_client
from db_modules import write2db
from time import sleep
import threading
from collections import Counter
from datetime import datetime


#记录系统调用thread_create的时间间隔和发生调用的进程
# define BPF program
prog = """
#include <linux/sched.h>

// define output data structure in C
struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
};

BPF_HASH(dist, struct data_t, u32);
//BPF_PERF_OUTPUT(events);

int do_trace(struct pt_regs *ctx) {
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    dist.increment(data);
    //events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""



class lmp_data(object):
    def __init__(self, internal_time, glob, process_name, count):
        self.glob = glob
        self.internal_time = internal_time
        self.process_name = process_name
        self.count = count 

data_struct = {"measurement":'thread_create_count',
               "time": [],
               "tags": ['glob', ],
               "fields": [ 'process_name', 'count']
            }

b = BPF(text=prog) 
def count_clone():
    count = 0
    b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="do_trace")
    for k, v in b['dist'].items():
        test_data = lmp_data(datetime.now().isoformat(), 'glob', proc_list[i], count_list[i])
        write2db(data_struct, test_data, influx_client, DatabaseType.INFLUXDB.value) 
while 1:
    count_clone()



