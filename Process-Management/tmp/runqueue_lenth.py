#!/usr/bin/python
#encoding:utf-8

from __future__ import print_function
from bcc import BPF, PerfType, PerfSWConfig
from time import sleep, strftime
import argparse
import threading
from const import DatabaseType
from init_db import influx_client
from db_modules import write2db
from datetime import datetime
#每个cpu核的进程运行队列的进程数目

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// Declare enough of cfs_rq to find nr_running, since we can't #import the
// header. This will need maintenance. It is from kernel/sched/sched.h:
struct cfs_rq_partial {
    struct load_weight load;
    unsigned long runnable_weight;
    unsigned int nr_running, h_nr_running;
};

struct key_t {
    unsigned int len;
    unsigned int cpu;
};


//存储数据
//BPF_PERF_OUTPUT(result);
BPF_HASH(dist, u32, u32, 10);

int do_perf_event(struct pt_regs *ctx)
{
    unsigned int len = 0;
    u32 data,cpu ;
    pid_t pid = 0;
    struct task_struct *task = NULL;
    struct cfs_rq_partial *my_q = NULL;

    task = (struct task_struct *)bpf_get_current_task();
    my_q = (struct cfs_rq_partial *)task->se.cfs_rq;
    len = my_q->nr_running;

    // if present. len 0 == idle, len 1 == one running task.
    if (len > 0)
        len--;

    data = len;
    cpu = bpf_get_smp_processor_id();
    dist.update(&cpu, &data);
    //result.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

b = BPF(text=bpf_text)
mp = {0:0, 1:0, 2:0, 3:0}
lock = threading.Lock()
frequency = 99

class lmp_data_cpu_core_4(object):
    def __init__(self, a, b, c, d, e, f):
        self.time = a
        self.glob = b
        self.cpu_0 = c
        self.cpu_1 = d
        self.cpu_2 = e 
        self.cpu_3 = f 

data_struct = {"measurement": 'queue_length',
               "time": [],
               "tags": ['glob', ],
               "fields": [ 'cpu_0', 'cpu_1', 'cpu_2', 'cpu_3']}

b.attach_perf_event(ev_type=PerfType.SOFTWARE,
    ev_config=PerfSWConfig.CPU_CLOCK, fn_name="do_perf_event",
    sample_period=0, sample_freq=frequency)

dist = b.get_table("dist")

def get_queue_length():
    for k, v in dist.items():
        mp[k.value] = v.value
        if(v.value == 0) :
            continue
        print(k.value, v.value)

timer = threading.Timer(1, get_queue_length)
timer.start()
while 1:
    sleep(1)
    tmp = mp
    test_data = lmp_data_cpu_core_4(datetime.now().isoformat(), 'glob', tmp[0], tmp[1], tmp[2], tmp[3])
    write2db(data_struct, test_data, influx_client, DatabaseType.INFLUXDB.value)

        
    
