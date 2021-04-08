#!/usr/bin/python
#encoding: utf-8
from bcc import BPF
from time import sleep
from multiprocessing import cpu_count
from const import DatabaseType
from init_db import influx_client
from db_modules import write2db
from datetime import datetime
#记录每秒钟每个核的调度次数，仅限四核机器
prog_text="""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
struct key_t {
    u32 prev_pid;
    u32 curr_pid;
    u32 cpu;
};

BPF_HASH(stats, struct key_t, u64, 1024);
int count_sched(struct pt_regs *ctx, struct task_struct *prev) {
    struct key_t key = {};
    u64 zero = 0, *val;
    key.curr_pid = bpf_get_current_pid_tgid();
    key.prev_pid = prev->pid;
    key.cpu = bpf_get_smp_processor_id();
    // could also use `stats.increment(key);`
    val = stats.lookup_or_try_init(&key, &zero);
    if (val) {
      (*val)++;
    }
    return 0;
}
"""

class lmp_data_cpu_core_4(object):
    def __init__(self, a, b, c, d, e, f):
        self.time = a
        self.glob = b
        self.cpu_0 = c
        self.cpu_1 = d
        self.cpu_2 = e 
        self.cpu_3 = f 

data_struct = {"measurement": 'core_dispacher_times',
               "time": [],
               "tags": ['glob', ],
               "fields": ['cpu_0', 'cpu_1', 'cpu_2', 'cpu_3']}

#count cpu dipacher
def count_cpu():
    b = BPF(text=prog_text)
    b.attach_kprobe(event="finish_task_switch", fn_name="count_sched")
    sleep(1)
    dispatch_count = {0:0, 1:0, 2:0, 3:0}
    for k, v in b["stats"].items():
        dispatch_count[k.cpu]+=1 
    print(dispatch_count[0], "  ", dispatch_count[1],"     ", dispatch_count[2], "         ", dispatch_count[3]);
    test_data = lmp_data_cpu_core_4(datetime.now().isoformat(), 'glob', dispatch_count[0], 
    dispatch_count[1], dispatch_count[2], dispatch_count[3])
    write2db(data_struct, test_data, influx_client, DatabaseType.INFLUXDB.value)
while 1:
    count_cpu()
