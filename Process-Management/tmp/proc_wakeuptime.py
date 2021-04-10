#!/usr/bin/python
#encoding:utf-8
# wakeuptime    Summarize(总结) sleep to wakeup time by waker kernel stack
#               For Linux, uses BCC, eBPF.

#一个进程从offcpu到再次被wake的时间
from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
from time import sleep, strftime
import signal
import errno
from sys import stderr
from const import DatabaseType
from init_db import influx_client
from db_modules import write2db
from datetime import datetime

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MINBLOCK_US    0
#define MAXBLOCK_US    2147483646

struct key_t {
    int  w_k_stack_id;
    char waker[TASK_COMM_LEN];
    char target[TASK_COMM_LEN];
};

BPF_HASH(counts, struct key_t);
BPF_HASH(start, u32);
BPF_STACK_TRACE(stack_traces, 1024);

int offcpu(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    struct task_struct *p = (struct task_struct *) bpf_get_current_task();
    u64 ts;

    ts = bpf_ktime_get_ns();
    start.update(&pid, &ts);
    return 0;
}

int waker(struct pt_regs *ctx, struct task_struct *p) {
    u32 pid = p->pid;
    u64 delta, *tsp, ts;

    tsp = start.lookup(&pid);
    if (tsp == 0)
        return 0;        // missed start
    start.delete(&pid);
    
    delta = bpf_ktime_get_ns() - *tsp;
    delta = delta / 1000;
    if ((delta < MINBLOCK_US) || (delta > MAXBLOCK_US))
        return 0;

    struct key_t key = {};

    key.w_k_stack_id = stack_traces.get_stackid(ctx, 0);
    bpf_probe_read_kernel(&key.target, sizeof(key.target), p->comm);
    bpf_get_current_comm(&key.waker, sizeof(key.waker));

    counts.increment(key, delta);
    return 0;
}
"""



class lmp_data(object):
    def __init__(self, internal_time, glob, process_name, lantency):
        self.glob = glob
        self.internal_time = internal_time
        self.process_name = process_name
        self.lantency = lantency

data_struct = {"measurement": 'core_dispacher_times',
               "time": [],
               "tags": ['glob', ],
               "fields": ['process_name', 'lantency']}

def wakeuptime():
    # initialize BPF
    b = BPF(text=bpf_text)
    b.attach_kprobe(event="schedule", fn_name="offcpu")
    b.attach_kprobe(event="try_to_wake_up", fn_name="waker")
    matched = b.num_open_kprobes()
    if matched == 0:
        print("0 functions traced. Exiting.")
        exit()
    while (1):
        try:
            sleep(2)
        except KeyboardInterrupt:
        # as cleanup can take many seconds, trap Ctrl-C:
            exit()
        missing_stacks = 0
        has_enomem = False
        counts = b.get_table("counts")
        stack_traces = b.get_table("stack_traces")
        for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
            # handle get_stackid errors
            # check for an ENOMEM error
            if k.w_k_stack_id == -errno.ENOMEM:
                missing_stacks += 1
                continue
            printb(b"    %-16s %s" % (b"waker:", k.waker))
            print("        %d\n" % v.value)
            test_data = lmp_data(datetime.now().isoformat(), 'glob', k.waker, v.value)
            write2db(data_struct, test_data, influx_client, DatabaseType.INFLUXDB.value)
        counts.clear()
wakeuptime()