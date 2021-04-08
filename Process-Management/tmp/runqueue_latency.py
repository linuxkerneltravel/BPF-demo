#!/usr/bin/python
#encoding: utf-8
from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse
from const import DatabaseType
from init_db import influx_client
from db_modules import write2db
from datetime import datetime
#度量任务在等待一个回合的运行队列上的延时，us输出
#内核会通过try_to_wake_up把任务唤醒, 这会涉及到这sched_wakeup和sched_waking两个tracepoint.
#sched_waking和sched_wakeup在wakeup task过程中肯定都会发生, sched_waking事件在ttwu开始的时候触发, 
# 而sched_wakeup在ttwu结束的时候触发. 一般情况下, 这2个tracepoint触发的时间非常靠近, 但是不排除中间会有较大gap.
# sched_wakeup_new. 同sched_wakeup, 但针对的是新创建的任务

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>

BPF_HASH(start, u32);
BPF_HASH(lentacy, u32, u64, 1024) ;

// record enqueue timestamp
static int trace_enqueue(u32 tgid, u32 pid)
{
    if (pid == 0)
        return 0;
    u64 ts = bpf_ktime_get_ns();
    start.update(&pid, &ts);
    return 0;
}
"""

bpf_text_raw_tp = """
RAW_TRACEPOINT_PROBE(sched_wakeup)
{
    // TP_PROTO(struct task_struct *p)
    struct task_struct *p = (struct task_struct *)ctx->args[0];
    return trace_enqueue(p->tgid, p->pid);
}

RAW_TRACEPOINT_PROBE(sched_wakeup_new)
{
    // TP_PROTO(struct task_struct *p)
    struct task_struct *p = (struct task_struct *)ctx->args[0];
    return trace_enqueue(p->tgid, p->pid);
}

RAW_TRACEPOINT_PROBE(sched_switch)
{
    // TP_PROTO(bool preempt, struct task_struct *prev, struct task_struct *next)
    struct task_struct *prev = (struct task_struct *)ctx->args[1];
    struct task_struct *next = (struct task_struct *)ctx->args[2];
    u32 cpu ;
    u32 pid, tgid;
    if (prev->state == TASK_RUNNING) {
        tgid = prev->tgid;
        pid = prev->pid;
        if (!(pid == 0)) {
            u64 ts = bpf_ktime_get_ns();
            start.update(&pid, &ts);
        }
    }
    tgid = next->tgid;
    pid = next->pid;
    if (pid == 0)
        return 0;
    u64 *tsp, delta;

    tsp = start.lookup(&pid);
    if (tsp == 0) {
        return 0;   
    }
    delta = bpf_ktime_get_ns() - *tsp;
    delta /= 1000;
    cpu = bpf_get_smp_processor_id();
    lentacy.update(&cpu, &delta);
    start.delete(&pid);
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

data_struct = {"measurement": 'runqueue_lentacy',
               "time": [],
               "tags": ['glob', ],
               "fields": ['cpu_0', 'cpu_1', 'cpu_2', 'cpu_3']}

is_support_raw_tp = BPF.support_raw_tracepoint()
bpf_text += bpf_text_raw_tp
def queue_lentacy():
    b = BPF(text=bpf_text)
    dispatch_lentacy = {0:0, 1:0, 2:0, 3:0}
    sleep(1)
    tmp = b.get_table("lentacy")
    for k, v in tmp.items():
        dispatch_lentacy[k.value] = v.value
    test_data = lmp_data_cpu_core_4(datetime.now().isoformat(), 'glob', dispatch_lentacy[0], 
    dispatch_lentacy[1], dispatch_lentacy[2], dispatch_lentacy[3])
    print(dispatch_lentacy[0], "  ", dispatch_lentacy[1],"     ", dispatch_lentacy[2], "         ", dispatch_lentacy[3])
    write2db(data_struct, test_data, influx_client, DatabaseType.INFLUXDB.value)
while 1:
    queue_lentacy()