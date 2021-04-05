#!/usr/bin/env python
# coding=utf-8
#!/usr/bin/python

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse

# arguments
examples = """examples:
    ./runqlat            # summarize run queue latency as a histogram //运行队列的所有进程调度信息
    ./runqlat -p 185     # trace PID 185 only  //跟踪185进程
"""
parser = argparse.ArgumentParser(
    description="Summarize run queue (scheduler) latency as a histogram",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-m", "--milliseconds", action="store_true",
    help="millisecond histogram")
parser.add_argument("-P", "--pids", action="store_true",
    help="print a histogram per process ID")
# PID options are --pid and --pids, so namespaces should be --pidns (not done
# yet) and --pidnss:
parser.add_argument("--pidnss", action="store_true",
    help="print a histogram per PID namespace")
parser.add_argument("-L", "--tids", action="store_true",
    help="print a histogram per thread ID")
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("interval", nargs="?", default=99999999,
    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
    help="number of outputs")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
countdown = int(args.count)
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
typedef struct pid_key {
    u64 id;    
    u64 slot;
} pid_key_t;

typedef struct pidns_key {
    u64 id;    
    u64 slot;
} pidns_key_t;

struct data_t {
    u64 ts;
    u64 latency;  //时延
    int cpu;
    int len;
};

struct rq_partial {
    raw_spinlock_t lock;
    unsigned int nr_running;  //就绪和运行进程的数量
};

struct cfs_rq {
    struct load_weight load;
    unsigned int nr_running;  //CFS运行队列调度实体数量，se入队时加1，se出队时减1
    unsigned int h_nr_running; //CFS运行队列调度实体数量     
    unsigned int idle_h_nr_running; //记录idle调度实体数量

    u64 exec_clock;
    u64 min_vruntime;

#ifndef CONFIG_64BIT

    u64 min_vruntime_copy;

#endif

    struct rb_root_cached tasks_timeline;
    struct sched_entity *curr;
    struct sched_entity *next;
    struct sched_entity *last;
    struct sched_entity *skip;

#ifdef  CONFIG_SCHED_DEBUG

    unsigned int nr_spread_over;

#endif

#ifdef CONFIG_SMP
    
    struct sched_avg avg;
#ifndef CONFIG_64BIT

    u64 load_last_update_time_copy;

#endif

    struct {
        raw_spinlock_t  lock ____cacheline_aligned;
        int nr;
        unsigned long load_avg;
        unsigned long util_avg;
        unsigned long runnable_avg;
    } removed;

#ifdef CONFIG_FAIR_GROUP_SCHED

    unsigned long tg_load_avg_contrib;
    long propagate;
    long prop_runnable_sum;
    unsigned long h_load;
    u64 last_h_load_update;
    struct sched_entity *h_load_next;

#endif 
#endif 

#ifdef CONFIG_FAIR_GROUP_SCHED
    struct rq *rq;   
    int on_list;
    struct list_head leaf_cfs_rq_list;
    struct task_group *tg;  

#ifdef CONFIG_CFS_BANDWIDTH

    int runtime_enabled;
    s64 runtime_remaining;

    u64 throttled_clock;
    u64 throttled_clock_task;
    u64 throttled_clock_task_time;
    int throttled;
    int throttle_count;
    struct list_head throttled_list;

#endif 
#endif 
};

BPF_HASH(start, u32);
BPF_PERF_OUTPUT(events);

STORAGE

//记录进程的运行时间增量
static int trace_enqueue(u32 tgid, u32 pid)
{
    if (FILTER || pid == 0)
        return 0;
    u64 ts = bpf_ktime_get_ns();
    start.update(&pid, &ts);
    return 0;
}
"""

#通过tracepoint的形式追踪进程调度，并记录运行时间
bpf_text_raw_tp ="""
//获取trace_sched_wakeup函数中的信息
RAW_TRACEPOINT_PROBE(sched_wakeup)
{
    // TP_PROTO(struct task_struct *p)
    struct task_struct *p = (struct task_struct *)ctx->args[0];
    return trace_enqueue(p->tgid, p->pid);
}

//获取trace_sched_wakeup_new函数ctx中的信息
RAW_TRACEPOINT_PROBE(sched_wakeup_new)
{
    // TP_PROTO(struct task_struct *p)
    struct task_struct *p = (struct task_struct *)ctx->args[0];
    return trace_enqueue(p->tgid, p->pid);
}

//获取trace_sched_switch函数ctx中的信息
RAW_TRACEPOINT_PROBE(sched_switch)
{
    struct task_struct *prev = (struct task_struct *)ctx->args[1];
    struct task_struct *next = (struct task_struct *)ctx->args[2];
    u32 pid, tgid;
    struct data_t data;

    if (prev->state == TASK_RUNNING) {
        tgid = prev->tgid;
        pid = prev->pid;
        if (!(FILTER || pid == 0)) {
            u64 ts = bpf_ktime_get_ns();
            start.update(&pid, &ts);
        }
    }

    tgid = next->tgid;
    pid = next->pid;
    if (FILTER || pid == 0)
        return 0;

    u64 *tsp, delta;
    tsp = start.lookup(&pid);
    if (tsp == 0) {
        return 0;   // missed enqueue
    }
    delta = bpf_ktime_get_ns() - *tsp;

    FACTOR
    STORE

    start.delete(&pid);
    //获取时间信息
    data.ts = bpf_ktime_get_ns();
    data.latency = delta;

    struct task_struct *task = NULL;
    task = (struct task_struct *)bpf_get_current_task();
    struct rq_partial *my_q = NULL;
    //当前处理的rq，即进程队列
    my_q = (struct rq_partial *)task->se.cfs_rq->rq;
    //系统中可运行状态的进程数目
    data.len = my_q->nr_running; 
    //当前cpu编号
    data.cpu = task->cpu;
    //将数据传到用户态
    events.perf_submit(ctx, &data, sizeof(data));    
    return 0;
}
"""

is_support_raw_tp = BPF.support_raw_tracepoint()
bpf_text += bpf_text_raw_tp

# code substitutions
if args.pid:
    # pid from userspace point of view is thread group from kernel pov
    bpf_text = bpf_text.replace('FILTER', 'tgid != %s' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER', '0')
if args.milliseconds:
    bpf_text = bpf_text.replace('FACTOR', 'delta /= 1000000;')
    label = "msecs"
else:
    bpf_text = bpf_text.replace('FACTOR', 'delta /= 1000;')
    label = "usecs"
if args.pids or args.tids:
    section = "pid"
    pid = "tgid"
    if args.tids:
        pid = "pid"
        section = "tid"
    bpf_text = bpf_text.replace('STORAGE',
        'BPF_HISTOGRAM(dist, pid_key_t);')
    bpf_text = bpf_text.replace('STORE',
        'pid_key_t key = {.id = ' + pid + ', .slot = bpf_log2l(delta)}; ' +
        'dist.increment(key);')
elif args.pidnss:
    section = "pidns"
    bpf_text = bpf_text.replace('STORAGE',
        'BPF_HISTOGRAM(dist, pidns_key_t);')
    bpf_text = bpf_text.replace('STORE', 'pidns_key_t key = ' +
        '{.id = prev->nsproxy->pid_ns_for_children->ns.inum, ' +
        '.slot = bpf_log2l(delta)}; dist.increment(key);')
else:
    section = ""
    bpf_text = bpf_text.replace('STORAGE', 'BPF_HISTOGRAM(dist);')
    bpf_text = bpf_text.replace('STORE',
        'dist.increment(bpf_log2l(delta));')
if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# load BPF program
bpf_handle = BPF(text=bpf_text)
# output
exiting = 0 if args.interval else 1
dist = bpf_handle.get_table("dist")

print("%-18s%-20s%22s%20s%15s" % ("BTIME(s)","SYSTIME(s)","RUNQUEUE_LATENCY","RUNQUEUE_LEN","CPU"))
start = 0

#用户态处理函数
def print_event(cpu, data, size):
    global start
    event = bpf_handle["events"].event(data)
    if start == 0:
            start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    print("%-18.5f%-16.2f%18d%20d%11d" % (time_s, event.ts, event.latency, event.len, event.cpu))
    data = [{"measurement":"process_sched","tags":["glob"],"fields":{"btime":time_s, "queue_len":event.len,"on_cpu":event.cpu,"latency":event.latency}}]
    client.write_points(data)

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

#注册用户态处理回调函数
bpf_handle["events"].open_perf_buffer(print_event)
while 1:
    try:
        sleep(1)
        bpf_handle.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
