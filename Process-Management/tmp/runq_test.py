from __future__ import print_function
from bcc import BPF, PerfType, PerfSWConfig
from time import sleep
import argparse

parser = argparse.ArgumentParser()

parser.add_argument("interval", nargs="?", default=99999999,
    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
    help="number of outputs")

args = parser.parse_args()

countdown = int(args.count)

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/spinlock_types.h>

typedef struct cfs_runq {
    struct load_weight load;
    unsigned int nr_running;
    unsigned int h_nr_running;
} cfs_part;

typedef struct runq {
    raw_spinlock_t  lock;
    unsigned int    nr_running;
} rq_part;

struct data_t {
    u32 cpu;
    u32 pid;
    u32 cfs_nr;
    u32 cfs_h_nr;
    u32 rq_nr;
};

BPF_PERF_OUTPUT(events);

int do_runqlen(struct pt_regs *ctx)
{
    int cpu = bpf_get_smp_processor_id();
    if (cpu) {
        return 0;
    }

    struct data_t data = {};

    struct task_struct *p = (struct task_struct *)bpf_get_current_task();
    cfs_part *my_q = (cfs_part *)p->se.cfs_rq;
    unsigned int runq_1 = my_q->nr_running;
    unsigned int runq_2 = my_q->h_nr_running;

    rq_part *r = (rq_part *)(ctx->ax);
    unsigned int runq_3 = r->nr_running;

    data.cpu = bpf_get_smp_processor_id();
    data.pid = bpf_get_current_pid_tgid() << 32;
    data.cfs_nr = runq_1;
    data.cfs_h_nr = runq_2;
    data.rq_nr = runq_3;

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_kprobe(event="pick_next_task_fair", fn_name="do_runqlen")

print("Tracing run queue length ... Hit Ctrl-C to end.")

def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("%-6d %-6d %-6d %-6d %-6d" % (event.cpu, event.pid, event.cfs_nr, event.cfs_h_nr,
        event.rq_nr))

b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
