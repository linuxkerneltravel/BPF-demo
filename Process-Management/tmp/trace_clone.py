from __future__ import print_function
from bcc import BPF
from ctypes import c_ushort, c_int, c_ulonglong
from time import sleep
from sys import argv



prog="""
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>
struct key_t {
    u32 cpu ;
    u32 pid ;
    char comm[TASK_COMM_LEN];
};

BPF_HASH(start, struct key_t, u64);
BPF_HASH(end, struct key_t, u64);

int trace_start(struct pt_regs* ctx) {
    u64 ts ;
    struct key_t key = {} ;
    key.pid = bpf_get_current_pid_tgid() ;
    key.cpu = bpf_get_smp_processor_id();
    bpf_get_current_comm(&key.comm, sizeof(key.comm));

    ts = bpf_ktime_get_ns();
    start.update(&key, &ts);
    return 0 ;
}

int trace_end(struct pt_regs* ctx) {

    u64*tsp, delta ;
    u64 value = 0 ;
    struct key_t key ;
    key.pid = bpf_get_current_pid_tgid() ;
    key.cpu = bpf_get_smp_processor_id() ;
    bpf_get_current_comm(&key.comm, sizeof(key.comm));

    tsp = start.lookup_or_try_init(&key, &value);

    if(!tsp) {
        delta = bpf_ktime_get_ns()-*tsp ;
        end.update(&key, &delta) ;
        start.delete(&key) ;
    }
    return 0 ; 
}
"""
b = BPF(text=prog)

def trace_clone_info():
    b.attach_kprobe(event="schedule", fn_name="trace_start")
    b.attach_kretprobe(event="schedule", fn_name="trace_end")
    for k, v in b['end'].items():
        print("%5d%5d%12s%20d"%(key.cpu, key.pid, key.comm, v))

while 1:
    sleep(1)
    trace_clone_info()