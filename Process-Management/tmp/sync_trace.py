from __future__ import print_function
from bcc import BPF

b = BPF(text="""

#include <uapi/linux/ptrace.h>

BPF_HASH(last);

int do_trace(struct pt_regs*ctx) {
    u64 ts, *tsp, delta, key=0 ;

    tsp = last.lookup(&key) ;

    if(tsp != NULL) {
        delta = bpf_ktime_get_ns() - *tsp ;
            bpf_trace_printk("%d\\n", delta) ;
        if(delta < 1000000000) {
            bpf_trace_printk("%d\\n", delta/1000000) ;
        }
        last.delete(&key) ;
    }
    ts = bpf_ktime_get_ns() ;
    last.update(&key, &ts) ;
}
""")
b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="do_trace")

dist = b.get_table("last")

start = 0
while 1:
    for k, v in dist.items() :
        print("%d\n"%(v.value))
    (task, pid, cpu, flags, ts, ms) = b.trace_fields() 
    if start == 0:
        start == ts
    ts = ts-start 
    print("at timr %.5f s:  mutiple clone detected, last %s ms ago"%(ts, ms))
