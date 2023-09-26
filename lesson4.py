'''
   Program Description:
   This program measures the time elapsed since the last call to the do_sync function and prints output if it was called within the past second. 
   Multiple consecutive calls to do_sync will print output for the 2nd and 3rd calls, simulating the behavior of 'sync;sync;sync'.

   Things to Learn:
   1. bpf_ktime_get_ns(): This function returns the current time in nanoseconds, allowing precise time measurements.
   2. BPF_HASH(last): A BPF map object is created with the name "last," and it is of type hash (associative array). The map has default key and value types of u64.
   3. key = 0: This program uses a single key/value pair in the "last" hash, where the key is hardwired to zero.
   4. last.lookup(&key): This function looks up the key in the "last" hash and returns a pointer to its value if it exists; otherwise, it returns NULL. The key is passed in as an address to a pointer.
   5. if (tsp != NULL) {: The verifier requires that pointer values derived from a map lookup must be checked for null value before dereferencing and using them.
   6. last.delete(&key): This line deletes the key from the "last" hash. It is currently required due to a kernel bug in .update() (fixed in 4.8.10).
   7. last.update(&key, &ts): This function associates the value in the 2nd argument with the key in the "last" hash, overwriting any previous value. This records the timestamp of the last call to do_sync.

   Usage:
   1. Compile and load this BPF program.
   2. Execute the program.
   3. Call the do_sync function or simulate multiple consecutive calls to observe the time elapsed between calls.

   Note: This program provides insights into measuring time intervals using BPF and managing data with BPF maps.
'''
#!/usr/bin/python

from __future__ import print_function
from bcc import BPF

# load BPF program
b = BPF(text="""

BPF_HASH(last);

int do_trace(struct pt_regs *ctx) {
    u64 ts, *tsp, delta, key = 0;
    // attempt to read stored timestamp
    tsp = last.lookup(&key);
    if (tsp != 0) {
        delta = bpf_ktime_get_ns() - *tsp;
        if (delta < 1000000000) {
            // output if time is less than 1 second
            bpf_trace_printk("%d\\n", delta / 1000000);
        }
        last.delete(&key);
    }
    // update stored timestamp
    ts = bpf_ktime_get_ns();
    last.update(&key, &ts);
    return 0;
}
""")
b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="do_trace")
print("Tracing for quick sync's... Ctrl-C to end")
# format output
start = 0
while 1:
    (task, pid, cpu, flags, ts, ms) = b.trace_fields()
    if start == 0:
        start = ts
    ts = ts - start
    print("At time %.2f s: multiple syncs detected, last %s ms ago" % (ts, ms))
