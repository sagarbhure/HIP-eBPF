'''
ROOT COMMAND: python3 lesson2.py
USER COMMAND: sync


Description:
   This program traces the sys_sync() kernel function and prints "sys_sync() called" when it runs.
   To begin tracing, execute this program. It will display "Tracing sys_sync()... Ctrl-C to end."
   Then, test by running the 'sync' command in another session while this program is tracing.

USAGE:
   1. Compile and load this BPF program.
   2. Execute the program.
   3. Run 'sync' in another session to trigger sys_sync() and observe the trace output.
'''

#!/usr/bin/python
from bcc import BPF
print('Tracing sys_sync()... Ctrl-C to end.')
BPF(text='int kprobe__sys_sync(void *ctx) { bpf_trace_printk("sys_sync() called\\n"); return 0; }').trace_print()
