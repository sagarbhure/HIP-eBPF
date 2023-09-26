'''
ROOT COMMAND:python3 lesson3.py
USER COMMAND: clone, pwd

Program Description:
This program traces new processes via sys_clone() but introduces additional concepts:
1. prog =: This time, we declare the C program as a variable and reference it later. This approach is useful when you need to incorporate string substitutions based on command-line arguments.
2. hello(): Instead of using the kprobe__ shortcut, we declare a C function named hello(). All C functions declared in the BPF program are expected to be executed on a probe and must take a pt_reg* ctx as the first argument. If you need to define helper functions that won't be executed on a probe, they should be defined as static inline and may require the _always_inline function attribute for compiler optimization.
3. b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello"): This line creates a kprobe for the kernel clone system call function and associates it with our defined hello() function. You can use attach_kprobe() multiple times to link your C function to multiple kernel functions.
4. b.trace_fields(): This function returns a fixed set of fields from trace_pipe, similar to trace_print(). While handy for experimentation, for more robust tooling, it's advisable to transition to using BPF_PERF_OUTPUT().

USAGE:
1. Compile and load this BPF program.
2. Execute the program.
3. Observe the trace output when new processes are created via sys_clone().

'''

from __future__ import print_function
from bcc import BPF
prog = """
int hello(void *ctx) {
  bpf_trace_printk("Hello, World!\\n");
  return 0;
}
"""
b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello")
print("PID MESSAGE")
b.trace_print(fmt="{1} {5}")
