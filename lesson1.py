'''
COMMAND: python3 lesson1.py

DESCRIPTION:
While running some commands (eg, “ls”) in another session. It should print “Hello, World!” for new processes. 

There are six key takeaways from this:
-  text='...': This declaration defines an inline BPF program, which is written in C.
-  kprobe__sys_clone(): This is a shorthand notation for kernel dynamic tracing using kprobes. If a C function starts with kprobe__, the remainder is treated as the name of the kernel function to instrument. In this instance, it's sys_clone().
-  void *ctx: The variable ctx has arguments, but since they are not utilized here, it is simply cast to void *.
-  bpf_trace_printk(): This is a basic kernel feature for emulating printf() functionality to the trace_pipe at /sys/kernel/debug/tracing/trace_pipe. It serves well for quick examples but comes with some limitations: it supports a maximum of three arguments, allows only one %s specifier, and trace_pipe is globally shared, leading to conflicts in output for concurrent programs. A better alternative is available through BPF_PERF_OUTPUT(), which will be discussed later.
-  return 0;: This statement is a necessary formality. For an explanation of why it's required, refer to issue #139.
-  .trace_print(): This is a bcc function that reads the trace_pipe and displays the output.
'''

from bcc import BPF
# This may not work for 4.17 on x64, you need replace kprobe__sys_clone with kprobe____x64_sys_clone
BPF(text='int kprobe__sys_clone(void *ctx) { bpf_trace_printk("Hello, World!\\n"); return 0; }').trace_print()
