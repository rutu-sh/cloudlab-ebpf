# Simple Tracepoint Hook 

This experiment demonstrates how to write an eBPF program that hooks into a tracepoint (syscall/sys_enter_execve) and writes the event data to a ring buffer, which is then read from the userspace using Golang and printed to the console.

This program creates two resources: 
1. `event_ringbuf`: ring buffer map to store the event data
2. `get_pid_execve`: eBPF program to hook on the `sys_enter_execve` tracepoint and write the event data to the ring buffer. 

## Usage 

Build using 

```bash
go build
```

Run using 

```bash
suod ./simple-tracepoint-hook
```
