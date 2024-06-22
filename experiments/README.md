# Experiments 

This directory contains the experiments that were run to evaluate the performance of the models.


## Experiments

| Experiment | Description | Reference |
|------------|-------------|-----------|
| XDP Packet Counter | A basic experiment to demonstrate how to load XDP program which writes to eBPF maps and read the map valuels from the userspace using Golang | [XDP Packet Counter](xdp-packet-counter/README.md) |
| Simple Tracepoint Hook | A basic experiment to demonstrate how to write an eBPF program that hooks into a tracepoint (syscall/sys_enter_execve) and writes the event data to a ring buffer, which is then read from the userspace using Golang and printed to the console | [Simple Tracepoint Hook](simple-tracepoint-hook/README.md) |