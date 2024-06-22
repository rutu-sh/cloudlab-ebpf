//go:build ignore
#include "vmlinux.h"
// #include<linux/bpf.h>
#include<bpf/bpf_core_read.h>
#include<bpf/bpf_helpers.h>


// The tracepoint to hook is sys_enter_execve
// The format of the tracepoint is defined in /sys/kernel/tracing/events/syscalls/sys_enter_execve/format
/*
    name: sys_enter_execve
    ID: 716
    format:
        field:unsigned short common_type;	        offset:0;	size:2;	signed:0;
        field:unsigned char common_flags;	        offset:2;	size:1;	signed:0;
        field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
        field:int common_pid;	                    offset:4;	size:4;	signed:1;

        field:int __syscall_nr;	                    offset:8;	size:4;	signed:1;
        field:const char * filename;	            offset:16;	size:8;	signed:0;
        field:const char *const * argv;	            offset:24;	size:8;	signed:0;
        field:const char *const * envp;	            offset:32;	size:8;	signed:0;

    print fmt: "filename: 0x%08lx, argv: 0x%08lx, envp: 0x%08lx", ((unsigned long)(REC->filename)), ((unsigned long)(REC->argv)), ((unsigned long)(REC->envp))
    sudo cat /sys/kernel/debug/tracing/trace
*/
// struct tp_sys_enter_execve_ctx {
//     // unsigned long long pad; // padding: common_type + common_flags + common_preempt_count + common_pid = 2 + 1 + 1 + 4 = 8 bytes = unsigned long long
    
//     // int syscall_nr; // 4 bytes
//     // long filename_ptr; // 8 bytes
//     // long argv_ptr; // 8 bytes
//     // long envp_ptr; // 8 bytes
//     int __syscall_nr;
//     const char * filename_ptr;
//     const char *const * argv;
//     const char *const * envp;
// };

struct event {
    __u64 timestamp;
    __u32 pid;
    char filename[512];
};

// Define a ring buffer map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256*1024);
} event_ringbuf SEC(".maps");


// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

// get the format at: /sys/kernel/tracing/events/syscalls/sys_enter_execve/format
SEC("tp/syscalls/sys_enter_execve") 
int get_pid_execve(struct trace_event_raw_sys_enter *ctx) {
    bpf_printk("hooked sys_enter_execve\n");
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct event *evt = bpf_ringbuf_reserve(&event_ringbuf, sizeof(struct event), 0);
    if (! evt) {
        bpf_printk("bpf_ringbuf_reserve failed\n");
        return 1;
    }
    bpf_printk("pid: %d\n", pid);
    evt->timestamp = bpf_ktime_get_ns();
    evt->pid = pid;
    char *filename_ptr = (char*) BPF_CORE_READ(ctx, args[0]);
    if (bpf_probe_read_user_str(evt->filename, sizeof(evt->filename), filename_ptr) < 0){
        bpf_printk("bpf_probe_read_user_str failed\n");
        bpf_ringbuf_discard(evt, 0);
        return 1;
    }
    bpf_printk("trying to read filename\n");
    bpf_printk("filename: %s\n", evt->filename);
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
