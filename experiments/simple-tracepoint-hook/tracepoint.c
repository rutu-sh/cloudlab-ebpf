//go:build ignore

#include<linux/bpf.h>
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
*/
struct tp_sys_enter_execve_ctx {
    unsigned long long pad; 
    // padding: common_type + common_flags + common_preempt_count + common_pid = 2 + 1 + 1 + 4 = 8 bytes = unsigned long long
    
    int syscall_nr; // 4 bytes
    long filename_ptr; // 8 bytes
    long argv_ptr; // 8 bytes
    long envp_ptr; // 8 bytes
};

struct event {
    __u64 timestamp;
    __u32 pid;
    char filename[512];
};


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF); 
    __uint(max_entries, 256*1024);
} ringbuf SEC(".maps");

// get the format at: /sys/kernel/tracing/events/syscalls/sys_enter_execve/format
SEC("tp/syscalls/sys_enter_execve") 
int get_pid_execve(struct tp_sys_enter_execve_ctx *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct event *evt = bpf_ringbuf_reserve(&ringbuf, sizeof(struct event), 0);
    if (! evt) {
        bpf_printk("bpf_ringbuf_reserve failed\n");
    }
    evt->timestamp = bpf_ktime_get_tai_ns();
    evt->pid = pid;
    bpf_probe_read_user_str(evt->filename, sizeof(evt->filename), (void *)ctx->filename_ptr);
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

