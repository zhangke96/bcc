#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# nfstop   Summarize NFS operation count
#           for Linux, uses BCC and eBPF
#
# USAGE: nfstop [-h] [-T] [-m] [-p PID] [interval] [count]
#
# 9-Nov-2024    Ke.Zhang     created this

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse
import pwd

# arguments
examples = """examples:
    ./nfstop 1 10           # all NFS operation 1 second summaries, 10 times
    ./nfstop -u username    # summarize NFS operation count for a user
"""
parser = argparse.ArgumentParser(
        description="Summarize NFS operation count",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples)
parser.add_argument("-u", "--user", help="output in user")
parser.add_argument("interval", nargs="?",
                    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
                    help="number of outputs")
parser.add_argument("--ebpf", action="store_true",
                    help=argparse.SUPPRESS)
args = parser.parse_args()
countdown = int(args.count)
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>

#define OP_NAME_LEN 8
typedef struct dist_key {
    char op[OP_NAME_LEN];
    u64 slot;
} dist_key_t;

struct stats_t {
    u64 getattr;
    u64 lookup;
    u64 open;
    u64 readdir;
    u64 read;
    u64 write;
};

enum op_type {
    OP_GETATTR,
    OP_LOOKUP,
    OP_OPEN,
    OP_READDIR,
    OP_READ,
    OP_WRITE,
};

// pid => stats or uid => stats
BPF_HASH(counts, u32, struct stats_t);

static int trace_return(struct pt_regs *ctx, enum op_type op)
{
    u64 *tsp;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    u64 uid_gid = bpf_get_current_uid_gid();
    u32 uid = uid_gid >> 32;
    u32 gid = (u32)uid_gid;

    u32 search_id = 0;
    bool pid_search = false;

    if (FILTER_UID)
        return 0;

    if (FILTER_PID) {
        search_id = pid;
    } else {
        search_id = uid;
    }

    struct stats_t *stats, zero = {};
    stats = counts.lookup_or_init(&search_id, &zero);
    if (!stats)
        return 0;
    switch (op) {
        case OP_GETATTR:
            stats->getattr++;
            break;
        case OP_LOOKUP:
            stats->lookup++;
            break;
        case OP_OPEN:
            stats->open++;
            break;
        case OP_READDIR:
            stats->readdir++;
            break;
        case OP_READ:
            stats->read++;
            break;
        case OP_WRITE:
            stats->write++;
            break;
    }
    
    return 0;
}

int trace_read_return(struct pt_regs *ctx)
{
    return trace_return(ctx, OP_READ);
}

int trace_write_return(struct pt_regs *ctx)
{
    char *op = "write";
    return trace_return(ctx, OP_WRITE);
}

int trace_open_return(struct pt_regs *ctx)
{
    char *op = "open";
    return trace_return(ctx, OP_OPEN);
}

int trace_getattr_return(struct pt_regs *ctx)
{
    char *op = "getattr";
    return trace_return(ctx, OP_GETATTR);
}

int trace_readdir_return(struct pt_regs *ctx)
{
    char *op = "readdir";
    // TODO get readdir entry count
    return trace_return(ctx, OP_READDIR);
}

int trace_lookup_return(struct pt_regs *ctx)
{
    char *op = "lookup";
    return trace_return(ctx, OP_LOOKUP);
}
"""
if args.user:
    # get username
    try:
        uid = pwd.getpwnam(args.user).pw_uid
    except KeyError:
        print(f"User {args.user} not found")
        exit(1)
    bpf_text = bpf_text.replace('FILTER_UID', 'uid != %s' % uid)
    bpf_text = bpf_text.replace('FILTER_PID', '1')
else:
    bpf_text = bpf_text.replace('FILTER_UID', '0')
    bpf_text = bpf_text.replace('FILTER_PID', '0')
if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# load BPF program
b = BPF(text=bpf_text)

b.attach_kretprobe(event="nfs_file_read", fn_name="trace_read_return")
b.attach_kretprobe(event="nfs_file_write", fn_name="trace_write_return")
b.attach_kretprobe(event="nfs_file_open", fn_name="trace_open_return")
b.attach_kretprobe(event="nfs_getattr", fn_name="trace_getattr_return")
b.attach_kretprobe(event="nfs_readdir", fn_name="trace_readdir_return")
b.attach_kretprobe(event="nfs_lookup", fn_name="trace_lookup_return")

if BPF.get_kprobe_functions(b'nfs4_file_open'):
    b.attach_kretprobe(event="nfs4_file_open", fn_name="trace_open_return")
else:
    b.attach_kretprobe(event="nfs_file_open", fn_name="trace_open_return")

print("Tracing NFS operation count... Hit Ctrl-C to end.")

# output
exiting = 0
while (1):
    try:
        if args.interval:
            sleep(int(args.interval))
        else:
            sleep(99999999)
    except KeyboardInterrupt:
        exiting = 1

    print()
    if args.interval:
        print(strftime("%H:%M:%S:"))

    counts = b.get_table("counts")
    def total_ops(c):
        return c.getattr + c.lookup + c.open + c.readdir + c.read + c.write

    sorted_counts = sorted(counts.items(), key=lambda counts: total_ops(counts[1]), reverse=True)
    # print title
    if args.user:
        print("%-6s %-8s %-8s %-8s %-8s %-8s %-8s" % ("PID", "GETATTR", "LOOKUP", "OPEN", "READDIR", "READ", "WRITE"))
    else:
        print("%-6s %-8s %-8s %-8s %-8s %-8s %-8s" % ("USER", "GETATTR", "LOOKUP", "OPEN", "READDIR", "READ", "WRITE"))
    # print top 10
    for k, v in sorted_counts[:10]:
        if args.user:
            print("%-6d %-8d %-8d %-8d %-8d %-8d %-8d" % (k.value, v.getattr, v.lookup, v.open, v.readdir, v.read, v.write))
        else:
            print("%-6s %-8d %-8d %-8d %-8d %-8d %-8d" % (pwd.getpwuid(k.value).pw_name, v.getattr, v.lookup, v.open, v.readdir, v.read, v.write))
            
    print()
    counts.clear()

    countdown -= 1
    if exiting or countdown == 0:
        exit()
