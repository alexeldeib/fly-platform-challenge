#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_SOCKS 1
#define MAX_PORTS 65535

static const __u32 SOCK_KEY = 0;

struct
{
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, MAX_SOCKS);
    __type(key, __u32);
    __type(value, __u64);
} sock_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PORTS);
    __type(key, __u16);
    __type(value, __u8);
} port_map SEC(".maps");

// n.b.: trailing slash for cilium/ebpf but not for libbpf
SEC("sk_lookup/")
int redir_port(struct bpf_sk_lookup *ctx)
{
    // check if port is in our listening list
    __u16 port = ctx->local_port;

    __u8 *found = bpf_map_lookup_elem(&port_map, &port);
    if (!found)
    {
        // if not, pass it forward
        return SK_PASS;
    }

    struct bpf_sock *sk;
    int err;

    // lookup our static listening socket
    sk = bpf_map_lookup_elem(&sock_map, &SOCK_KEY);
    if (!sk)
    {
        // debug only
        const char fmt_str[] = "failed bpf map lookup for socket\n";
        bpf_trace_printk(fmt_str, sizeof(fmt_str));
        return SK_PASS;
    }

    // assign and handle or error
    err = bpf_sk_assign(ctx, sk, 0);
    if (err)
    {
        // debug only
        const char fmt_str[] = "failed bpf sk assign\n";
        bpf_trace_printk(fmt_str, sizeof(fmt_str));
    }

    bpf_sk_release(sk);
    return err ? SK_DROP : SK_PASS;
}
