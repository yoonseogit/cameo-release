#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define AF_INET 2
#define IPPROTO_UDP 17

#define ROLE_UNTRUSTED 1
#define ROLE_MEDIATOR  2

#define EPERM 1


/*
 * Userspace loader가 계산한 protected DDS domain의
 * UDP port range.
 *
 * key = 0
 *
 * 예:
 *   protected_domain = 20
 *
 *   protected_port_min = 12400
 *   protected_port_max = 12649
 */
struct guard_config_value
{
    __u32 protected_port_min;
    __u32 protected_port_max;
};


struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);

    __type(key, __u32);
    __type(value, struct guard_config_value);
} guard_config SEC(".maps");


/*
 * TGID -> process role
 *
 * ROLE_UNTRUSTED
 * ROLE_MEDIATOR
 */
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);

    __type(key, __u32);
    __type(value, __u32);
} process_roles SEC(".maps");


static __always_inline __u32 current_tgid(void)
{
    return (__u32)(
        bpf_get_current_pid_tgid() >> 32
    );
}


static __always_inline int
apply_guard(
    __u32 tgid,
    __u32 role,
    __u16 dport)
{
    /*
     * Trusted Mediator는 internal/protected domain
     * 모두 송신 가능.
     */
    if (role == ROLE_MEDIATOR)
    {
        bpf_printk(
            "BYPASS_ALLOW tgid=%u role=%u port=%u",
            tgid,
            role,
            dport
        );

        return 0;
    }


    /*
     * 현재 Guard의 보안 대상은
     * 등록된 Untrusted process.
     */
    if (role != ROLE_UNTRUSTED)
    {
        return 0;
    }


    /*
     * Loader가 등록한 protected port configuration 조회.
     */
    __u32 config_key = 0;

    struct guard_config_value *config =
        bpf_map_lookup_elem(
            &guard_config,
            &config_key
        );


    /*
     * 등록된 Untrusted process인데 configuration이 없다면
     * 잘못 초기화된 security guard 상태이므로 fail-closed.
     */
    if (!config)
    {
        bpf_printk(
            "BYPASS_CONFIG_MISS tgid=%u role=%u",
            tgid,
            role
        );

        return -EPERM;
    }


    /*
     * Protected DDS domain으로 직접 송신하려는 경우 차단.
     */
    if ((__u32)dport >= config->protected_port_min &&
        (__u32)dport <= config->protected_port_max)
    {
        bpf_printk(
            "BYPASS_DENY tgid=%u role=%u port=%u",
            tgid,
            role,
            dport
        );

        return -EPERM;
    }


    /*
     * Protected range 밖의 UDP traffic은 허용.
     *
     * 예:
     * D10 internal Fast DDS traffic.
     */
    bpf_printk(
        "BYPASS_ALLOW tgid=%u role=%u port=%u",
        tgid,
        role,
        dport
    );

    return 0;
}


SEC("lsm/socket_sendmsg")
int BPF_PROG(
    guard_socket_sendmsg,
    struct socket *sock,
    struct msghdr *msg,
    int size,
    int ret)
{
    if (ret != 0)
    {
        return ret;
    }


    __u32 tgid =
        current_tgid();


    __u32 *role =
        bpf_map_lookup_elem(
            &process_roles,
            &tgid
        );


    /*
     * 현재 security target으로 등록되지 않은 process는
     * Guard 대상이 아니다.
     */
    if (!role)
    {
        return 0;
    }


    struct sock *sk =
        BPF_CORE_READ(
            sock,
            sk
        );

    if (!sk)
    {
        return 0;
    }


    __u16 family =
        BPF_CORE_READ(
            sk,
            __sk_common.skc_family
        );


    __u16 protocol =
        BPF_CORE_READ(
            sk,
            sk_protocol
        );


    /*
     * 현재 threat model:
     * IPv4 UDP
     */
    if (family != AF_INET ||
        protocol != IPPROTO_UDP)
    {
        return 0;
    }


    void *msg_name =
        BPF_CORE_READ(
            msg,
            msg_name
        );


    int msg_namelen =
        BPF_CORE_READ(
            msg,
            msg_namelen
        );


    /*
     * Fast DDS가 현재 실험에서 사용하는 일반적인 sendmsg path.
     */
    if (msg_name &&
        msg_namelen >= sizeof(struct sockaddr_in))
    {
        struct sockaddr_in addr = {};

        if (bpf_probe_read_kernel(
                &addr,
                sizeof(addr),
                msg_name) == 0)
        {
            __u16 dport =
                bpf_ntohs(
                    addr.sin_port
                );

            return apply_guard(
                tgid,
                *role,
                dport
            );
        }
    }


    /*
     * connected UDP socket fallback.
     */
    __u16 dport_network =
        BPF_CORE_READ(
            sk,
            __sk_common.skc_dport
        );


    __u16 dport =
        bpf_ntohs(
            dport_network
        );


    return apply_guard(
        tgid,
        *role,
        dport
    );
}