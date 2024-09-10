// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// #define EPERM 13
// #define BLOCK_DEST 167783178
char LICENSE[] SEC("license") = "Dual BSD/GPL";

typedef struct {
  u32 pid;
  u32 pid_ns;
  u32 mnt_ns;
  char comm[80];
  u32 daddr;
} event;

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const event *unused __attribute__((unused));

static __always_inline u32 get_task_pid_vnr(struct task_struct *task) {
  struct pid *pid = BPF_CORE_READ(task, thread_pid);
  unsigned int level = BPF_CORE_READ(pid, level);
  return BPF_CORE_READ(pid, numbers[level].nr);
}

static __always_inline u32 get_task_ns_tgid(struct task_struct *task) {
  struct task_struct *group_leader = BPF_CORE_READ(task, group_leader);
  return get_task_pid_vnr(group_leader);
}

SEC("lsm/socket_connect")
int BPF_PROG(enforce_soconn, struct socket *sock, struct sockaddr *address,
             int addrlen) {
  struct task_struct *t = (struct task_struct *)bpf_get_current_task();
  u32 pid_ns = BPF_CORE_READ(t, nsproxy, pid_ns_for_children, ns).inum;
  u32 mnt_ns = BPF_CORE_READ(t, nsproxy, mnt_ns, ns).inum;

  if (pid_ns == PROC_PID_INIT_INO) {
    return 0;
  }

  u64 id = bpf_get_current_pid_tgid();
  u32 tgid = id >> 32;

  // Only IPv4 in this example
  if (address->sa_family != 2) {
    return 0;
  }

  // Cast the address to an IPv4 socket address
  struct sockaddr_in *addr = (struct sockaddr_in *)address;

  // Where do you want to go?
  __u32 dest = addr->sin_addr.s_addr;

  // // Only IPv4 in this example
  // if (address->sa_family == 10) {
  //   // Cast the address to an IPv4 socket address
  //   struct sockaddr_in6 *addr = (struct sockaddr_in6 *)address;

  //   // Where do you want to go?
  //   __u32 dest = addr->sin6_addr.in6_u.u6_addr32;
  //   bpf_printk("lsm: found connect to %d", dest);
  // }
  event *task_info;

  task_info = bpf_ringbuf_reserve(&events, sizeof(event), 0);
  if (!task_info) {
    return 0;
  }

  task_info->pid = get_task_ns_tgid(t);
  task_info->pid_ns = pid_ns;
  task_info->mnt_ns = mnt_ns;
  bpf_get_current_comm(&task_info->comm, sizeof(task_info->comm));
  task_info->daddr = dest;

  bpf_printk("[connect] proc %s -> %pI4", task_info->comm, &task_info->daddr);


  bpf_ringbuf_submit(task_info, 0);

  // if (dest == BLOCK_DEST) {
  //   return -EPERM;
  // }

  return 0;
}

SEC("lsm/socket_accept")
int BPF_PROG(enforce_soacc, struct socket *sock, struct socket *newsock) {
  bpf_printk("[accept]=====================================");
  struct task_struct *t = (struct task_struct *)bpf_get_current_task();
  u32 pid_ns = BPF_CORE_READ(t, nsproxy, pid_ns_for_children, ns).inum;
  u32 mnt_ns = BPF_CORE_READ(t, nsproxy, mnt_ns, ns).inum;

  // if (pid_ns == PROC_PID_INIT_INO) {
  //   return 0;
  // }


  // u32 tgid = bpf_get_current_pid_tgid() >> 32;

  // u16 family = BPF_CORE_READ(newsock, sk, __sk_common).skc_family;
  // // Only IPv4 in this example
  // if (family != 2) {
  //   return 0;
  // }

  // u32 src = BPF_CORE_READ(newsock, sk, __sk_common).skc_rcv_saddr;

  // // Where do you want to go?
  // u32 dest = BPF_CORE_READ(newsock, sk, __sk_common).skc_daddr;

  // // Only IPv4 in this example
  // if (address->sa_family == 10) {
  //   // Cast the address to an IPv4 socket address
  //   struct sockaddr_in6 *addr = (struct sockaddr_in6 *)address;

  //   // Where do you want to go?
  //   __u32 dest = addr->sin6_addr.in6_u.u6_addr32;
  //   bpf_printk("lsm: found connect to %d", dest);
  // }
  // event *task_info;

  // task_info = bpf_ringbuf_reserve(&events, sizeof(event), 0);
  // if (!task_info) {
  //   return 0;
  // }

  // task_info->pid = get_task_ns_tgid(t);
  // task_info->pid_ns = pid_ns;
  // task_info->mnt_ns = mnt_ns;
  // bpf_get_current_comm(&task_info->comm, sizeof(task_info->comm));
  // task_info->daddr = BPF_CORE_READ(newsock, sk, __sk_common).skc_rcv_saddr;

  // bpf_printk("[accept] proc %s -> %pI4", task_info->comm, &task_info->daddr);

  // bpf_ringbuf_submit(task_info, 0);
  return 0;
}

SEC("lsm/socket_getsockname")
int BPF_PROG(enforce_getsockname, struct socket *sock) {

  struct task_struct *t = (struct task_struct *)bpf_get_current_task();
  u32 pid_ns = BPF_CORE_READ(t, nsproxy, pid_ns_for_children, ns).inum;
  u32 mnt_ns = BPF_CORE_READ(t, nsproxy, mnt_ns, ns).inum;

  if (pid_ns == PROC_PID_INIT_INO) {
    return 0;
  }

  bpf_printk("[getsocname]==================");

  u16 family = BPF_CORE_READ(sock, sk, __sk_common).skc_family;
  // Only IPv4 in this example
  if (family != 2) {
    return 0;
  }

  u32 src = BPF_CORE_READ(sock, sk, __sk_common).skc_rcv_saddr;

  // Where do you want to go?
  u32 dest = BPF_CORE_READ(sock, sk, __sk_common).skc_daddr;

  bpf_printk("src -> %pI4 dest -> %pI4", &src, &dest);

  return 0;
}


SEC("lsm/socket_create")
int BPF_PROG(enforce_socket_create, int family, int type, int protocol, int kern) {

  struct task_struct *t = (struct task_struct *)bpf_get_current_task();
  u32 pid_ns = BPF_CORE_READ(t, nsproxy, pid_ns_for_children, ns).inum;
  u32 mnt_ns = BPF_CORE_READ(t, nsproxy, mnt_ns, ns).inum;

  if (pid_ns == PROC_PID_INIT_INO) {
    return 0;
  }

  bpf_printk("[socketcreate]==================");

  // u16 family = BPF_CORE_READ(sock, sk, __sk_common).skc_family;
  // // Only IPv4 in this example
  if (family != 2) {
    return 0;
  }

  // u32 src = BPF_CORE_READ(sock, sk, __sk_common).skc_rcv_saddr;

  // // Where do you want to go?
  // u32 dest = BPF_CORE_READ(sock, sk, __sk_common).skc_daddr;

  // bpf_printk("src -> %pI4 dest -> %pI4", &src, &dest);

  return 0;
}

SEC("lsm/inet_conn_request")
int BPF_PROG(enforce_inet_conn_request, struct sock *sk, struct sk_buff *skb, struct request_sock *req) {

  struct task_struct *t = (struct task_struct *)bpf_get_current_task();
  u32 pid_ns = BPF_CORE_READ(t, nsproxy, pid_ns_for_children, ns).inum;
  u32 mnt_ns = BPF_CORE_READ(t, nsproxy, mnt_ns, ns).inum;

  if (pid_ns == PROC_PID_INIT_INO) {
    return 0;
  }

  bpf_printk("[inet_conn_reques]");

  return 0;
}

SEC("lsm/socket_sock_rcv_skb")
int BPF_PROG(enforce_socket_sock_rcv_skb, struct sock *sk, struct sk_buff *skb) {

  struct task_struct *t = (struct task_struct *)bpf_get_current_task();
  u32 pid_ns = BPF_CORE_READ(t, nsproxy, pid_ns_for_children, ns).inum;
  u32 mnt_ns = BPF_CORE_READ(t, nsproxy, mnt_ns, ns).inum;

  if (pid_ns == PROC_PID_INIT_INO) {
    return 0;
  }

  bpf_printk("[socket_sock_rcv_skb]");

  return 0;
}