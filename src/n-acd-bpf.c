/*
 * eBPF filter for IPv4 Address Conflict Detection
 *
 * An eBPF map and an eBPF program are provided. The map contains all the
 * addresses address conflict detection is performed on, and the program
 * filters out all packets except exactly the packets relevant to the ACD
 * protocol on the addresses currently in the map.
 *
 * Note that userspace still has to filter the incoming packets, as filter
 * are applied when packets are queued on the socket, not when userspace
 * receives them. It is therefore possible to receive packets about addresses
 * that have already been removed.
 */

#include <c-stdaux.h>
#include <errno.h>
#include <inttypes.h>
#include <linux/bpf.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "n-acd-private.h"

#define BPF_LD_ABS(SIZE, IMM)                                                   \
        ((struct bpf_insn) {                                                    \
                .code           = BPF_LD | BPF_SIZE(SIZE) | BPF_ABS,            \
                .dst_reg        = 0,                                            \
                .src_reg        = 0,                                            \
                .off            = 0,                                            \
                .imm            = IMM,                                          \
        })

#define BPF_LDX_MEM(SIZE, DST, SRC, OFF)                                        \
        ((struct bpf_insn) {                                                    \
                .code           = BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM,           \
                .dst_reg        = DST,                                          \
                .src_reg        = SRC,                                          \
                .off            = OFF,                                          \
                .imm            = 0,                                            \
        })

#define BPF_LD_MAP_FD(DST, MAP_FD)                                              \
        ((struct bpf_insn) {                                                    \
                .code           = BPF_LD | BPF_DW | BPF_IMM,                    \
                .dst_reg        = DST,                                          \
                .src_reg        = BPF_PSEUDO_MAP_FD,                            \
                .off            = 0,                                            \
                .imm            = (__u32) (MAP_FD),                             \
        }),                                                                     \
        ((struct bpf_insn) {                                                    \
                .code           = 0, /* zero is reserved opcode */              \
                .dst_reg        = 0,                                            \
                .src_reg        = 0,                                            \
                .off            = 0,                                            \
                .imm            = ((__u64) (MAP_FD)) >> 32,                     \
        })

#define BPF_ALU_REG(OP, DST, SRC)                                               \
        ((struct bpf_insn) {                                                    \
                .code           = BPF_ALU64 | BPF_OP(OP) | BPF_X,               \
                .dst_reg        = DST,                                          \
                .src_reg        = SRC,                                          \
                .off            = 0,                                            \
                .imm            = 0,                                            \
        })

#define BPF_ALU_IMM(OP, DST, IMM)                                               \
        ((struct bpf_insn) {                                                    \
                .code           = BPF_ALU64 | BPF_OP(OP) | BPF_K,               \
                .dst_reg        = DST,                                          \
                .src_reg        = 0,                                            \
                .off            = 0,                                            \
                .imm            = IMM,                                          \
        })

#define BPF_MOV_REG(DST, SRC)                                                   \
        ((struct bpf_insn) {                                                    \
                .code           = BPF_ALU64 | BPF_MOV | BPF_X,                  \
                .dst_reg        = DST,                                          \
                .src_reg        = SRC,                                          \
                .off            = 0,                                            \
                .imm            = 0,                                            \
        })

#define BPF_MOV_IMM(DST, IMM)                                                   \
        ((struct bpf_insn) {                                                    \
                .code           = BPF_ALU64 | BPF_MOV | BPF_K,                  \
                .dst_reg        = DST,                                          \
                .src_reg        = 0,                                            \
                .off            = 0,                                            \
                .imm            = IMM,                                          \
        })

#define BPF_STX_MEM(SIZE, DST, SRC, OFF)                                        \
        ((struct bpf_insn) {                                                    \
                .code           = BPF_STX | BPF_SIZE(SIZE) | BPF_MEM,           \
                .dst_reg        = DST,                                          \
                .src_reg        = SRC,                                          \
                .off            = OFF,                                          \
                .imm            = 0,                                            \
        })

#define BPF_JMP_REG(OP, DST, SRC, OFF)                                          \
        ((struct bpf_insn) {                                                    \
                .code           = BPF_JMP | BPF_OP(OP) | BPF_X,                 \
                .dst_reg        = DST,                                          \
                .src_reg        = SRC,                                          \
                .off            = OFF,                                          \
                .imm            = 0,                                            \
        })

#define BPF_JMP_IMM(OP, DST, IMM, OFF)                                          \
        ((struct bpf_insn) {                                                    \
                .code           = BPF_JMP | BPF_OP(OP) | BPF_K,                 \
                .dst_reg        = DST,                                          \
                .src_reg        = 0,                                            \
                .off            = OFF,                                          \
                .imm            = IMM,                                          \
        })

#define BPF_EMIT_CALL(FUNC)                                                     \
        ((struct bpf_insn) {                                                    \
                .code           = BPF_JMP | BPF_CALL,                           \
                .dst_reg        = 0,                                            \
                .src_reg        = 0,                                            \
                .off            = 0,                                            \
                .imm            = FUNC,                                         \
        })

#define BPF_EXIT_INSN()                                                         \
        ((struct bpf_insn) {                                                    \
                .code           = BPF_JMP | BPF_EXIT,                           \
                .dst_reg        = 0,                                            \
                .src_reg        = 0,                                            \
                .off            = 0,                                            \
                .imm            = 0,                                            \
        })

static int n_acd_syscall_bpf(int cmd, union bpf_attr *attr, unsigned int size) {
        return (int)syscall(__NR_bpf, cmd, attr, size);
}

int n_acd_bpf_map_create(int *mapfdp, size_t max_entries) {
        union bpf_attr attr;
        int mapfd;

        memset(&attr, 0, sizeof(attr));
        attr = (union bpf_attr){
                .map_type    = BPF_MAP_TYPE_HASH,
                .key_size    = sizeof(uint32_t),
                .value_size  = sizeof(uint8_t), /* values are never used, but must be set */
                .max_entries = max_entries,
        };

        mapfd = n_acd_syscall_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
        if (mapfd < 0)
                return -errno;

        *mapfdp = mapfd;
        return 0;
}

int n_acd_bpf_map_add(int mapfd, struct in_addr *addrp) {
        union bpf_attr attr;
        uint32_t addr = be32toh(addrp->s_addr);
        uint8_t _dummy = 0;
        int r;

        memset(&attr, 0, sizeof(attr));
        attr = (union bpf_attr){
                .map_fd = mapfd,
                .key    = (uint64_t)(unsigned long)&addr,
                .value  = (uint64_t)(unsigned long)&_dummy,
                .flags  = BPF_NOEXIST,
        };

        r = n_acd_syscall_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
        if (r < 0)
                return -errno;

        return 0;
}

int n_acd_bpf_map_remove(int mapfd, struct in_addr *addrp) {
        uint32_t addr = be32toh(addrp->s_addr);
        union bpf_attr attr;
        int r;

        memset(&attr, 0, sizeof(attr));
        attr = (union bpf_attr){
                .map_fd = mapfd,
                .key    = (uint64_t)(unsigned long)&addr,
        };

        r = n_acd_syscall_bpf(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
        if (r < 0)
                return -errno;

        return 0;
}

int n_acd_bpf_compile(int *progfdp, int mapfd, struct ether_addr *macp) {
        const union {
                uint8_t u8[6];
                uint16_t u16[3];
                uint32_t u32[1];
        } mac = {
                .u8 = {
                        macp->ether_addr_octet[0],
                        macp->ether_addr_octet[1],
                        macp->ether_addr_octet[2],
                        macp->ether_addr_octet[3],
                        macp->ether_addr_octet[4],
                        macp->ether_addr_octet[5],
                },
        };
        struct bpf_insn prog[] = {
                /* for using BPF_LD_ABS r6 must point to the skb, currently in r1 */
                BPF_MOV_REG(6, 1),                                              /* r6 = r1 */

                /* drop the packet if it is too short */
                BPF_LDX_MEM(BPF_W, 0, 6, offsetof(struct __sk_buff, len)),      /* r0 = skb->len */
                BPF_JMP_IMM(BPF_JGE, 0, sizeof(struct ether_arp), 2),           /* if (r0 >= sizeof(ether_arp)) skip 2 */
                BPF_MOV_IMM(0, 0),                                              /* r0 = 0 */
                BPF_EXIT_INSN(),                                                /* return */

                /* drop the packet if the header is not as expected */
                BPF_LD_ABS(BPF_H, offsetof(struct ether_arp, arp_hrd)),         /* r0 = header type */
                BPF_JMP_IMM(BPF_JEQ, 0, ARPHRD_ETHER, 2),                       /* if (r0 == ethernet) skip 2 */
                BPF_MOV_IMM(0, 0),                                              /* r0 = 0 */
                BPF_EXIT_INSN(),                                                /* return */

                BPF_LD_ABS(BPF_H, offsetof(struct ether_arp, arp_pro)),         /* r0 = protocol */
                BPF_JMP_IMM(BPF_JEQ, 0, ETHERTYPE_IP, 2),                       /* if (r0 == IP) skip 2 */
                BPF_MOV_IMM(0, 0),                                              /* r0 = 0 */
                BPF_EXIT_INSN(),                                                /* return */

                BPF_LD_ABS(BPF_B, offsetof(struct ether_arp, arp_hln)),         /* r0 = hw addr length */
                BPF_JMP_IMM(BPF_JEQ, 0, sizeof(struct ether_addr), 2),          /* if (r0 == sizeof(ether_addr)) skip 2 */
                BPF_MOV_IMM(0, 0),                                              /* r0 = 0 */
                BPF_EXIT_INSN(),                                                /* return */

                BPF_LD_ABS(BPF_B, offsetof(struct ether_arp, arp_pln)),         /* r0 = protocol addr length */
                BPF_JMP_IMM(BPF_JEQ, 0, sizeof(struct in_addr), 2),             /* if (r0 == sizeof(in_addr)) skip 2 */
                BPF_MOV_IMM(0, 0),                                              /* r0 = 0 */
                BPF_EXIT_INSN(),                                                /* return */

                /* drop packets from our own mac address */
                BPF_LD_ABS(BPF_W, offsetof(struct ether_arp, arp_sha)),         /* r0 = first four bytes of packet mac address */
                BPF_JMP_IMM(BPF_JNE, 0, be32toh(mac.u32[0]), 4),                /* if (r0 != first four bytes of our mac address) skip 4 */
                BPF_LD_ABS(BPF_H, offsetof(struct ether_arp, arp_sha) + 4),     /* r0 = last two bytes of packet mac address */
                BPF_JMP_IMM(BPF_JNE, 0, be16toh(mac.u16[2]), 2),                /* if (r0 != last two bytes of our mac address) skip 2 */
                BPF_MOV_IMM(0, 0),                                              /* r0 = 0 */
                BPF_EXIT_INSN(),                                                /* return */

                /*
                 * We listen for two kinds of packets:
                 *  Conflicts)
                 *    These are requests or replies with the sender address not set to INADDR_ANY. The
                 *    conflicted address is the sender address, remember this in r7.
                 *  Probes)
                 *    These are requests with the sender address set to INADDR_ANY. The probed address
                 *    is the target address, remember this in r7.
                 *  Any other packets are dropped.
                 */
                BPF_LD_ABS(BPF_W, offsetof(struct ether_arp, arp_spa)),         /* r0 = sender ip address */
                BPF_JMP_IMM(BPF_JEQ, 0, 0, 7),                                  /* if (r0 == 0) skip 7 */
                BPF_MOV_REG(7, 0),                                              /* r7 = r0 */
                BPF_LD_ABS(BPF_H, offsetof(struct ether_arp, arp_op)),          /* r0 = operation */
                BPF_JMP_IMM(BPF_JEQ, 0, ARPOP_REQUEST, 3),                      /* if (r0 == request) skip 3 */
                BPF_JMP_IMM(BPF_JEQ, 0, ARPOP_REPLY, 2),                        /* if (r0 == reply) skip 2 */
                BPF_MOV_IMM(0, 0),                                              /* r0 = 0 */
                BPF_EXIT_INSN(),                                                /* return */
                BPF_JMP_IMM(BPF_JA, 0, 0, 6),                                   /* skip 6 */
                BPF_LD_ABS(BPF_W, offsetof(struct ether_arp, arp_tpa)),         /* r0 = target ip address */
                BPF_MOV_REG(7, 0),                                              /* r7 = r0 */
                BPF_LD_ABS(BPF_H, offsetof(struct ether_arp, arp_op)),          /* r0 = operation */
                BPF_JMP_IMM(BPF_JEQ, 0, ARPOP_REQUEST, 2),                      /* if (r0 == request) skip 2 */
                BPF_MOV_IMM(0, 0),                                              /* r0 = 0 */
                BPF_EXIT_INSN(),                                                /* return */

                /* check if the probe or conflict is for an address we are monitoring */
                BPF_STX_MEM(BPF_W, 10, 7, -4),                                  /* *(uint32_t*)fp - 4 = r7 */
                BPF_MOV_REG(2, 10),                                             /* r2 = fp */
                BPF_ALU_IMM(BPF_ADD, 2, -4),                                    /* r2 -= 4 */
                BPF_LD_MAP_FD(1, mapfd),                                        /* r1 = mapfd */
                BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),                        /* r0 = map_lookup_elem(r1, r2) */
                BPF_JMP_IMM(BPF_JNE, 0, 0, 2),                                  /* if (r0 != NULL) skip 2 */
                BPF_MOV_IMM(0, 0),                                              /* r0 = 0 */
                BPF_EXIT_INSN(),                                                /* return */

                /* return exactly the packet length*/
                BPF_MOV_IMM(0, sizeof(struct ether_arp)),                       /* r0 = sizeof(struct ether_arp) */
                BPF_EXIT_INSN(),                                                /* return */
        };
        union bpf_attr attr;
        int progfd;

        memset(&attr, 0, sizeof(attr));
        attr = (union bpf_attr){
                .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
                .insns     = (uint64_t)(unsigned long)prog,
                .insn_cnt  = sizeof(prog) / sizeof(*prog),
                .license   = (uint64_t)(unsigned long)"ASL",
        };

        progfd = n_acd_syscall_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
        if (progfd < 0)
                return -errno;

        *progfdp = progfd;
        return 0;
}
