/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <linux/netlink.h>
#include <linux/if_ether.h>
#include <linux/if_infiniband.h>
#include <linux/if_packet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include "macro.h"
#include "missing_network.h"
#include "missing_socket.h"
#include "sparse-endian.h"

union sockaddr_union {
        /* The minimal, abstract version */
        struct sockaddr sa;

        /* The libc provided version that allocates "enough room" for every protocol */
        struct sockaddr_storage storage;

        /* Protoctol-specific implementations */
        struct sockaddr_in in;
        struct sockaddr_in6 in6;
        struct sockaddr_un un;
        struct sockaddr_nl nl;
        struct sockaddr_ll ll;
#if 0 /* NM_IGNORED */
        struct sockaddr_vm vm;
#endif /* NM_IGNORED */

        /* Ensure there is enough space to store Infiniband addresses */
        uint8_t ll_buffer[offsetof(struct sockaddr_ll, sll_addr) + CONST_MAX(ETH_ALEN, INFINIBAND_ALEN)];

        /* Ensure there is enough space after the AF_UNIX sun_path for one more NUL byte, just to be sure that the path
         * component is always followed by at least one NUL byte. */
        uint8_t un_buffer[sizeof(struct sockaddr_un) + 1];
};

#define SUN_PATH_LEN (sizeof(((struct sockaddr_un){}).sun_path))

typedef struct SocketAddress {
        union sockaddr_union sockaddr;

        /* We store the size here explicitly due to the weird
         * sockaddr_un semantics for abstract sockets */
        socklen_t size;

        /* Socket type, i.e. SOCK_STREAM, SOCK_DGRAM, ... */
        int type;

        /* Socket protocol, IPPROTO_xxx, usually 0, except for netlink */
        int protocol;
} SocketAddress;

typedef enum SocketAddressBindIPv6Only {
        SOCKET_ADDRESS_DEFAULT,
        SOCKET_ADDRESS_BOTH,
        SOCKET_ADDRESS_IPV6_ONLY,
        _SOCKET_ADDRESS_BIND_IPV6_ONLY_MAX,
        _SOCKET_ADDRESS_BIND_IPV6_ONLY_INVALID = -1
} SocketAddressBindIPv6Only;

#define socket_address_family(a) ((a)->sockaddr.sa.sa_family)

const char* socket_address_type_to_string(int t) _const_;
int socket_address_type_from_string(const char *s) _pure_;

int sockaddr_un_unlink(const struct sockaddr_un *sa);

static inline int socket_address_unlink(const SocketAddress *a) {
        return socket_address_family(a) == AF_UNIX ? sockaddr_un_unlink(&a->sockaddr.un) : 0;
}

bool socket_address_can_accept(const SocketAddress *a) _pure_;

int socket_address_listen(
                const SocketAddress *a,
                int flags,
                int backlog,
                SocketAddressBindIPv6Only only,
                const char *bind_to_device,
                bool reuse_port,
                bool free_bind,
                bool transparent,
                mode_t directory_mode,
                mode_t socket_mode,
                const char *label);

int socket_address_verify(const SocketAddress *a, bool strict) _pure_;
int socket_address_print(const SocketAddress *a, char **p);
bool socket_address_matches_fd(const SocketAddress *a, int fd);

bool socket_address_equal(const SocketAddress *a, const SocketAddress *b) _pure_;

const char* socket_address_get_path(const SocketAddress *a);

bool socket_ipv6_is_supported(void);

int sockaddr_port(const struct sockaddr *_sa, unsigned *port);
const union in_addr_union *sockaddr_in_addr(const struct sockaddr *sa);

int sockaddr_pretty(const struct sockaddr *_sa, socklen_t salen, bool translate_ipv6, bool include_port, char **ret);
int getpeername_pretty(int fd, bool include_port, char **ret);
int getsockname_pretty(int fd, char **ret);

int socknameinfo_pretty(union sockaddr_union *sa, socklen_t salen, char **_ret);

const char* socket_address_bind_ipv6_only_to_string(SocketAddressBindIPv6Only b) _const_;
SocketAddressBindIPv6Only socket_address_bind_ipv6_only_from_string(const char *s) _pure_;
SocketAddressBindIPv6Only socket_address_bind_ipv6_only_or_bool_from_string(const char *s);

int netlink_family_to_string_alloc(int b, char **s);
int netlink_family_from_string(const char *s) _pure_;

bool sockaddr_equal(const union sockaddr_union *a, const union sockaddr_union *b);

int fd_set_sndbuf(int fd, size_t n, bool increase);
static inline int fd_inc_sndbuf(int fd, size_t n) {
        return fd_set_sndbuf(fd, n, true);
}
int fd_set_rcvbuf(int fd, size_t n, bool increase);
static inline int fd_inc_rcvbuf(int fd, size_t n) {
        return fd_set_rcvbuf(fd, n, true);
}

int ip_tos_to_string_alloc(int i, char **s);
int ip_tos_from_string(const char *s);

typedef enum {
      IFNAME_VALID_ALTERNATIVE = 1 << 0,
      IFNAME_VALID_NUMERIC     = 1 << 1,
      _IFNAME_VALID_ALL        = IFNAME_VALID_ALTERNATIVE | IFNAME_VALID_NUMERIC,
} IfnameValidFlags;
bool ifname_valid_full(const char *p, IfnameValidFlags flags);
static inline bool ifname_valid(const char *p) {
        return ifname_valid_full(p, 0);
}
bool address_label_valid(const char *p);

int getpeercred(int fd, struct ucred *ucred);
int getpeersec(int fd, char **ret);
int getpeergroups(int fd, gid_t **ret);

ssize_t send_one_fd_iov_sa(
                int transport_fd,
                int fd,
                struct iovec *iov, size_t iovlen,
                const struct sockaddr *sa, socklen_t len,
                int flags);
int send_one_fd_sa(int transport_fd,
                   int fd,
                   const struct sockaddr *sa, socklen_t len,
                   int flags);
#define send_one_fd_iov(transport_fd, fd, iov, iovlen, flags) send_one_fd_iov_sa(transport_fd, fd, iov, iovlen, NULL, 0, flags)
#define send_one_fd(transport_fd, fd, flags) send_one_fd_iov_sa(transport_fd, fd, NULL, 0, NULL, 0, flags)
ssize_t receive_one_fd_iov(int transport_fd, struct iovec *iov, size_t iovlen, int flags, int *ret_fd);
int receive_one_fd(int transport_fd, int flags);

ssize_t next_datagram_size_fd(int fd);

int flush_accept(int fd);

#define CMSG_FOREACH(cmsg, mh)                                          \
        for ((cmsg) = CMSG_FIRSTHDR(mh); (cmsg); (cmsg) = CMSG_NXTHDR((mh), (cmsg)))

struct cmsghdr* cmsg_find(struct msghdr *mh, int level, int type, socklen_t length);

/* Type-safe, dereferencing version of cmsg_find() */
#define CMSG_FIND_DATA(mh, level, type, ctype) \
        ({                                                            \
                struct cmsghdr *_found;                               \
                _found = cmsg_find(mh, level, type, CMSG_LEN(sizeof(ctype))); \
                (ctype*) (_found ? CMSG_DATA(_found) : NULL);         \
        })

/* Resolves to a type that can carry cmsghdr structures. Make sure things are properly aligned, i.e. the type
 * itself is placed properly in memory and the size is also aligned to what's appropriate for "cmsghdr"
 * structures. */
#define CMSG_BUFFER_TYPE(size)                                          \
        union {                                                         \
                struct cmsghdr cmsghdr;                                 \
                uint8_t buf[size];                                      \
                uint8_t align_check[(size) >= CMSG_SPACE(0) &&          \
                                    (size) == CMSG_ALIGN(size) ? 1 : -1]; \
        }

/*
 * Certain hardware address types (e.g Infiniband) do not fit into sll_addr
 * (8 bytes) and run over the structure. This macro returns the correct size that
 * must be passed to kernel.
 */
#define SOCKADDR_LL_LEN(sa)                                             \
        ({                                                              \
                const struct sockaddr_ll *_sa = &(sa);                  \
                size_t _mac_len = sizeof(_sa->sll_addr);                \
                assert(_sa->sll_family == AF_PACKET);                   \
                if (be16toh(_sa->sll_hatype) == ARPHRD_ETHER)           \
                        _mac_len = MAX(_mac_len, (size_t) ETH_ALEN);    \
                if (be16toh(_sa->sll_hatype) == ARPHRD_INFINIBAND)      \
                        _mac_len = MAX(_mac_len, (size_t) INFINIBAND_ALEN); \
                offsetof(struct sockaddr_ll, sll_addr) + _mac_len;      \
        })

/* Covers only file system and abstract AF_UNIX socket addresses, but not unnamed socket addresses. */
#define SOCKADDR_UN_LEN(sa)                                             \
        ({                                                              \
                const struct sockaddr_un *_sa = &(sa);                  \
                assert(_sa->sun_family == AF_UNIX);                     \
                offsetof(struct sockaddr_un, sun_path) +                \
                        (_sa->sun_path[0] == 0 ?                        \
                         1 + strnlen(_sa->sun_path+1, sizeof(_sa->sun_path)-1) : \
                         strnlen(_sa->sun_path, sizeof(_sa->sun_path))+1); \
        })

#define SOCKADDR_LEN(sa)                                                \
        ({                                                              \
                const union sockaddr_union *__sa = &(sa);               \
                size_t _len;                                            \
                switch(__sa->sa.sa_family) {                            \
                case AF_INET:                                           \
                        _len = sizeof(struct sockaddr_in);              \
                        break;                                          \
                case AF_INET6:                                          \
                        _len = sizeof(struct sockaddr_in6);             \
                        break;                                          \
                case AF_UNIX:                                           \
                        _len = SOCKADDR_UN_LEN(__sa->un);               \
                        break;                                          \
                case AF_PACKET:                                         \
                        _len = SOCKADDR_LL_LEN(__sa->ll);               \
                        break;                                          \
                case AF_NETLINK:                                        \
                        _len = sizeof(struct sockaddr_nl);              \
                        break;                                          \
                case AF_VSOCK:                                          \
                        _len = sizeof(struct sockaddr_vm);              \
                        break;                                          \
                default:                                                \
                        assert_not_reached("invalid socket family");    \
                }                                                       \
                _len;                                                   \
        })

int socket_ioctl_fd(void);

int sockaddr_un_set_path(struct sockaddr_un *ret, const char *path);

static inline int setsockopt_int(int fd, int level, int optname, int value) {
        if (setsockopt(fd, level, optname, &value, sizeof(value)) < 0)
                return -errno;

        return 0;
}

static inline int getsockopt_int(int fd, int level, int optname, int *ret) {
        int v;
        socklen_t sl = sizeof(v);

        if (getsockopt(fd, level, optname, &v, &sl) < 0)
                return -errno;
        if (sl != sizeof(v))
                return -EIO;

        *ret = v;
        return 0;
}

int socket_bind_to_ifname(int fd, const char *ifname);
int socket_bind_to_ifindex(int fd, int ifindex);

ssize_t recvmsg_safe(int sockfd, struct msghdr *msg, int flags);

int socket_get_family(int fd, int *ret);
int socket_set_recvpktinfo(int fd, int af, bool b);
int socket_set_unicast_if(int fd, int af, int ifi);

int socket_set_option(int fd, int af, int opt_ipv4, int opt_ipv6, int val);
#if 0 /* NM_IGNORED */
static inline int socket_set_recverr(int fd, int af, bool b) {
        return socket_set_option(fd, af, IP_RECVERR, IPV6_RECVERR, b);
}
static inline int socket_set_recvttl(int fd, int af, bool b) {
        return socket_set_option(fd, af, IP_RECVTTL, IPV6_RECVHOPLIMIT, b);
}
static inline int socket_set_ttl(int fd, int af, int ttl) {
        return socket_set_option(fd, af, IP_TTL, IPV6_UNICAST_HOPS, ttl);
}
static inline int socket_set_freebind(int fd, int af, bool b) {
        return socket_set_option(fd, af, IP_FREEBIND, IPV6_FREEBIND, b);
}
static inline int socket_set_transparent(int fd, int af, bool b) {
        return socket_set_option(fd, af, IP_TRANSPARENT, IPV6_TRANSPARENT, b);
}
static inline int socket_set_recvfragsize(int fd, int af, bool b) {
        return socket_set_option(fd, af, IP_RECVFRAGSIZE, IPV6_RECVFRAGSIZE, b);
}
#endif /* NM_IGNORED */

int socket_get_mtu(int fd, int af, size_t *ret);
