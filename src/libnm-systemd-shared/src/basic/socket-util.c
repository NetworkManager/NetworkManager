/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "nm-sd-adapt-shared.h"

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>
#if 0 /* NM_IGNORED */
#include <linux/if.h>
#endif /* NM_IGNORED */

#include "alloc-util.h"
#include "errno-util.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "io-util.h"
#include "log.h"
#include "memory-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "socket-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "user-util.h"
#include "utf8.h"

#if 0 /* NM_IGNORED */
#if ENABLE_IDN
#  define IDN_FLAGS NI_IDN
#else
#  define IDN_FLAGS 0
#endif

static const char* const socket_address_type_table[] = {
        [SOCK_STREAM] =    "Stream",
        [SOCK_DGRAM] =     "Datagram",
        [SOCK_RAW] =       "Raw",
        [SOCK_RDM] =       "ReliableDatagram",
        [SOCK_SEQPACKET] = "SequentialPacket",
        [SOCK_DCCP] =      "DatagramCongestionControl",
};

DEFINE_STRING_TABLE_LOOKUP(socket_address_type, int);

int socket_address_verify(const SocketAddress *a, bool strict) {
        assert(a);

        /* With 'strict' we enforce additional sanity constraints which are not set by the standard,
         * but should only apply to sockets we create ourselves. */

        switch (socket_address_family(a)) {

        case AF_INET:
                if (a->size != sizeof(struct sockaddr_in))
                        return -EINVAL;

                if (a->sockaddr.in.sin_port == 0)
                        return -EINVAL;

                if (!IN_SET(a->type, 0, SOCK_STREAM, SOCK_DGRAM))
                        return -EINVAL;

                return 0;

        case AF_INET6:
                if (a->size != sizeof(struct sockaddr_in6))
                        return -EINVAL;

                if (a->sockaddr.in6.sin6_port == 0)
                        return -EINVAL;

                if (!IN_SET(a->type, 0, SOCK_STREAM, SOCK_DGRAM))
                        return -EINVAL;

                return 0;

        case AF_UNIX:
                if (a->size < offsetof(struct sockaddr_un, sun_path))
                        return -EINVAL;
                if (a->size > sizeof(struct sockaddr_un) + !strict)
                        /* If !strict, allow one extra byte, since getsockname() on Linux will append
                         * a NUL byte if we have path sockets that are above sun_path's full size. */
                        return -EINVAL;

                if (a->size > offsetof(struct sockaddr_un, sun_path) &&
                    a->sockaddr.un.sun_path[0] != 0 &&
                    strict) {
                        /* Only validate file system sockets here, and only in strict mode */
                        const char *e;

                        e = memchr(a->sockaddr.un.sun_path, 0, sizeof(a->sockaddr.un.sun_path));
                        if (e) {
                                /* If there's an embedded NUL byte, make sure the size of the socket address matches it */
                                if (a->size != offsetof(struct sockaddr_un, sun_path) + (e - a->sockaddr.un.sun_path) + 1)
                                        return -EINVAL;
                        } else {
                                /* If there's no embedded NUL byte, then the size needs to match the whole
                                 * structure or the structure with one extra NUL byte suffixed. (Yeah, Linux is awful,
                                 * and considers both equivalent: getsockname() even extends sockaddr_un beyond its
                                 * size if the path is non NUL terminated.)*/
                                if (!IN_SET(a->size, sizeof(a->sockaddr.un.sun_path), sizeof(a->sockaddr.un.sun_path)+1))
                                        return -EINVAL;
                        }
                }

                if (!IN_SET(a->type, 0, SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET))
                        return -EINVAL;

                return 0;

        case AF_NETLINK:

                if (a->size != sizeof(struct sockaddr_nl))
                        return -EINVAL;

                if (!IN_SET(a->type, 0, SOCK_RAW, SOCK_DGRAM))
                        return -EINVAL;

                return 0;

        case AF_VSOCK:
                if (a->size != sizeof(struct sockaddr_vm))
                        return -EINVAL;

                if (!IN_SET(a->type, 0, SOCK_STREAM, SOCK_DGRAM))
                        return -EINVAL;

                return 0;

        default:
                return -EAFNOSUPPORT;
        }
}

int socket_address_print(const SocketAddress *a, char **ret) {
        int r;

        assert(a);
        assert(ret);

        r = socket_address_verify(a, false); /* We do non-strict validation, because we want to be
                                              * able to pretty-print any socket the kernel considers
                                              * valid. We still need to do validation to know if we
                                              * can meaningfully print the address. */
        if (r < 0)
                return r;

        if (socket_address_family(a) == AF_NETLINK) {
                _cleanup_free_ char *sfamily = NULL;

                r = netlink_family_to_string_alloc(a->protocol, &sfamily);
                if (r < 0)
                        return r;

                r = asprintf(ret, "%s %u", sfamily, a->sockaddr.nl.nl_groups);
                if (r < 0)
                        return -ENOMEM;

                return 0;
        }

        return sockaddr_pretty(&a->sockaddr.sa, a->size, false, true, ret);
}

bool socket_address_can_accept(const SocketAddress *a) {
        assert(a);

        return
                IN_SET(a->type, SOCK_STREAM, SOCK_SEQPACKET);
}

bool socket_address_equal(const SocketAddress *a, const SocketAddress *b) {
        assert(a);
        assert(b);

        /* Invalid addresses are unequal to all */
        if (socket_address_verify(a, false) < 0 ||
            socket_address_verify(b, false) < 0)
                return false;

        if (a->type != b->type)
                return false;

        if (socket_address_family(a) != socket_address_family(b))
                return false;

        switch (socket_address_family(a)) {

        case AF_INET:
                if (a->sockaddr.in.sin_addr.s_addr != b->sockaddr.in.sin_addr.s_addr)
                        return false;

                if (a->sockaddr.in.sin_port != b->sockaddr.in.sin_port)
                        return false;

                break;

        case AF_INET6:
                if (memcmp(&a->sockaddr.in6.sin6_addr, &b->sockaddr.in6.sin6_addr, sizeof(a->sockaddr.in6.sin6_addr)) != 0)
                        return false;

                if (a->sockaddr.in6.sin6_port != b->sockaddr.in6.sin6_port)
                        return false;

                break;

        case AF_UNIX:
                if (a->size <= offsetof(struct sockaddr_un, sun_path) ||
                    b->size <= offsetof(struct sockaddr_un, sun_path))
                        return false;

                if ((a->sockaddr.un.sun_path[0] == 0) != (b->sockaddr.un.sun_path[0] == 0))
                        return false;

                if (a->sockaddr.un.sun_path[0]) {
                        if (!path_equal_or_files_same(a->sockaddr.un.sun_path, b->sockaddr.un.sun_path, 0))
                                return false;
                } else {
                        if (a->size != b->size)
                                return false;

                        if (memcmp(a->sockaddr.un.sun_path, b->sockaddr.un.sun_path, a->size) != 0)
                                return false;
                }

                break;

        case AF_NETLINK:
                if (a->protocol != b->protocol)
                        return false;

                if (a->sockaddr.nl.nl_groups != b->sockaddr.nl.nl_groups)
                        return false;

                break;

        case AF_VSOCK:
                if (a->sockaddr.vm.svm_cid != b->sockaddr.vm.svm_cid)
                        return false;

                if (a->sockaddr.vm.svm_port != b->sockaddr.vm.svm_port)
                        return false;

                break;

        default:
                /* Cannot compare, so we assume the addresses are different */
                return false;
        }

        return true;
}

const char* socket_address_get_path(const SocketAddress *a) {
        assert(a);

        if (socket_address_family(a) != AF_UNIX)
                return NULL;

        if (a->sockaddr.un.sun_path[0] == 0)
                return NULL;

        /* Note that this is only safe because we know that there's an extra NUL byte after the sockaddr_un
         * structure. On Linux AF_UNIX file system socket addresses don't have to be NUL terminated if they take up the
         * full sun_path space. */
        assert_cc(sizeof(union sockaddr_union) >= sizeof(struct sockaddr_un)+1);
        return a->sockaddr.un.sun_path;
}

bool socket_ipv6_is_supported(void) {
        if (access("/proc/net/if_inet6", F_OK) != 0)
                return false;

        return true;
}

bool socket_address_matches_fd(const SocketAddress *a, int fd) {
        SocketAddress b;
        socklen_t solen;

        assert(a);
        assert(fd >= 0);

        b.size = sizeof(b.sockaddr);
        if (getsockname(fd, &b.sockaddr.sa, &b.size) < 0)
                return false;

        if (b.sockaddr.sa.sa_family != a->sockaddr.sa.sa_family)
                return false;

        solen = sizeof(b.type);
        if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &b.type, &solen) < 0)
                return false;

        if (b.type != a->type)
                return false;

        if (a->protocol != 0)  {
                solen = sizeof(b.protocol);
                if (getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, &b.protocol, &solen) < 0)
                        return false;

                if (b.protocol != a->protocol)
                        return false;
        }

        return socket_address_equal(a, &b);
}

int sockaddr_port(const struct sockaddr *_sa, unsigned *ret_port) {
        const union sockaddr_union *sa = (const union sockaddr_union*) _sa;

        /* Note, this returns the port as 'unsigned' rather than 'uint16_t', as AF_VSOCK knows larger ports */

        assert(sa);

        switch (sa->sa.sa_family) {

        case AF_INET:
                *ret_port = be16toh(sa->in.sin_port);
                return 0;

        case AF_INET6:
                *ret_port = be16toh(sa->in6.sin6_port);
                return 0;

        case AF_VSOCK:
                *ret_port = sa->vm.svm_port;
                return 0;

        default:
                return -EAFNOSUPPORT;
        }
}

const union in_addr_union *sockaddr_in_addr(const struct sockaddr *_sa) {
        const union sockaddr_union *sa = (const union sockaddr_union*) _sa;

        if (!sa)
                return NULL;

        switch (sa->sa.sa_family) {

        case AF_INET:
                return (const union in_addr_union*) &sa->in.sin_addr;

        case AF_INET6:
                return (const union in_addr_union*) &sa->in6.sin6_addr;

        default:
                return NULL;
        }
}

int sockaddr_pretty(
                const struct sockaddr *_sa,
                socklen_t salen,
                bool translate_ipv6,
                bool include_port,
                char **ret) {

        union sockaddr_union *sa = (union sockaddr_union*) _sa;
        char *p;
        int r;

        assert(sa);
        assert(salen >= sizeof(sa->sa.sa_family));

        switch (sa->sa.sa_family) {

        case AF_INET: {
                uint32_t a;

                a = be32toh(sa->in.sin_addr.s_addr);

                if (include_port)
                        r = asprintf(&p,
                                     "%u.%u.%u.%u:%u",
                                     a >> 24, (a >> 16) & 0xFF, (a >> 8) & 0xFF, a & 0xFF,
                                     be16toh(sa->in.sin_port));
                else
                        r = asprintf(&p,
                                     "%u.%u.%u.%u",
                                     a >> 24, (a >> 16) & 0xFF, (a >> 8) & 0xFF, a & 0xFF);
                if (r < 0)
                        return -ENOMEM;
                break;
        }

        case AF_INET6: {
                static const unsigned char ipv4_prefix[] = {
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF
                };

                if (translate_ipv6 &&
                    memcmp(&sa->in6.sin6_addr, ipv4_prefix, sizeof(ipv4_prefix)) == 0) {
                        const uint8_t *a = sa->in6.sin6_addr.s6_addr+12;
                        if (include_port)
                                r = asprintf(&p,
                                             "%u.%u.%u.%u:%u",
                                             a[0], a[1], a[2], a[3],
                                             be16toh(sa->in6.sin6_port));
                        else
                                r = asprintf(&p,
                                             "%u.%u.%u.%u",
                                             a[0], a[1], a[2], a[3]);
                        if (r < 0)
                                return -ENOMEM;
                } else {
                        char a[INET6_ADDRSTRLEN], ifname[IF_NAMESIZE + 1];

                        inet_ntop(AF_INET6, &sa->in6.sin6_addr, a, sizeof(a));
                        if (sa->in6.sin6_scope_id != 0)
                                format_ifname_full(sa->in6.sin6_scope_id, ifname, FORMAT_IFNAME_IFINDEX);

                        if (include_port) {
                                r = asprintf(&p,
                                             "[%s]:%u%s%s",
                                             a,
                                             be16toh(sa->in6.sin6_port),
                                             sa->in6.sin6_scope_id != 0 ? "%" : "",
                                             sa->in6.sin6_scope_id != 0 ? ifname : "");
                                if (r < 0)
                                        return -ENOMEM;
                        } else {
                                p = sa->in6.sin6_scope_id != 0 ? strjoin(a, "%", ifname) : strdup(a);
                                if (!p)
                                        return -ENOMEM;
                        }
                }

                break;
        }

        case AF_UNIX:
                if (salen <= offsetof(struct sockaddr_un, sun_path) ||
                    (sa->un.sun_path[0] == 0 && salen == offsetof(struct sockaddr_un, sun_path) + 1))
                        /* The name must have at least one character (and the leading NUL does not count) */
                        p = strdup("<unnamed>");
                else {
                        /* Note that we calculate the path pointer here through the .un_buffer[] field, in order to
                         * outtrick bounds checking tools such as ubsan, which are too smart for their own good: on
                         * Linux the kernel may return sun_path[] data one byte longer than the declared size of the
                         * field. */
                        char *path = (char*) sa->un_buffer + offsetof(struct sockaddr_un, sun_path);
                        size_t path_len = salen - offsetof(struct sockaddr_un, sun_path);

                        if (path[0] == 0) {
                                /* Abstract socket. When parsing address information from, we
                                 * explicitly reject overly long paths and paths with embedded NULs.
                                 * But we might get such a socket from the outside. Let's return
                                 * something meaningful and printable in this case. */

                                _cleanup_free_ char *e = NULL;

                                e = cescape_length(path + 1, path_len - 1);
                                if (!e)
                                        return -ENOMEM;

                                p = strjoin("@", e);
                        } else {
                                if (path[path_len - 1] == '\0')
                                        /* We expect a terminating NUL and don't print it */
                                        path_len --;

                                p = cescape_length(path, path_len);
                        }
                }
                if (!p)
                        return -ENOMEM;

                break;

        case AF_VSOCK:
                if (include_port) {
                        if (sa->vm.svm_cid == VMADDR_CID_ANY)
                                r = asprintf(&p, "vsock::%u", sa->vm.svm_port);
                        else
                                r = asprintf(&p, "vsock:%u:%u", sa->vm.svm_cid, sa->vm.svm_port);
                } else
                        r = asprintf(&p, "vsock:%u", sa->vm.svm_cid);
                if (r < 0)
                        return -ENOMEM;
                break;

        default:
                return -EOPNOTSUPP;
        }

        *ret = p;
        return 0;
}

int getpeername_pretty(int fd, bool include_port, char **ret) {
        union sockaddr_union sa;
        socklen_t salen = sizeof(sa);
        int r;

        assert(fd >= 0);
        assert(ret);

        if (getpeername(fd, &sa.sa, &salen) < 0)
                return -errno;

        if (sa.sa.sa_family == AF_UNIX) {
                struct ucred ucred = {};

                /* UNIX connection sockets are anonymous, so let's use
                 * PID/UID as pretty credentials instead */

                r = getpeercred(fd, &ucred);
                if (r < 0)
                        return r;

                if (asprintf(ret, "PID "PID_FMT"/UID "UID_FMT, ucred.pid, ucred.uid) < 0)
                        return -ENOMEM;

                return 0;
        }

        /* For remote sockets we translate IPv6 addresses back to IPv4
         * if applicable, since that's nicer. */

        return sockaddr_pretty(&sa.sa, salen, true, include_port, ret);
}

int getsockname_pretty(int fd, char **ret) {
        union sockaddr_union sa;
        socklen_t salen = sizeof(sa);

        assert(fd >= 0);
        assert(ret);

        if (getsockname(fd, &sa.sa, &salen) < 0)
                return -errno;

        /* For local sockets we do not translate IPv6 addresses back
         * to IPv6 if applicable, since this is usually used for
         * listening sockets where the difference between IPv4 and
         * IPv6 matters. */

        return sockaddr_pretty(&sa.sa, salen, false, true, ret);
}

int socknameinfo_pretty(union sockaddr_union *sa, socklen_t salen, char **_ret) {
        int r;
        char host[NI_MAXHOST], *ret;

        assert(_ret);

        r = getnameinfo(&sa->sa, salen, host, sizeof(host), NULL, 0, IDN_FLAGS);
        if (r != 0) {
                int saved_errno = errno;

                r = sockaddr_pretty(&sa->sa, salen, true, true, &ret);
                if (r < 0)
                        return r;

                log_debug_errno(saved_errno, "getnameinfo(%s) failed: %m", ret);
        } else {
                ret = strdup(host);
                if (!ret)
                        return -ENOMEM;
        }

        *_ret = ret;
        return 0;
}

static const char* const netlink_family_table[] = {
        [NETLINK_ROUTE] = "route",
        [NETLINK_FIREWALL] = "firewall",
        [NETLINK_INET_DIAG] = "inet-diag",
        [NETLINK_NFLOG] = "nflog",
        [NETLINK_XFRM] = "xfrm",
        [NETLINK_SELINUX] = "selinux",
        [NETLINK_ISCSI] = "iscsi",
        [NETLINK_AUDIT] = "audit",
        [NETLINK_FIB_LOOKUP] = "fib-lookup",
        [NETLINK_CONNECTOR] = "connector",
        [NETLINK_NETFILTER] = "netfilter",
        [NETLINK_IP6_FW] = "ip6-fw",
        [NETLINK_DNRTMSG] = "dnrtmsg",
        [NETLINK_KOBJECT_UEVENT] = "kobject-uevent",
        [NETLINK_GENERIC] = "generic",
        [NETLINK_SCSITRANSPORT] = "scsitransport",
        [NETLINK_ECRYPTFS] = "ecryptfs",
        [NETLINK_RDMA] = "rdma",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_FALLBACK(netlink_family, int, INT_MAX);

static const char* const socket_address_bind_ipv6_only_table[_SOCKET_ADDRESS_BIND_IPV6_ONLY_MAX] = {
        [SOCKET_ADDRESS_DEFAULT] = "default",
        [SOCKET_ADDRESS_BOTH] = "both",
        [SOCKET_ADDRESS_IPV6_ONLY] = "ipv6-only"
};

DEFINE_STRING_TABLE_LOOKUP(socket_address_bind_ipv6_only, SocketAddressBindIPv6Only);

SocketAddressBindIPv6Only socket_address_bind_ipv6_only_or_bool_from_string(const char *n) {
        int r;

        r = parse_boolean(n);
        if (r > 0)
                return SOCKET_ADDRESS_IPV6_ONLY;
        if (r == 0)
                return SOCKET_ADDRESS_BOTH;

        return socket_address_bind_ipv6_only_from_string(n);
}

bool sockaddr_equal(const union sockaddr_union *a, const union sockaddr_union *b) {
        assert(a);
        assert(b);

        if (a->sa.sa_family != b->sa.sa_family)
                return false;

        if (a->sa.sa_family == AF_INET)
                return a->in.sin_addr.s_addr == b->in.sin_addr.s_addr;

        if (a->sa.sa_family == AF_INET6)
                return memcmp(&a->in6.sin6_addr, &b->in6.sin6_addr, sizeof(a->in6.sin6_addr)) == 0;

        if (a->sa.sa_family == AF_VSOCK)
                return a->vm.svm_cid == b->vm.svm_cid;

        return false;
}

int fd_set_sndbuf(int fd, size_t n, bool increase) {
        int r, value;
        socklen_t l = sizeof(value);

        if (n > INT_MAX)
                return -ERANGE;

        r = getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &value, &l);
        if (r >= 0 && l == sizeof(value) && increase ? (size_t) value >= n*2 : (size_t) value == n*2)
                return 0;

        /* First, try to set the buffer size with SO_SNDBUF. */
        r = setsockopt_int(fd, SOL_SOCKET, SO_SNDBUF, n);
        if (r < 0)
                return r;

        /* SO_SNDBUF above may set to the kernel limit, instead of the requested size.
         * So, we need to check the actual buffer size here. */
        l = sizeof(value);
        r = getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &value, &l);
        if (r >= 0 && l == sizeof(value) && increase ? (size_t) value >= n*2 : (size_t) value == n*2)
                return 1;

        /* If we have the privileges we will ignore the kernel limit. */
        r = setsockopt_int(fd, SOL_SOCKET, SO_SNDBUFFORCE, n);
        if (r < 0)
                return r;

        return 1;
}

int fd_set_rcvbuf(int fd, size_t n, bool increase) {
        int r, value;
        socklen_t l = sizeof(value);

        if (n > INT_MAX)
                return -ERANGE;

        r = getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &value, &l);
        if (r >= 0 && l == sizeof(value) && increase ? (size_t) value >= n*2 : (size_t) value == n*2)
                return 0;

        /* First, try to set the buffer size with SO_RCVBUF. */
        r = setsockopt_int(fd, SOL_SOCKET, SO_RCVBUF, n);
        if (r < 0)
                return r;

        /* SO_RCVBUF above may set to the kernel limit, instead of the requested size.
         * So, we need to check the actual buffer size here. */
        l = sizeof(value);
        r = getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &value, &l);
        if (r >= 0 && l == sizeof(value) && increase ? (size_t) value >= n*2 : (size_t) value == n*2)
                return 1;

        /* If we have the privileges we will ignore the kernel limit. */
        r = setsockopt_int(fd, SOL_SOCKET, SO_RCVBUFFORCE, n);
        if (r < 0)
                return r;

        return 1;
}

static const char* const ip_tos_table[] = {
        [IPTOS_LOWDELAY] = "low-delay",
        [IPTOS_THROUGHPUT] = "throughput",
        [IPTOS_RELIABILITY] = "reliability",
        [IPTOS_LOWCOST] = "low-cost",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_FALLBACK(ip_tos, int, 0xff);

bool ifname_valid_full(const char *p, IfnameValidFlags flags) {
        bool numeric = true;

        /* Checks whether a network interface name is valid. This is inspired by dev_valid_name() in the kernel sources
         * but slightly stricter, as we only allow non-control, non-space ASCII characters in the interface name. We
         * also don't permit names that only container numbers, to avoid confusion with numeric interface indexes. */

        assert(!(flags & ~_IFNAME_VALID_ALL));

        if (isempty(p))
                return false;

        if (flags & IFNAME_VALID_ALTERNATIVE) {
                if (strlen(p) >= ALTIFNAMSIZ)
                        return false;
        } else {
                if (strlen(p) >= IFNAMSIZ)
                        return false;
        }

        if (dot_or_dot_dot(p))
                return false;

        for (const char *t = p; *t; t++) {
                if ((unsigned char) *t >= 127U)
                        return false;

                if ((unsigned char) *t <= 32U)
                        return false;

                if (IN_SET(*t, ':', '/'))
                        return false;

                numeric = numeric && (*t >= '0' && *t <= '9');
        }

        if (numeric) {
                if (!(flags & IFNAME_VALID_NUMERIC))
                        return false;

                /* Verify that the number is well-formatted and in range. */
                if (parse_ifindex(p) < 0)
                        return false;
        }

        return true;
}

bool address_label_valid(const char *p) {

        if (isempty(p))
                return false;

        if (strlen(p) >= IFNAMSIZ)
                return false;

        while (*p) {
                if ((uint8_t) *p >= 127U)
                        return false;

                if ((uint8_t) *p <= 31U)
                        return false;
                p++;
        }

        return true;
}

int getpeercred(int fd, struct ucred *ucred) {
        socklen_t n = sizeof(struct ucred);
        struct ucred u;
        int r;

        assert(fd >= 0);
        assert(ucred);

        r = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &u, &n);
        if (r < 0)
                return -errno;

        if (n != sizeof(struct ucred))
                return -EIO;

        /* Check if the data is actually useful and not suppressed due to namespacing issues */
        if (!pid_is_valid(u.pid))
                return -ENODATA;

        /* Note that we don't check UID/GID here, as namespace translation works differently there: instead of
         * receiving in "invalid" user/group we get the overflow UID/GID. */

        *ucred = u;
        return 0;
}

int getpeersec(int fd, char **ret) {
        _cleanup_free_ char *s = NULL;
        socklen_t n = 64;

        assert(fd >= 0);
        assert(ret);

        for (;;) {
                s = new0(char, n+1);
                if (!s)
                        return -ENOMEM;

                if (getsockopt(fd, SOL_SOCKET, SO_PEERSEC, s, &n) >= 0)
                        break;

                if (errno != ERANGE)
                        return -errno;

                s = mfree(s);
        }

        if (isempty(s))
                return -EOPNOTSUPP;

        *ret = TAKE_PTR(s);

        return 0;
}

int getpeergroups(int fd, gid_t **ret) {
        socklen_t n = sizeof(gid_t) * 64;
        _cleanup_free_ gid_t *d = NULL;

        assert(fd >= 0);
        assert(ret);

        for (;;) {
                d = malloc(n);
                if (!d)
                        return -ENOMEM;

                if (getsockopt(fd, SOL_SOCKET, SO_PEERGROUPS, d, &n) >= 0)
                        break;

                if (errno != ERANGE)
                        return -errno;

                d = mfree(d);
        }

        assert_se(n % sizeof(gid_t) == 0);
        n /= sizeof(gid_t);

        if ((socklen_t) (int) n != n)
                return -E2BIG;

        *ret = TAKE_PTR(d);

        return (int) n;
}

ssize_t send_one_fd_iov_sa(
                int transport_fd,
                int fd,
                struct iovec *iov, size_t iovlen,
                const struct sockaddr *sa, socklen_t len,
                int flags) {

        CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(int))) control = {};
        struct msghdr mh = {
                .msg_name = (struct sockaddr*) sa,
                .msg_namelen = len,
                .msg_iov = iov,
                .msg_iovlen = iovlen,
        };
        ssize_t k;

        assert(transport_fd >= 0);

        /*
         * We need either an FD or data to send.
         * If there's nothing, return an error.
         */
        if (fd < 0 && !iov)
                return -EINVAL;

        if (fd >= 0) {
                struct cmsghdr *cmsg;

                mh.msg_control = &control;
                mh.msg_controllen = sizeof(control);

                cmsg = CMSG_FIRSTHDR(&mh);
                cmsg->cmsg_level = SOL_SOCKET;
                cmsg->cmsg_type = SCM_RIGHTS;
                cmsg->cmsg_len = CMSG_LEN(sizeof(int));
                memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
        }
        k = sendmsg(transport_fd, &mh, MSG_NOSIGNAL | flags);
        if (k < 0)
                return (ssize_t) -errno;

        return k;
}

int send_one_fd_sa(
                int transport_fd,
                int fd,
                const struct sockaddr *sa, socklen_t len,
                int flags) {

        assert(fd >= 0);

        return (int) send_one_fd_iov_sa(transport_fd, fd, NULL, 0, sa, len, flags);
}

ssize_t receive_one_fd_iov(
                int transport_fd,
                struct iovec *iov, size_t iovlen,
                int flags,
                int *ret_fd) {

        CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(int))) control;
        struct msghdr mh = {
                .msg_control = &control,
                .msg_controllen = sizeof(control),
                .msg_iov = iov,
                .msg_iovlen = iovlen,
        };
        struct cmsghdr *found;
        ssize_t k;

        assert(transport_fd >= 0);
        assert(ret_fd);

        /*
         * Receive a single FD via @transport_fd. We don't care for
         * the transport-type. We retrieve a single FD at most, so for
         * packet-based transports, the caller must ensure to send
         * only a single FD per packet.  This is best used in
         * combination with send_one_fd().
         */

        k = recvmsg_safe(transport_fd, &mh, MSG_CMSG_CLOEXEC | flags);
        if (k < 0)
                return k;

        found = cmsg_find(&mh, SOL_SOCKET, SCM_RIGHTS, CMSG_LEN(sizeof(int)));
        if (!found) {
                cmsg_close_all(&mh);

                /* If didn't receive an FD or any data, return an error. */
                if (k == 0)
                        return -EIO;
        }

        if (found)
                *ret_fd = *(int*) CMSG_DATA(found);
        else
                *ret_fd = -1;

        return k;
}

int receive_one_fd(int transport_fd, int flags) {
        int fd;
        ssize_t k;

        k = receive_one_fd_iov(transport_fd, NULL, 0, flags, &fd);
        if (k == 0)
                return fd;

        /* k must be negative, since receive_one_fd_iov() only returns
         * a positive value if data was received through the iov. */
        assert(k < 0);
        return (int) k;
}
#endif /* NM_IGNORED */

ssize_t next_datagram_size_fd(int fd) {
        ssize_t l;
        int k;

        /* This is a bit like FIONREAD/SIOCINQ, however a bit more powerful. The difference being: recv(MSG_PEEK) will
         * actually cause the next datagram in the queue to be validated regarding checksums, which FIONREAD doesn't
         * do. This difference is actually of major importance as we need to be sure that the size returned here
         * actually matches what we will read with recvmsg() next, as otherwise we might end up allocating a buffer of
         * the wrong size. */

        l = recv(fd, NULL, 0, MSG_PEEK|MSG_TRUNC);
        if (l < 0) {
                if (IN_SET(errno, EOPNOTSUPP, EFAULT))
                        goto fallback;

                return -errno;
        }
        if (l == 0)
                goto fallback;

        return l;

fallback:
        k = 0;

        /* Some sockets (AF_PACKET) do not support null-sized recv() with MSG_TRUNC set, let's fall back to FIONREAD
         * for them. Checksums don't matter for raw sockets anyway, hence this should be fine. */

        if (ioctl(fd, FIONREAD, &k) < 0)
                return -errno;

        return (ssize_t) k;
}

#if 0 /* NM_IGNORED */
/* Put a limit on how many times will attempt to call accept4(). We loop
 * only on "transient" errors, but let's make sure we don't loop forever. */
#define MAX_FLUSH_ITERATIONS 1024

int flush_accept(int fd) {

        int r, b;
        socklen_t l = sizeof(b);

        /* Similar to flush_fd() but flushes all incoming connections by accepting and immediately closing
         * them. */

        if (getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &b, &l) < 0)
                return -errno;

        assert(l == sizeof(b));
        if (!b) /* Let's check if this socket accepts connections before calling accept(). accept4() can
                 * return EOPNOTSUPP if the fd is not a listening socket, which we should treat as a fatal
                 * error, or in case the incoming TCP connection triggered a network issue, which we want to
                 * treat as a transient error. Thus, let's rule out the first reason for EOPNOTSUPP early, so
                 * we can loop safely on transient errors below. */
                return -ENOTTY;

        for (unsigned iteration = 0;; iteration++) {
                int cfd;

                r = fd_wait_for_event(fd, POLLIN, 0);
                if (r < 0) {
                        if (r == -EINTR)
                                continue;

                        return r;
                }
                if (r == 0)
                        return 0;

                if (iteration >= MAX_FLUSH_ITERATIONS)
                        return log_debug_errno(SYNTHETIC_ERRNO(EBUSY),
                                               "Failed to flush connections within " STRINGIFY(MAX_FLUSH_ITERATIONS) " iterations.");

                cfd = accept4(fd, NULL, NULL, SOCK_NONBLOCK|SOCK_CLOEXEC);
                if (cfd < 0) {
                        if (errno == EAGAIN)
                                return 0;

                        if (ERRNO_IS_ACCEPT_AGAIN(errno))
                                continue;

                        return -errno;
                }

                safe_close(cfd);
        }
}
#endif /* NM_IGNORED */

struct cmsghdr* cmsg_find(struct msghdr *mh, int level, int type, socklen_t length) {
        struct cmsghdr *cmsg;

        assert(mh);

        CMSG_FOREACH(cmsg, mh)
                if (cmsg->cmsg_level == level &&
                    cmsg->cmsg_type == type &&
                    (length == (socklen_t) -1 || length == cmsg->cmsg_len))
                        return cmsg;

        return NULL;
}

#if 0 /* NM_IGNORED */
int socket_ioctl_fd(void) {
        int fd;

        /* Create a socket to invoke the various network interface ioctl()s on. Traditionally only AF_INET was good for
         * that. Since kernel 4.6 AF_NETLINK works for this too. We first try to use AF_INET hence, but if that's not
         * available (for example, because it is made unavailable via SECCOMP or such), we'll fall back to the more
         * generic AF_NETLINK. */

        fd = socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, 0);
        if (fd < 0)
                fd = socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_GENERIC);
        if (fd < 0)
                return -errno;

        return fd;
}

int sockaddr_un_unlink(const struct sockaddr_un *sa) {
        const char *p, * nul;

        assert(sa);

        if (sa->sun_family != AF_UNIX)
                return -EPROTOTYPE;

        if (sa->sun_path[0] == 0) /* Nothing to do for abstract sockets */
                return 0;

        /* The path in .sun_path is not necessarily NUL terminated. Let's fix that. */
        nul = memchr(sa->sun_path, 0, sizeof(sa->sun_path));
        if (nul)
                p = sa->sun_path;
        else
                p = memdupa_suffix0(sa->sun_path, sizeof(sa->sun_path));

        if (unlink(p) < 0)
                return -errno;

        return 1;
}
#endif /* NM_IGNORED */

int sockaddr_un_set_path(struct sockaddr_un *ret, const char *path) {
        size_t l;

        assert(ret);
        assert(path);

        /* Initialize ret->sun_path from the specified argument. This will interpret paths starting with '@' as
         * abstract namespace sockets, and those starting with '/' as regular filesystem sockets. It won't accept
         * anything else (i.e. no relative paths), to avoid ambiguities. Note that this function cannot be used to
         * reference paths in the abstract namespace that include NUL bytes in the name. */

        l = strlen(path);
        if (l < 2)
                return -EINVAL;
        if (!IN_SET(path[0], '/', '@'))
                return -EINVAL;

        /* Don't allow paths larger than the space in sockaddr_un. Note that we are a tiny bit more restrictive than
         * the kernel is: we insist on NUL termination (both for abstract namespace and regular file system socket
         * addresses!), which the kernel doesn't. We do this to reduce chance of incompatibility with other apps that
         * do not expect non-NUL terminated file system path*/
        if (l+1 > sizeof(ret->sun_path))
                return -EINVAL;

        *ret = (struct sockaddr_un) {
                .sun_family = AF_UNIX,
        };

        if (path[0] == '@') {
                /* Abstract namespace socket */
                memcpy(ret->sun_path + 1, path + 1, l); /* copy *with* trailing NUL byte */
                return (int) (offsetof(struct sockaddr_un, sun_path) + l); /* 🔥 *don't* 🔥 include trailing NUL in size */

        } else {
                assert(path[0] == '/');

                /* File system socket */
                memcpy(ret->sun_path, path, l + 1); /* copy *with* trailing NUL byte */
                return (int) (offsetof(struct sockaddr_un, sun_path) + l + 1); /* include trailing NUL in size */
        }
}

int socket_bind_to_ifname(int fd, const char *ifname) {
        assert(fd >= 0);

        /* Call with NULL to drop binding */

        if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen_ptr(ifname)) < 0)
                return -errno;

        return 0;
}

int socket_bind_to_ifindex(int fd, int ifindex) {
        char ifname[IF_NAMESIZE + 1];
        int r;

        assert(fd >= 0);

        if (ifindex <= 0) {
                /* Drop binding */
                if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, NULL, 0) < 0)
                        return -errno;

                return 0;
        }

        r = setsockopt_int(fd, SOL_SOCKET, SO_BINDTOIFINDEX, ifindex);
        if (r != -ENOPROTOOPT)
                return r;

        /* Fall back to SO_BINDTODEVICE on kernels < 5.0 which didn't have SO_BINDTOIFINDEX */
        if (!format_ifname(ifindex, ifname))
                return -errno;

        return socket_bind_to_ifname(fd, ifname);
}

ssize_t recvmsg_safe(int sockfd, struct msghdr *msg, int flags) {
        ssize_t n;

        /* A wrapper around recvmsg() that checks for MSG_CTRUNC, and turns it into an error, in a reasonably
         * safe way, closing any SCM_RIGHTS fds in the error path.
         *
         * Note that unlike our usual coding style this might modify *msg on failure. */

        n = recvmsg(sockfd, msg, flags);
        if (n < 0)
                return -errno;

        if (FLAGS_SET(msg->msg_flags, MSG_CTRUNC)) {
                cmsg_close_all(msg);
                return -EXFULL; /* a recognizable error code */
        }

        return n;
}

#if 0 /* NM_IGNORED */
int socket_get_family(int fd, int *ret) {
        int af;
        socklen_t sl = sizeof(af);

        if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &af, &sl) < 0)
                return -errno;

        if (sl != sizeof(af))
                return -EINVAL;

        return af;
}

int socket_set_recvpktinfo(int fd, int af, bool b) {
        int r;

        if (af == AF_UNSPEC) {
                r = socket_get_family(fd, &af);
                if (r < 0)
                        return r;
        }

        switch (af) {

        case AF_INET:
                return setsockopt_int(fd, IPPROTO_IP, IP_PKTINFO, b);

        case AF_INET6:
                return setsockopt_int(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, b);

        case AF_NETLINK:
                return setsockopt_int(fd, SOL_NETLINK, NETLINK_PKTINFO, b);

        case AF_PACKET:
                return setsockopt_int(fd, SOL_PACKET, PACKET_AUXDATA, b);

        default:
                return -EAFNOSUPPORT;
        }
}

int socket_set_unicast_if(int fd, int af, int ifi) {
        be32_t ifindex_be = htobe32(ifi);
        int r;

        if (af == AF_UNSPEC) {
                r = socket_get_family(fd, &af);
                if (r < 0)
                        return r;
        }

        switch (af) {

        case AF_INET:
                if (setsockopt(fd, IPPROTO_IP, IP_UNICAST_IF, &ifindex_be, sizeof(ifindex_be)) < 0)
                        return -errno;

                return 0;

        case AF_INET6:
                if (setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_IF, &ifindex_be, sizeof(ifindex_be)) < 0)
                        return -errno;

                return 0;

        default:
                return -EAFNOSUPPORT;
        }
}

int socket_set_option(int fd, int af, int opt_ipv4, int opt_ipv6, int val) {
        int r;

        if (af == AF_UNSPEC) {
                r = socket_get_family(fd, &af);
                if (r < 0)
                        return r;
        }

        switch (af) {

        case AF_INET:
                return setsockopt_int(fd, IPPROTO_IP, opt_ipv4, val);

        case AF_INET6:
                return setsockopt_int(fd, IPPROTO_IPV6, opt_ipv6, val);

        default:
                return -EAFNOSUPPORT;
        }
}

int socket_get_mtu(int fd, int af, size_t *ret) {
        int mtu, r;

        if (af == AF_UNSPEC) {
                r = socket_get_family(fd, &af);
                if (r < 0)
                        return r;
        }

        switch (af) {

        case AF_INET:
                r = getsockopt_int(fd, IPPROTO_IP, IP_MTU, &mtu);
                break;

        case AF_INET6:
                r = getsockopt_int(fd, IPPROTO_IPV6, IPV6_MTU, &mtu);
                break;

        default:
                return -EAFNOSUPPORT;
        }

        if (r < 0)
                return r;
        if (mtu <= 0)
                return -EINVAL;

        *ret = (size_t) mtu;
        return 0;
}
#endif /* NM_IGNORED */
