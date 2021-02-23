/*
 * IPv4 Address Conflict Detection
 *
 * This file contains the main context initialization and management functions,
 * as well as a bunch of utilities used through the n-acd modules.
 */

/**
 * DOC: IPv4 Address Conflict Detection
 *
 * The `n-acd` project implements the IPv4 Address Conflict Detection protocol
 * as defined in RFC-5227. The protocol originates in the IPv4 Link Local
 * Address selection but was later on generalized and resulted in `ACD`. The
 * idea is to use `ARP` to query a link for an address to see whether it
 * already exists on the network, as well as defending an address that is in
 * use on a network interface. Furthermore, `ACD` provides passive diagnostics
 * for administrators, as it will detect address conflicts automatically, which
 * then can be logged or shown to a user.
 *
 * The main context object of `n-acd` is the `NAcd` structure. It is a passive
 * ref-counted context object which drives `ACD` probes running on it. A
 * context is specific to a linux network device and transport. If multiple
 * network devices are used, then separate `NAcd` contexts must be deployed.
 *
 * The `NAcdProbe` object drives a single `ACD` state-machine. A probe is
 * created on an `NAcd` context by providing an address to probe for. The probe
 * will then raise notifications whether the address conflict detection found
 * something, or whether the address is ready to be used. Optionally, the probe
 * will then enter into passive mode and defend the address as long as it is
 * kept active.
 *
 * Note that the `n-acd` project only implements the networking protocol. It
 * never queries or modifies network interfaces. It completely relies on the
 * API user to react to notifications and update network interfaces
 * respectively. `n-acd` uses an event-mechanism on every context object. All
 * events raise by any probe or operation on a given context will queue all
 * events on that context object. The event-queue can then be drained by the
 * API user. All events are properly asynchronous and designed in a way that no
 * synchronous reaction to any event is required. That is, the events are
 * carefully designed to allow forwarding via IPC (or even networks) to a
 * controller that handles them and specifies how to react. Furthermore, none
 * of the function calls of `n-acd` require synchronous error handling.
 * Instead, functions only ever return values on fatal errors. Everything else
 * is queued as events, thus guaranteeing that synchronous handling of return
 * values is not required. Exceptions are functions that do not affect internal
 * state or do not have an associated context object.
 */

#include <assert.h>
#include <c-list.h>
#include <c-rbtree.h>
#include <c-siphash.h>
#include <c-stdaux.h>
#include <endian.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/if_packet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include "n-acd.h"
#include "n-acd-private.h"

enum {
        N_ACD_EPOLL_TIMER,
        N_ACD_EPOLL_SOCKET,
};

static int n_acd_get_random(unsigned int *random) {
        uint8_t hash_seed[] = {
                0x3a, 0x0c, 0xa6, 0xdd, 0x44, 0xef, 0x5f, 0x7a,
                0x5e, 0xd7, 0x25, 0x37, 0xbf, 0x4e, 0x80, 0xa1,
        };
        CSipHash hash = C_SIPHASH_NULL;
        struct timespec ts;
        const uint8_t *p;
        int r;

        /*
         * We need random jitter for all timeouts when handling ARP probes. Use
         * AT_RANDOM to get a seed for rand_r(3p), if available (should always
         * be available on linux). See the time-out scheduler for details.
         * Additionally, we include the current time in the seed. This avoids
         * using the same jitter in case you run multiple ACD engines in the
         * same process. Lastly, the seed is hashed with SipHash24 to avoid
         * exposing the value of AT_RANDOM on the network.
         */
        c_siphash_init(&hash, hash_seed);

        p = (const uint8_t *)getauxval(AT_RANDOM);
        if (p)
                c_siphash_append(&hash, p, 16);

        r = clock_gettime(CLOCK_MONOTONIC, &ts);
        if (r < 0)
                return -c_errno();

        c_siphash_append(&hash, (const uint8_t *)&ts.tv_sec, sizeof(ts.tv_sec));
        c_siphash_append(&hash, (const uint8_t *)&ts.tv_nsec, sizeof(ts.tv_nsec));

        *random = c_siphash_finalize(&hash);
        return 0;
}

static int n_acd_socket_new(int *fdp, int fd_bpf_prog, NAcdConfig *config) {
        const struct sockaddr_ll address = {
                .sll_family = AF_PACKET,
                .sll_protocol = htobe16(ETH_P_ARP),
                .sll_ifindex = config->ifindex,
                .sll_halen = ETH_ALEN,
                .sll_addr = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
        };
        int r, s = -1;

        s = socket(PF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (s < 0) {
                r = -c_errno();
                goto error;
        }

        if (fd_bpf_prog >= 0) {
                r = setsockopt(s, SOL_SOCKET, SO_ATTACH_BPF, &fd_bpf_prog, sizeof(fd_bpf_prog));
                if (r < 0) {
                        r = -c_errno();
                        goto error;
                }
        }

        r = bind(s, (struct sockaddr *)&address, sizeof(address));
        if (r < 0) {
                r = -c_errno();
                goto error;
        }

        *fdp = s;
        s = -1;
        return 0;

error:
        if (s >= 0)
                close(s);
        return r;
}

/**
 * n_acd_config_new() - create configuration object
 * @configp:                    output argument for new configuration
 *
 * This creates a new configuration object and provides it to the caller. The
 * object is fully owned by the caller upon function return.
 *
 * A configuration object is a passive structure that is used to collect
 * information that is then passed to a constructor or other function. A
 * configuration never validates the data, but it is up to the consumer of a
 * configuration to do that.
 *
 * Return: 0 on success, negative error code on failure.
 */
_c_public_ int n_acd_config_new(NAcdConfig **configp) {
        _c_cleanup_(n_acd_config_freep) NAcdConfig *config = NULL;

        config = malloc(sizeof(*config));
        if (!config)
                return -ENOMEM;

        *config = (NAcdConfig)N_ACD_CONFIG_NULL(*config);

        *configp = config;
        config = NULL;
        return 0;
}

/**
 * n_acd_config_free() - destroy configuration object
 * @config:                     configuration to operate on, or NULL
 *
 * This destroys the configuration object @config. If @config is NULL, this is
 * a no-op.
 *
 * Return: NULL is returned.
 */
_c_public_ NAcdConfig *n_acd_config_free(NAcdConfig *config) {
        if (!config)
                return NULL;

        free(config);

        return NULL;
}

/**
 * n_acd_config_set_ifindex() - set ifindex property
 * @config:                     configuration to operate on
 * @ifindex:                    ifindex to set
 *
 * This sets the @ifindex property of the configuration object. Any previous
 * value is overwritten.
 *
 * A valid ifindex is a 32bit integer greater than 0. Any other value is
 * treated as unspecified.
 *
 * The ifindex corresponds to the interface index provided by the linux kernel.
 * It specifies the network device to be used.
 */
_c_public_ void n_acd_config_set_ifindex(NAcdConfig *config, int ifindex) {
        config->ifindex = ifindex;
}

/**
 * n_acd_config_set_transport() - set transport property
 * @config:                     configuration to operate on
 * @transport:                  transport to set
 *
 * This specifies the transport to use. A transport must be one of the
 * `N_ACD_TRANSPORT_*` identifiers. It selects which transport protocol `n-acd`
 * will run on.
 */
_c_public_ void n_acd_config_set_transport(NAcdConfig *config, unsigned int transport) {
        config->transport = transport;
}

/**
 * n_acd_config_set_mac() - set mac property
 * @config:                     configuration to operate on
 * @mac:                        mac to set
 *
 * This specifies the hardware address (also referred to as `MAC Address`) to
 * use. Any hardware address can be specified. It is the caller's
 * responsibility to make sure the address can actually be used.
 *
 * The address in @mac is copied into @config. It does not have to be retained
 * by the caller.
 */
_c_public_ void n_acd_config_set_mac(NAcdConfig *config, const uint8_t *mac, size_t n_mac) {
        /*
         * We truncate the address at the maximum we support. We still remember
         * the original length, so any consumer of this configuration can then
         * complain about an unsupported address length. This allows us to
         * avoid a memory allocation here and having to return `int`.
         */
        config->n_mac = n_mac;
        memcpy(config->mac, mac, n_mac > ETH_ALEN ? ETH_ALEN : n_mac);
}

int n_acd_event_node_new(NAcdEventNode **nodep) {
        NAcdEventNode *node;

        node = malloc(sizeof(*node));
        if (!node)
                return -ENOMEM;

        *node = (NAcdEventNode)N_ACD_EVENT_NODE_NULL(*node);

        *nodep = node;
        return 0;
}

NAcdEventNode *n_acd_event_node_free(NAcdEventNode *node) {
        if (!node)
                return NULL;

        c_list_unlink(&node->probe_link);
        c_list_unlink(&node->acd_link);
        free(node);

        return NULL;
}

int n_acd_ensure_bpf_map_space(NAcd *acd) {
        NAcdProbe *probe;
        _c_cleanup_(c_closep) int fd_map = -1, fd_prog = -1;
        size_t  max_map;
        int r;

        if (acd->n_bpf_map < acd->max_bpf_map)
                return 0;

        max_map = 2 * acd->max_bpf_map;

        r = n_acd_bpf_map_create(&fd_map, max_map);
        if (r)
                return r;

        c_rbtree_for_each_entry(probe, &acd->ip_tree, ip_node) {
                r = n_acd_bpf_map_add(fd_map, &probe->ip);
                if (r)
                        return r;
        }

        r = n_acd_bpf_compile(&fd_prog, fd_map, (struct ether_addr*) acd->mac);
        if (r)
                return r;

        if (fd_prog >= 0) {
                r = setsockopt(acd->fd_socket, SOL_SOCKET, SO_ATTACH_BPF, &fd_prog, sizeof(fd_prog));
                if (r)
                        return -c_errno();
        }

        if (acd->fd_bpf_map >= 0)
                close(acd->fd_bpf_map);
        acd->fd_bpf_map = fd_map;
        fd_map = -1;
        acd->max_bpf_map = max_map;
        return 0;
}

/**
 * n_acd_new() - create a new ACD context
 * @acdp:                       output argument for new context object
 * @config:                     configuration parameters
 *
 * Create a new ACD context and return it in @acdp. The configuration @config
 * must be initialized by the caller and must specify a valid network
 * interface, transport mechanism, as well as hardware address compatible with
 * the selected transport. The configuration is copied into the context. The
 * @config object thus does not have to be retained by the caller.
 *
 * Return: 0 on success, negative error code on failure.
 */
_c_public_ int n_acd_new(NAcd **acdp, NAcdConfig *config) {
        _c_cleanup_(n_acd_unrefp) NAcd *acd = NULL;
        _c_cleanup_(c_closep) int fd_bpf_prog = -1;
        struct epoll_event eevent;
        int r;

        if (config->ifindex <= 0 ||
            config->transport != N_ACD_TRANSPORT_ETHERNET ||
            config->n_mac != ETH_ALEN ||
            !memcmp(config->mac, (uint8_t[ETH_ALEN]){ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, ETH_ALEN))
                return N_ACD_E_INVALID_ARGUMENT;

        acd = malloc(sizeof(*acd));
        if (!acd)
                return -ENOMEM;

        *acd = (NAcd)N_ACD_NULL(*acd);
        acd->ifindex = config->ifindex;
        memcpy(acd->mac, config->mac, ETH_ALEN);

        r = n_acd_get_random(&acd->seed);
        if (r)
                return r;

        acd->fd_epoll = epoll_create1(EPOLL_CLOEXEC);
        if (acd->fd_epoll < 0)
                return -c_errno();

        r = timer_init(&acd->timer);
        if (r < 0)
                return r;

        acd->max_bpf_map = 8;

        r = n_acd_bpf_map_create(&acd->fd_bpf_map, acd->max_bpf_map);
        if (r)
                return r;

        r = n_acd_bpf_compile(&fd_bpf_prog, acd->fd_bpf_map, (struct ether_addr*) acd->mac);
        if (r)
                return r;

        r = n_acd_socket_new(&acd->fd_socket, fd_bpf_prog, config);
        if (r)
                return r;

        eevent = (struct epoll_event){
                .events = EPOLLIN,
                .data.u32 = N_ACD_EPOLL_TIMER,
        };
        r = epoll_ctl(acd->fd_epoll, EPOLL_CTL_ADD, acd->timer.fd, &eevent);
        if (r < 0)
                return -c_errno();

        eevent = (struct epoll_event){
                .events = EPOLLIN,
                .data.u32 = N_ACD_EPOLL_SOCKET,
        };
        r = epoll_ctl(acd->fd_epoll, EPOLL_CTL_ADD, acd->fd_socket, &eevent);
        if (r < 0)
                return -c_errno();

        *acdp = acd;
        acd = NULL;
        return 0;
}

static void n_acd_free_internal(NAcd *acd) {
        NAcdEventNode *node, *t_node;

        if (!acd)
                return;

        c_list_for_each_entry_safe(node, t_node, &acd->event_list, acd_link)
                n_acd_event_node_free(node);

        c_assert(c_rbtree_is_empty(&acd->ip_tree));

        if (acd->fd_socket >= 0) {
                c_assert(acd->fd_epoll >= 0);
                epoll_ctl(acd->fd_epoll, EPOLL_CTL_DEL, acd->fd_socket, NULL);
                close(acd->fd_socket);
                acd->fd_socket = -1;
        }

        if (acd->fd_bpf_map >= 0) {
                close(acd->fd_bpf_map);
                acd->fd_bpf_map = -1;
        }

        if (acd->timer.fd >= 0) {
                c_assert(acd->fd_epoll >= 0);
                epoll_ctl(acd->fd_epoll, EPOLL_CTL_DEL, acd->timer.fd, NULL);
                timer_deinit(&acd->timer);
        }

        if (acd->fd_epoll >= 0) {
                close(acd->fd_epoll);
                acd->fd_epoll = -1;
        }

        free(acd);
}

/**
 * n_acd_ref() - acquire reference
 * @acd:                        context to operate on, or NULL
 *
 * This acquires a single reference to the context specified as @acd. If @acd
 * is NULL, this is a no-op.
 *
 * Return: @acd is returned.
 */
_c_public_ NAcd *n_acd_ref(NAcd *acd) {
        if (acd)
                ++acd->n_refs;
        return acd;
}

/**
 * n_acd_unref() - release reference
 * @acd:                        context to operate on, or NULL
 *
 * This releases a single reference to the context @acd. If this is the last
 * reference, the context is torn down and deallocated.
 *
 * Return: NULL is returned.
 */
_c_public_ NAcd *n_acd_unref(NAcd *acd) {
        if (acd && !--acd->n_refs)
                n_acd_free_internal(acd);
        return NULL;
}

int n_acd_raise(NAcd *acd, NAcdEventNode **nodep, unsigned int event) {
        NAcdEventNode *node;
        int r;

        r = n_acd_event_node_new(&node);
        if (r)
                return r;

        node->event.event = event;
        c_list_link_tail(&acd->event_list, &node->acd_link);

        if (nodep)
                *nodep = node;
        return 0;
}

int n_acd_send(NAcd *acd, const struct in_addr *tpa, const struct in_addr *spa) {
        struct sockaddr_ll address = {
                .sll_family = AF_PACKET,
                .sll_protocol = htobe16(ETH_P_ARP),
                .sll_ifindex = acd->ifindex,
                .sll_halen = ETH_ALEN,
                .sll_addr = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
        };
        struct ether_arp arp = {
                .ea_hdr = {
                        .ar_hrd = htobe16(ARPHRD_ETHER),
                        .ar_pro = htobe16(ETHERTYPE_IP),
                        .ar_hln = sizeof(acd->mac),
                        .ar_pln = sizeof(uint32_t),
                        .ar_op = htobe16(ARPOP_REQUEST),
                },
        };
        ssize_t l;
        int r;

        memcpy(arp.arp_sha, acd->mac, sizeof(acd->mac));
        memcpy(arp.arp_tpa, &tpa->s_addr, sizeof(uint32_t));

        if (spa)
                memcpy(arp.arp_spa, &spa->s_addr, sizeof(spa->s_addr));

        l = sendto(acd->fd_socket,
                   &arp,
                   sizeof(arp),
                   MSG_NOSIGNAL,
                   (struct sockaddr *)&address,
                   sizeof(address));
        if (l < 0) {
                if (errno == EAGAIN || errno == ENOBUFS) {
                        /*
                         * We never maintain outgoing queues. We rely on the
                         * network device to do that for us. In case the queues
                         * are full, or the kernel refuses to queue the packet
                         * for other reasons, we must tell our caller that the
                         * packet was dropped.
                         */
                        return N_ACD_E_DROPPED;
                } else if (errno == ENETDOWN || errno == ENXIO) {
                        /*
                         * These errors happen if the network device went down
                         * or was actually removed. We always propagate this as
                         * event, so the user can react accordingly (similarly
                         * to the recvmmsg(2) handler). In case the user does
                         * not immediately react, we also tell our caller that
                         * the packet was dropped, so we don't erroneously
                         * treat this as success.
                         */

                        r = n_acd_raise(acd, NULL, N_ACD_EVENT_DOWN);
                        if (r)
                                return r;

                        return N_ACD_E_DROPPED;
                }

                /*
                 * Random network error. We treat this as fatal and propagate
                 * the error, so it is noticed and can be investigated.
                 */
                return -c_errno();
        } else if (l != (ssize_t)sizeof(arp)) {
                /*
                 * Ugh, the kernel modified the packet. This is unexpected. We
                 * consider the packet lost.
                 */
                return N_ACD_E_DROPPED;
        }

        return 0;
}

/**
 * n_acd_get_fd() - get pollable file descriptor
 * @acd:                        context object to operate on
 * @fdp:                        output argument for file descriptor
 *
 * This returns the backing file-descriptor of the context object @acd. The
 * file-descriptor is owned by @acd and valid as long as @acd is. The
 * file-descriptor never changes, so it can be cached by the caller as long as
 * they hold a reference to @acd.
 *
 * The file-descriptor is internal to the @acd context and should not be
 * modified by the caller. It is only exposed to allow the caller to poll on
 * it. Whenever the file-descriptor polls readable, n_acd_dispatch() should be
 * called.
 *
 * Currently, the file-descriptor is an epoll-fd.
 */
_c_public_ void n_acd_get_fd(NAcd *acd, int *fdp) {
        *fdp = acd->fd_epoll;
}

static int n_acd_handle_timeout(NAcd *acd) {
        NAcdProbe *probe;
        uint64_t now;
        int r;

        /*
         * Read the current time once, and handle all timeouts that triggered
         * before the current time. Rereading the current time in each loop
         * might risk creating a live-lock, and the fact that we read the
         * time after reading the timer guarantees that the timeout which
         * woke us up is handled.
         *
         * When there are no more timeouts to handle at the given time, we
         * rearm the timer to potentially wake us up again in the future.
         */
        timer_now(&acd->timer, &now);

        for (;;) {
                Timeout *timeout;

                r = timer_pop_timeout(&acd->timer, now, &timeout);
                if (r < 0) {
                        return r;
                } else if (!timeout) {
                        /*
                         * There are no more timeouts pending before @now. Rearm
                         * the timer to fire again at the next timeout.
                         */
                        timer_rearm(&acd->timer);
                        break;
                }

                probe = (void *)timeout - offsetof(NAcdProbe, timeout);
                r = n_acd_probe_handle_timeout(probe);
                if (r)
                        return r;
        }

        return 0;
}

static int n_acd_handle_packet(NAcd *acd, struct ether_arp *packet) {
        bool hard_conflict;
        NAcdProbe *probe;
        uint32_t addr;
        CRBNode *node;
        int r;

        /*
         * We are interested in 2 kinds of ARP messages:
         *
         *  1) Someone who is *NOT* us sends *ANY* ARP message with our IP
         *     address as sender. This is never good, because it implies an
         *     address conflict.
         *     We call this a hard-conflict.
         *
         *  2) Someone who is *NOT* us sends an ARP REQUEST without any sender
         *     IP, but our IP as target. This implies someone else performs an
         *     ARP Probe with our address. This also implies a conflict, but
         *     one that can be resolved by responding to the probe.
         *     We call this a soft-conflict.
         *
         * We are never interested in any other ARP message. The kernel already
         * deals with everything else, hence, we can silently ignore those.
         *
         * Now, we simply check whether a sender-address is set. This allows us
         * to distinguish both cases. We then check further conditions, so we
         * can bail out early if neither is the case.
         *
         * Lastly, we perform a lookup in our probe-set to check whether the
         * address actually matches, so we can let these probes dispatch the
         * message. Note that we allow duplicate probes, so we need to dispatch
         * each matching probe, not just one.
         */

        if (memcmp(packet->arp_spa, (uint8_t[4]){ }, sizeof(packet->arp_spa))) {
                memcpy(&addr, packet->arp_spa, sizeof(addr));
                hard_conflict = true;
        } else if (packet->ea_hdr.ar_op == htobe16(ARPOP_REQUEST)) {
                memcpy(&addr, packet->arp_tpa, sizeof(addr));
                hard_conflict = false;
        } else {
                /*
                 * The BPF filter will not let through any other packet.
                 */
                return -EIO;
        }

        /* Find top-most node that matches @addr. */
        node = acd->ip_tree.root;
        while (node) {
                probe = c_rbnode_entry(node, NAcdProbe, ip_node);
                if (addr < probe->ip.s_addr)
                        node = node->left;
                else if (addr > probe->ip.s_addr)
                        node = node->right;
                else
                        break;
        }

        /*
         * If the address is unknown, we drop the package. This might happen if
         * the kernel queued the packet and passed the BPF filter, but we
         * modified the set before dequeuing the message.
         */
        if (!node)
                return 0;

        /* Forward to left-most child that still matches @addr. */
        while (node->left && addr == c_rbnode_entry(node->left,
                                                    NAcdProbe,
                                                    ip_node)->ip.s_addr)
                node = node->left;

        /* Iterate all matching entries in-order. */
        do {
                probe = c_rbnode_entry(node, NAcdProbe, ip_node);

                r = n_acd_probe_handle_packet(probe, packet, hard_conflict);
                if (r)
                        return r;

                node = c_rbnode_next(node);
        } while (node && addr == c_rbnode_entry(node,
                                                NAcdProbe,
                                                ip_node)->ip.s_addr);

        return 0;
}

static int n_acd_dispatch_timer(NAcd *acd, struct epoll_event *event) {
        int r;

        if (event->events & (EPOLLHUP | EPOLLERR)) {
                /*
                 * There is no way to handle either gracefully. If we ignored
                 * them, we would busy-loop, so lets rather forward the error
                 * to the caller.
                 */
                return -EIO;
        }

        if (event->events & EPOLLIN) {
                r = timer_read(&acd->timer);
                if (r <= 0)
                        return r;

                c_assert(r == TIMER_E_TRIGGERED);

                /*
                 * A timer triggered, handle all pending timeouts at a given
                 * point in time. There can only be a finite number of pending
                 * timeouts, any new ones will be in the future, so not handled
                 * now, but guaranteed to wake us up again when they do trigger.
                 */
                r = n_acd_handle_timeout(acd);
                if (r)
                        return r;
        }

        return 0;
}

static bool n_acd_packet_is_valid(NAcd *acd, void *packet, size_t n_packet) {
        struct ether_arp *arp;

        /*
         * The eBPF filter will ensure that this function always returns true, however,
         * this allows the eBPF filter to be an optional optimization which is necessary
         * on older kernels.
         *
         * See comments in n-acd-bpf.c for details.
         */

        if (n_packet != sizeof(*arp))
                return false;

        arp = packet;

        if (arp->arp_hrd != htobe16(ARPHRD_ETHER))
                return false;

        if (arp->arp_pro != htobe16(ETHERTYPE_IP))
                return false;

        if (arp->arp_hln != sizeof(struct ether_addr))
                return false;

        if (arp->arp_pln != sizeof(struct in_addr))
                return false;

        if (!memcmp(arp->arp_sha, acd->mac, sizeof(struct ether_addr)))
                return false;

        if (memcmp(arp->arp_spa, &((struct in_addr) { INADDR_ANY }), sizeof(struct in_addr))) {
                if (arp->arp_op != htobe16(ARPOP_REQUEST) && arp->arp_op != htobe16(ARPOP_REPLY))
                        return false;
        } else if (arp->arp_op != htobe16(ARPOP_REQUEST)) {
                return false;
        }

        return true;
}

static int n_acd_dispatch_socket(NAcd *acd, struct epoll_event *event) {
        const size_t n_batch = 8;
        struct mmsghdr msgs[n_batch];
        struct iovec iovecs[n_batch];
        struct ether_arp data[n_batch];
        size_t i;
        int r, n;

        for (i = 0; i < n_batch; ++i) {
                iovecs[i].iov_base = data + i;
                iovecs[i].iov_len = sizeof(data[i]);
                msgs[i].msg_hdr = (struct msghdr){
                        .msg_iov = iovecs + i,
                        .msg_iovlen = 1,
                };
        }

        /*
         * We always directly call into recvmmsg(2), regardless which EPOLL*
         * event is signalled. On sockets, the recv(2)-family of syscalls does
         * a suitable job of handling all possible scenarios and telling us
         * about it. Hence, lets take the easy route and always ask the kernel
         * about the current state.
         */
        n = recvmmsg(acd->fd_socket, msgs, n_batch, 0, NULL);
        if (n < 0) {
                if (errno == ENETDOWN) {
                        /*
                         * We get ENETDOWN if the network-device goes down or
                         * is removed. This error is temporary and only queued
                         * once. Subsequent reads will simply return EAGAIN
                         * until the device is up again and has data queued.
                         * Usually, the caller should tear down all probes when
                         * an interface goes down, but we leave it up to the
                         * caller to decide what to do. We propagate the code
                         * and continue.
                         */
                        return n_acd_raise(acd, NULL, N_ACD_EVENT_DOWN);
                } else if (errno == EAGAIN) {
                        /*
                         * There is no more data queued and we did not get
                         * preempted. Everything is good to go.
                         * As a safety-net against busy-looping, we do check
                         * for HUP/ERR. Neither should be set, since they imply
                         * error-dequeue behavior on all socket calls. Lets
                         * fail hard if we trigger it, so we can investigate.
                         */
                        if (event->events & (EPOLLHUP | EPOLLERR))
                                return -EIO;

                        return 0;
                } else {
                        /*
                         * Something went wrong. Propagate the error-code, so
                         * this can be investigated.
                         */
                        return -c_errno();
                }
        } else if (n >= (ssize_t)n_batch) {
                /*
                 * If all buffers were filled with data, we cannot be sure that
                 * there is nothing left to read. But to avoid starvation, we
                 * cannot loop on this condition. Instead, we mark the context
                 * as preempted so the caller can call us again.
                 * Note that in level-triggered event-loops this condition can
                 * be neglected, but in edge-triggered event-loops it is
                 * crucial to forward this information.
                 *
                 * On the other hand, there are several conditions where the
                 * kernel might return less batches than requested, but was
                 * still preempted. However, all of those cases require the
                 * preemption to have triggered a wakeup *after* we entered
                 * recvmmsg(). Hence, even if we did not recognize the
                 * preemption, an edge must have triggered and as such we will
                 * handle the event on the next turn.
                 */
                acd->preempted = true;
        }

        for (i = 0; (ssize_t)i < n; ++i) {
                if (!n_acd_packet_is_valid(acd, data + i, msgs[i].msg_len))
                        continue;
                /*
                 * Handle the packet. Bail out if something went wrong. Note
                 * that this must be fatal errors, since we discard all other
                 * packets that follow.
                 */
                r = n_acd_handle_packet(acd, data + i);
                if (r)
                        return r;
        }

        return 0;
}

/**
 * n_acd_dispatch() - dispatch context
 * @acd:                        context object to operate on
 *
 * This dispatches the internal state-machine of all probes and operations
 * running on the context @acd.
 *
 * Any outside effect or event triggered by this dispatcher will be queued on
 * the event-queue of @acd. Whenever the dispatcher returns, the caller is
 * required to drain the event-queue via n_acd_pop_event() until it is empty.
 *
 * This function dispatches as many events as possible up to a static limit to
 * prevent stalling execution. If the static limit is reached, this function
 * will return with N_ACD_E_PREEMPTED, otherwise 0 is returned. In most cases
 * preemption can be ignored, because level-triggered event notification
 * handles it automatically. However, in case of edge-triggered event
 * mechanisms, the caller must make sure to call the dispatcher again.
 *
 * Return: 0 on success, N_ACD_E_PREEMPTED on preemption, negative error code
 *         on failure.
 */
_c_public_ int n_acd_dispatch(NAcd *acd) {
        struct epoll_event events[2];
        int n, i, r = 0;

        n = epoll_wait(acd->fd_epoll, events, sizeof(events) / sizeof(*events), 0);
        if (n < 0) {
                /* Linux never returns EINTR if `timeout == 0'. */
                return -c_errno();
        }

        acd->preempted = false;

        for (i = 0; i < n; ++i) {
                switch (events[i].data.u32) {
                case N_ACD_EPOLL_TIMER:
                        r = n_acd_dispatch_timer(acd, events + i);
                        break;
                case N_ACD_EPOLL_SOCKET:
                        r = n_acd_dispatch_socket(acd, events + i);
                        break;
                default:
                        c_assert(0);
                        r = 0;
                        break;
                }

                if (r)
                        return r;
        }

        return acd->preempted ? N_ACD_E_PREEMPTED : 0;
}

/**
 * n_acd_pop_event() - get the next pending event
 * @acd:                        context object to operate on
 * @eventp:                     output argument for the event
 *
 * Returns a pointer to the next pending event. The event is still owend by
 * the context, and is only valid until the next call to n_acd_pop_event()
 * or until the owning object is freed (either the ACD context or the indicated
 * probe object).
 *
 * An event either originates on the ACD context, or one of the configured
 * probes. If the event-type has a 'probe' pointer, it originated on the
 * indicated probe (which is *never* NULL), otherwise it originated on the
 * context.
 *
 * Users must call this function repeatedly until either an error is returned,
 * or the event-pointer is NULL. Wakeups on the epoll-fd are only guaranteed
 * for each batch of events. Hence, it is the callers responsibility to drain
 * the event-queue somehow after each call to n_acd_dispatch(). Note that
 * events can only be added by n_acd_dispatch(), hence, you cannot live-lock
 * when draining the event queue.
 *
 * The possible events are:
 *  * N_ACD_EVENT_READY:    A configured IP address was probed successfully
 *                          and is ready to be used. Once configured on the
 *                          interface, the caller must call n_acd_announce()
 *                          to announce and start defending the address.
 *  * N_ACD_EVENT_USED:     Someone is already using the IP address being
 *                          probed. The probe is put into stopped state and
 *                          should be freed by the caller.
 *  * N_ACD_EVENT_DEFENDED: A conflict was detected for an announced IP
 *                          address, and the engine attempted to defend it.
 *                          This is purely informational, and no action is
 *                          required by the caller.
 *  * N_ACD_EVENT_CONFLICT: A conflict was detected for an announced IP
 *                          address, and the probe was not able to defend
 *                          it (according to the configured policy). The
 *                          probe halted, the caller must stop using
 *                          the address immediately, and should free the probe.
 *  * N_ACD_EVENT_DOWN:     The specified network interface was put down. The
 *                          user is recommended to free *ALL* probes and
 *                          recreate them as soon as the interface is up again.
 *                          Note that this event is purely informational. The
 *                          probes will continue running, but all packets will
 *                          be blackholed, and no network packets are received,
 *                          until the network is back up again. Hence, from an
 *                          operational perspective, the legitimacy of the ACD
 *                          probes is lost and the user better re-probes all
 *                          addresses.
 *
 * Returns: 0 on success, negative error code on failure. The popped event is
 *          returned in @eventp. If no event is pending, NULL is placed in
 *          @eventp and 0 is returned. If an error is returned, @eventp is left
 *          untouched.
 */
_c_public_ int n_acd_pop_event(NAcd *acd, NAcdEvent **eventp) {
        NAcdEventNode *node, *t_node;

        c_list_for_each_entry_safe(node, t_node, &acd->event_list, acd_link) {
                if (node->is_public) {
                        n_acd_event_node_free(node);
                        continue;
                }

                node->is_public = true;
                *eventp = &node->event;
                return 0;
        }

        *eventp = NULL;
        return 0;
}

/**
 * n_acd_probe() - start new probe
 * @acd:                        context object to operate on
 * @probep:                     output argument for new probe
 * @config:                     probe configuration
 *
 * This creates a new probe on the context @acd and returns the probe in
 * @probep. The configuration @config must provide valid probe parameters. At
 * least a valid IP address must be provided through the configuration.
 *
 * This function does not reject duplicate probes for the same address. It is
 * the caller's decision whether duplicates are allowed or not. But note that
 * duplicate probes on the same context will not conflict each other. That is,
 * running a probe for the same address twice on the same context will not
 * cause them to consider each other a duplicate.
 *
 * Probes are rather lightweight objects. They do not create any
 * file-descriptors or other kernel objects. Probes always re-use the
 * infrastructure provided by the context object @acd. This allows running many
 * probes simultaneously without exhausting resources.
 *
 * Return: 0 on success, N_ACD_E_INVALID_ARGUMENT on invalid configuration
 *         parameters, negative error code on failure.
 */
_c_public_ int n_acd_probe(NAcd *acd, NAcdProbe **probep, NAcdProbeConfig *config) {
        return n_acd_probe_new(probep, acd, config);
}
