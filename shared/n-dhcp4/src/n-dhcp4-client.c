/*
 * Client Side of the Dynamic Host Configuration Protocol for IPv4
 *
 * This implements the public API around the NDhcp4Client object. The client
 * object is simply a context to track running probes. It manages pending
 * events of all probes, as well as forwards the dispatching requests whenever
 * the dispatcher is run.
 */

#include <assert.h>
#include <c-list.h>
#include <c-stdaux.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_infiniband.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>
#include "n-dhcp4.h"
#include "n-dhcp4-private.h"

/**
 * n_dhcp4_client_config_new() - allocate new client configuration
 * @configp:                    output argument for new client config
 *
 * This creates a new client configuration object. Client configurations are
 * unlinked objects that merely serve as collection of parameters. They do not
 * perform validity checks.
 *
 * The new client configuration is fully owned by the caller. They are
 * responsible to free the object if no longer needed.
 *
 * Return: 0 on success, negative error code on failure.
 */
_c_public_ int n_dhcp4_client_config_new(NDhcp4ClientConfig **configp) {
        _c_cleanup_(n_dhcp4_client_config_freep) NDhcp4ClientConfig *config = NULL;

        config = calloc(1, sizeof(*config));
        if (!config)
                return -ENOMEM;

        *config = (NDhcp4ClientConfig)N_DHCP4_CLIENT_CONFIG_NULL(*config);

        *configp = config;
        config = NULL;
        return 0;
}

/**
 * n_dhcp4_client_config_free() - destroy client configuration
 * @config:                     client configuration to operate on, or NULL
 *
 * This destroys a client configuration and deallocates all its resources. If
 * NULL is passed, this is a no-op.
 *
 * Return: NULL is returned.
 */
_c_public_ NDhcp4ClientConfig *n_dhcp4_client_config_free(NDhcp4ClientConfig *config) {
        if (!config)
                return NULL;

        free(config->client_id);
        free(config);

        return NULL;
}

/**
 * n_dhcp4_client_config_dup() - duplicate client configuration
 * @config:                     client configuration to operate on
 * @dupp:                       output argument for duplicate
 *
 * This duplicates the client configuration given as @config and returns it in
 * @dupp to the caller.
 *
 * Return: 0 on success, negative error code on failure.
 */
int n_dhcp4_client_config_dup(NDhcp4ClientConfig *config, NDhcp4ClientConfig **dupp) {
        _c_cleanup_(n_dhcp4_client_config_freep) NDhcp4ClientConfig *dup = NULL;
        int r;

        r = n_dhcp4_client_config_new(&dup);
        if (r)
                return r;

        dup->ifindex = config->ifindex;
        dup->transport = config->transport;
        dup->request_broadcast = config->request_broadcast;
        memcpy(dup->mac, config->mac, sizeof(dup->mac));
        dup->n_mac = config->n_mac;
        memcpy(dup->broadcast_mac, config->broadcast_mac, sizeof(dup->broadcast_mac));
        dup->n_broadcast_mac = config->n_broadcast_mac;

        r = n_dhcp4_client_config_set_client_id(dup,
                                                config->client_id,
                                                config->n_client_id);
        if (r)
                return r;

        *dupp = dup;
        dup = NULL;
        return 0;
}

/**
 * n_dhcp4_client_config_set_ifindex() - set ifindex property
 * @config:                     client configuration to operate on
 * @ifindex:                    ifindex to set
 *
 * This sets the ifindex property of the client configuration. The ifindex
 * specifies the network device that a DHCP client will run on.
 */
_c_public_ void n_dhcp4_client_config_set_ifindex(NDhcp4ClientConfig *config, int ifindex) {
        config->ifindex = ifindex;
}

/**
 * n_dhcp4_client_config_set_transport() - set transport property
 * @config:                     client configuration to operate on
 * @transport:                  transport to set
 *
 * This sets the transport property of the client configuration. The transport
 * defines the hardware transport of the network device that a DHCP client
 * runs on.
 *
 * This takes one of the N_DHCP4_TRANSPORT_* identifiers as argument.
 */
_c_public_ void n_dhcp4_client_config_set_transport(NDhcp4ClientConfig *config, unsigned int transport) {
        config->transport = transport;
}

/**
 * n_dhcp4_client_config_set_request_broadcast() - set request-broadcast property
 * @config:                           configuration to operate on
 * @request_broadcast:                value to set
 *
 * This sets the request_broadcast property of the given configuration object.
 *
 * The default is false. If set to true, a the server will be told to not unicast
 * replies to the client's IP address before it has been configured, but broadcast
 * to INADDR_ANY instead. In most cases, you do not want this.
 *
 * Background: OFFER and ACK messages from DHCP servers to clients are unicast
 *             to the IP address handed out, even before the IP address has
 *             been configured on the taregt interface. This usually works
 *             because the correct destination hardware address is explicitly
 *             set on the outgoing packets, rather than being resolved (which
 *             would not work). However, some hardware does not accept incoming
 *             IP packets destined for addresses they do not own, even if the
 *             hardware address is correct. In this case, the server must
 *             broadcast the replies in order for the client to receive them.
 *             In general, unneccesary broadcasting is something one wants to
 *             avoid, and some networks will not deliver broadcasts to the
 *             client at all, in which case this flag must not be set.
 */
_c_public_ void n_dhcp4_client_config_set_request_broadcast(NDhcp4ClientConfig *config, bool request_broadcast) {
        config->request_broadcast = request_broadcast;
}

/**
 * n_dhcp4_client_config_set_mac() - set mac property
 * @config:                     client configuration to operate on
 * @mac:                        hardware address to set
 * @n_mac:                      length of the hardware address
 *
 * This sets the mac property of the client configuration. It specifies the
 * hardware address of the local interface that the DHCP client runs on.
 *
 * This function copies the specified hardware address into @config. Any
 * hardware address is supported. It is up to the consumer of the client
 * configuration to verify the validity of the hardware address.
 *
 * Note: This function may truncate the hardware address internally, but
 *       retains the original length. The consumer of this configuration can
 *       thus tell whether the data was truncated and will refuse it.
 *       The internal buffer is big enough to hold any hardware address of all
 *       supported transports. Thus, truncation only happens if you use
 *       unsupported transports, and those will be rejected, anyway.
 */
_c_public_ void n_dhcp4_client_config_set_mac(NDhcp4ClientConfig *config, const uint8_t *mac, size_t n_mac) {
        config->n_mac = n_mac;

        if (n_mac > sizeof(config->mac))
                n_mac = sizeof(config->mac);

        memcpy(config->mac, mac, n_mac);
}

/**
 * n_dhcp4_client_config_set_broadcast_mac() - set broadcast-mac property
 * @config:                     client configuration to operate on
 * @mac:                        hardware address to set
 * @n_mac:                      length of the hardware address
 *
 * This sets the broadcast-mac property of the client configuration. It
 * specifies the destination hardware address to use for broadcasts on the
 * local interface that the DHCP client runs on.
 *
 * This function copies the specified hardware address into @config. Any
 * hardware address is supported. It is up to the consumer of the client
 * configuration to verify the validity of the hardware address.
 *
 * Note: This function may truncate the hardware address internally, but
 *       retains the original length. The consumer of this configuration can
 *       thus tell whether the data was truncated and will refuse it.
 *       The internal buffer is big enough to hold any hardware address of all
 *       supported transports. Thus, truncation only happens if you use
 *       unsupported transports, and those will be rejected, anyway.
 */
_c_public_ void n_dhcp4_client_config_set_broadcast_mac(NDhcp4ClientConfig *config, const uint8_t *mac, size_t n_mac) {
        config->n_broadcast_mac = n_mac;

        if (n_mac > sizeof(config->mac))
                n_mac = sizeof(config->mac);

        memcpy(config->broadcast_mac, mac, n_mac);
}

/**
 * n_dhcp4_client_config_set_client_id() - set client-id property
 * @config:                     client configuration to operate on
 * @id:                         client id
 * @n_id:                       length of the client id in bytes
 *
 * This sets the client-id property of @config. It copies the entire client-id
 * buffer into the configuration.
 *
 * Return: 0 on success, negative error code on failure.
 */
_c_public_ int n_dhcp4_client_config_set_client_id(NDhcp4ClientConfig *config, const uint8_t *id, size_t n_id) {
        uint8_t *t;

        t = malloc(n_id + 1);
        if (!t)
                return -ENOMEM;

        free(config->client_id);
        config->client_id = t;
        config->n_client_id = n_id;

        memcpy(config->client_id, id, n_id);
        config->client_id[n_id] = 0; /* safety 0 for debugging */

        return 0;
}

/**
 * n_dhcp4_c_event_node_new() - allocate new event
 * @nodep:                      output argument for new event
 *
 * This allocates a new event node and returns it to the caller. The caller
 * fully owns the event-node and is reposonsible to either link it somewhere,
 * or release it.
 *
 * Event nodes can be linked on a client object, as well as optionally on a
 * probe object. As long as an event-node is linked, it will be retrievable by
 * the API user through n_dhcp4_client_pop_event(). Furthermore, destruction of
 * the client, or probe respectively, will clean-up all pending events.
 *
 * Return: 0 on success, negative error code on failure.
 */
int n_dhcp4_c_event_node_new(NDhcp4CEventNode **nodep) {
        NDhcp4CEventNode *node;

        node = calloc(1, sizeof(*node));
        if (!node)
                return -ENOMEM;

        *node = (NDhcp4CEventNode)N_DHCP4_C_EVENT_NODE_NULL(*node);

        *nodep = node;
        return 0;
}

/**
 * n_dhcp4_c_event_node_free() - deallocate event
 * @node:                       node to operate on, or NULL
 *
 * This deallocates the node given as @node. If the node is linked on a client
 * or probe, it is unlinked automatically.
 *
 * If @probe is NULL, this is a no-op.
 *
 * Return: NULL is returned.
 */
NDhcp4CEventNode *n_dhcp4_c_event_node_free(NDhcp4CEventNode *node) {
        if (!node)
                return NULL;

        switch (node->event.event) {
        case N_DHCP4_CLIENT_EVENT_OFFER:
                node->event.offer.lease = n_dhcp4_client_lease_unref(node->event.offer.lease);
                break;
        case N_DHCP4_CLIENT_EVENT_GRANTED:
                node->event.granted.lease = n_dhcp4_client_lease_unref(node->event.granted.lease);
                break;
        case N_DHCP4_CLIENT_EVENT_EXTENDED:
                node->event.extended.lease = n_dhcp4_client_lease_unref(node->event.extended.lease);
                break;
        default:
                break;
        }

        c_list_unlink(&node->probe_link);
        c_list_unlink(&node->client_link);
        free(node);

        return NULL;
}

/**
 * n_dhcp4_client_new() - allocate new client
 * @clientp:                    output argument for new client
 * @config:                     configuration to use
 *
 * This allocates a new DHCP4 client object and returns it in @clientp to the
 * caller. The caller then owns a single ref-count to the object and is
 * responsible to drop it, when no longer needed.
 *
 * The configuration given as @config is used to initialize the client. The
 * caller is free to destroy the configuration once this function returns.
 *
 * Return: 0 on success, negative error code on failure.
 */
_c_public_ int n_dhcp4_client_new(NDhcp4Client **clientp, NDhcp4ClientConfig *config) {
        _c_cleanup_(n_dhcp4_client_unrefp) NDhcp4Client *client = NULL;
        struct epoll_event ev = {
                .events = EPOLLIN,
        };
        int r;

        c_assert(clientp);

        /* verify configuration */
        {
                if (config->ifindex < 1)
                        return N_DHCP4_E_INVALID_IFINDEX;

                switch (config->transport) {
                case N_DHCP4_TRANSPORT_ETHERNET:
                        if (config->n_mac != ETH_ALEN ||
                            config->n_broadcast_mac != ETH_ALEN)
                                return N_DHCP4_E_INVALID_ADDRESS;

                        break;
                case N_DHCP4_TRANSPORT_INFINIBAND:
                        if (config->n_mac != INFINIBAND_ALEN ||
                            config->n_broadcast_mac != INFINIBAND_ALEN)
                                return N_DHCP4_E_INVALID_ADDRESS;

                        break;
                default:
                        return N_DHCP4_E_INVALID_TRANSPORT;
                }

                if (config->n_client_id < 1)
                        return N_DHCP4_E_INVALID_CLIENT_ID;
        }

        client = malloc(sizeof(*client));
        if (!client)
                return -ENOMEM;

        *client = (NDhcp4Client)N_DHCP4_CLIENT_NULL(*client);

        r = n_dhcp4_client_config_dup(config, &client->config);
        if (r)
                return r;

        client->fd_epoll = epoll_create1(EPOLL_CLOEXEC);
        if (client->fd_epoll < 0)
                return -errno;

        client->fd_timer = timerfd_create(CLOCK_BOOTTIME, TFD_CLOEXEC | TFD_NONBLOCK);
        if (client->fd_timer < 0)
                return -errno;

        ev.data.u32 = N_DHCP4_CLIENT_EPOLL_TIMER;
        r = epoll_ctl(client->fd_epoll, EPOLL_CTL_ADD, client->fd_timer, &ev);
        if (r < 0)
                return -errno;

        *clientp = client;
        client = NULL;
        return 0;
}

static void n_dhcp4_client_free(NDhcp4Client *client) {
        NDhcp4CEventNode *node, *t_node;

        c_assert(!client->current_probe);

        c_list_for_each_entry_safe(node, t_node, &client->event_list, client_link)
                n_dhcp4_c_event_node_free(node);

        if (client->fd_timer >= 0) {
                epoll_ctl(client->fd_epoll, EPOLL_CTL_DEL, client->fd_timer, NULL);
                close(client->fd_timer);
        }

        if (client->fd_epoll >= 0)
                close(client->fd_epoll);

        n_dhcp4_client_config_free(client->config);
        free(client);
}

/**
 * n_dhcp4_client_ref() - acquire client reference
 * @client:                     client to operate on, or NULL
 *
 * This acquires a reference to the client given as @client. If @client is
 * NULL, this function is a no-op.
 *
 * Return: @client is returned.
 */
_c_public_ NDhcp4Client *n_dhcp4_client_ref(NDhcp4Client *client) {
        if (client)
                ++client->n_refs;
        return client;
}

/**
 * n_dhcp4_client_unref() - release client reference
 * @client:                     client to operate on, or NULL
 *
 * This releases a reference to the client given as @client. If @client is
 * NULL, this is a no-op.
 *
 * Once the last reference is dropped, the client object will get destroyed and
 * deallocated.
 *
 * Return: NULL is returned.
 */
_c_public_ NDhcp4Client *n_dhcp4_client_unref(NDhcp4Client *client) {
        if (client && !--client->n_refs)
                n_dhcp4_client_free(client);
        return NULL;
}

/**
 * n_dhcp4_client_raise() - raise event
 * @client:                     client to operate on
 * @nodep:                      output argument for new event, or NULL
 * @event:                      event type to use
 *
 * This creates a new event-node on @client, setting the event-type to @event.
 * The newly created event-node is returned to the caller in @nodep (unless
 * @nodep is NULL).
 *
 * The event-node is automatically linked on @client.
 *
 * Return: 0 on success, negative error code on failure.
 */
int n_dhcp4_client_raise(NDhcp4Client *client, NDhcp4CEventNode **nodep, unsigned int event) {
        NDhcp4CEventNode *node;
        int r;

        r = n_dhcp4_c_event_node_new(&node);
        if (r)
                return r;

        node->event.event = event;
        c_list_link_tail(&client->event_list, &node->client_link);

        if (nodep)
                *nodep = node;
        return 0;
}

/**
 * n_dhcp4_client_arm_timer() - update timer
 * @client:                     client to operate on
 *
 * This updates the timer on @client to fire on the next pending timeout. This
 * must be called whenever a timeout on @client might have changed.
 */
void n_dhcp4_client_arm_timer(NDhcp4Client *client) {
        uint64_t timeout = 0;
        int r;

        if (client->current_probe)
                n_dhcp4_client_probe_get_timeout(client->current_probe, &timeout);

        if (timeout != client->scheduled_timeout) {
                r = timerfd_settime(client->fd_timer,
                                    TFD_TIMER_ABSTIME,
                                    &(struct itimerspec){
                                        .it_value = {
                                                .tv_sec = timeout / UINT64_C(1000000000),
                                                .tv_nsec = timeout % UINT64_C(1000000000),
                                        },
                                    },
                                    NULL);
                c_assert(r >= 0);

                client->scheduled_timeout = timeout;
        }
}

/**
 * n_dhcp4_client_get_fd() - retrieve event FD
 * @client:                     client to operate on
 * @fdp:                        output argument to store FD
 *
 * This retrieves the FD used by the client object given as @client. The FD is
 * always valid, and returned in @fdp.
 *
 * The caller is expected to poll this FD for readable events and call
 * n_dhcp4_client_dispatch() whenever the FD is readable.
 */
_c_public_ void n_dhcp4_client_get_fd(NDhcp4Client *client, int *fdp) {
        *fdp = client->fd_epoll;
}

static int n_dhcp4_client_dispatch_timer(NDhcp4Client *client, struct epoll_event *event) {
        uint64_t v, ns_now;
        int r;

        if (event->events & (EPOLLHUP | EPOLLERR)) {
                /*
                 * There is no way to handle either gracefully. If we ignored
                 * them, we would busy-loop, so lets rather forward the error
                 * to the caller.
                 */
                return -ENOTRECOVERABLE;
        }

        if (event->events & EPOLLIN) {
                r = read(client->fd_timer, &v, sizeof(v));
                if (r < 0) {
                        if (errno == EAGAIN) {
                                /*
                                 * There are no more pending events, so nothing
                                 * to be done. Return to the caller.
                                 */
                                return 0;
                        }

                        /*
                         * Something failed. We use CLOCK_BOOTTIME/MONOTONIC,
                         * so ECANCELED cannot happen. Hence, there is no error
                         * that we could gracefully handle. Fail hard and let
                         * the caller deal with it.
                         */
                        return -errno;
                } else if (r != sizeof(v) || v == 0) {
                        /*
                         * Kernel guarantees 8-byte reads, and only to return
                         * data if at least one timer triggered; fail hard if
                         * it suddenly starts exposing unexpected behavior.
                         */
                        return -ENOTRECOVERABLE;
                }

                /*
                 * Forward the timer-event to the active probe. Timers should
                 * not fire if there is no probe running, but lets ignore them
                 * for now, so probe-internals are not leaked to this generic
                 * client dispatcher.
                 */
                if (client->current_probe) {
                        /*
                         * Read the current time *after* dispatching the timer,
                         * to make sure we do not miss wakeups.
                         */
                        ns_now = n_dhcp4_gettime(CLOCK_BOOTTIME);

                        r = n_dhcp4_client_probe_dispatch_timer(client->current_probe,
                                                                ns_now);
                        if (r)
                                return r;
                }
        }

        return 0;
}

static int n_dhcp4_client_dispatch_io(NDhcp4Client *client, struct epoll_event *event) {
        int r;

        if (client->current_probe)
                r = n_dhcp4_client_probe_dispatch_io(client->current_probe,
                                                     event->events);
        else
                return -ENOTRECOVERABLE;

        return r;
}

/**
 * n_dhcp4_client_dispatch() - dispatch client
 * @client:                     client to operate on
 *
 * This dispatches pending operations on @client. It will read incoming
 * messages, write pending data, and handle any timeouts.
 *
 * This function never blocks.
 *
 * If there are more events to dispatch, than would be reasonable to do in a
 * single dispatch, this will return N_DHCP4_E_PREEMPTED. In this case the
 * caller is expected to call into this function again when it is ready to
 * dispatch more events.
 * If your event loop is level-triggered (it very likely is), you can
 * optionally ignore this return code and treat it as success.
 *
 * Return: 0 on success, negative error code on failure, N_DHCP4_E_PREEMPTED if
 *         there is more data to dispatch.
 */
_c_public_ int n_dhcp4_client_dispatch(NDhcp4Client *client) {
        struct epoll_event events[2];
        int n, i, r = 0;

        n = epoll_wait(client->fd_epoll, events, sizeof(events) / sizeof(*events), 0);
        if (n < 0) {
                /* Linux never returns EINTR if `timeout == 0'. */
                return -errno;
        }

        client->preempted = false;

        for (i = 0; i < n; ++i) {
                switch (events[i].data.u32) {
                case N_DHCP4_CLIENT_EPOLL_TIMER:
                        r = n_dhcp4_client_dispatch_timer(client, events + i);
                        break;
                case N_DHCP4_CLIENT_EPOLL_IO:
                        r = n_dhcp4_client_dispatch_io(client, events + i);
                        break;
                default:
                        c_assert(0);
                        r = 0;
                        break;
                }

                if (r) {
                        if (r == N_DHCP4_E_DOWN) {
                                r = n_dhcp4_client_raise(client,
                                                         NULL,
                                                         N_DHCP4_CLIENT_EVENT_DOWN);
                                if (r)
                                        return r;

                                /* continue normally */
                        } else if (r) {
                                c_assert(r < _N_DHCP4_E_INTERNAL);
                                return r;
                        }
                }
        }

        n_dhcp4_client_arm_timer(client);

        return client->preempted ? N_DHCP4_E_PREEMPTED : 0;
}

/**
 * n_dhcp4_client_pop_event() - fetch pending event
 * @client:                     client to operate on
 * @eventp:                     output argument to store next event
 *
 * This fetches the next pending event from the event-queue and returns it to a
 * caller. A pointer to the event is stored in @eventp. If there is no more
 * event queued, NULL is returned.
 *
 * If a valid event is returned, it is accessible until the next call to this
 * function, or the destruction of the context object (this might be either the
 * client object or the probe object, pointed to by the event), whichever
 * happens first.
 * That is, the caller should not pin the returned event object, but copy
 * required information into their own state tracking contexts.
 *
 * The possible events are:
 * * N_DHCP4_CLIENT_EVENT_OFFER:     A lease offered from a server in response
 *                                   to a probe. Several such offers may be
 *                                   received until one of them is selected by
 *                                   the caller. Only one lease may be selected.
 *                                   The attached lease object may be queried
 *                                   for information in order to decide which
 *                                   lease to select, though the information is
 *                                   not guaranteed to stay the same in the
 *                                   final lease.
 * * N_DHCP4_CLIENT_EVENT_GRANTED:   A selected lease was granted by the server.
 *                                   The information in the attached lease
 *                                   object should be used to configure the
 *                                   client. Once the client has been
 *                                   configured, the lease should be accepted.
 * * N_DHCP4_CLIENT_EVENT_RETRACTED: A selected lease offer was retracted by the
 *                                   server. This can happen in case the server
 *                                   offers the same lease to several clients,
 *                                   or the server discovers that the IP address
 *                                   in the lease is already in use.
 * * N_DHCP4_CLIENT_EVENT_EXTENDED:  An active lease is extended, if applicable
 *                                   the kernel should be updated with the new
 *                                   lifetime information for addresses and/or
 *                                   routes.
 * * N_DHCP4_CLIENT_EVENT_EXPIRED:   An active lease failed to be extended by
 *                                   the end of its lifetime. The client should
 *                                   immediately stop using the information
 *                                   contained in the lease.
 * * N_DHCP4_CLIENT_EVENT_DOWN:      The network interface was put down down.
 *                                   The user is recommended to reestablish the
 *                                   lease at the first opportunity when the
 *                                   network comes back up. Note that this is
 *                                   purely informational, the probe will keep
 *                                   running, and if the network topology does
 *                                   not change any lease we have will still be
 *                                   valid.
 * * N_DHCP4_CLIENT_EVENT_CANCELLED: The probe was cancelled. This can happen if
 *                                   the client attempted several incompatible
 *                                   probes in parallel, then the most recent
 *                                   ones will be cancelled asynchronously.
 *
 * Return: 0 on success, negative error code on failure.
 */
_c_public_ int n_dhcp4_client_pop_event(NDhcp4Client *client, NDhcp4ClientEvent **eventp) {
        NDhcp4CEventNode *node, *t_node;

        c_list_for_each_entry_safe(node, t_node, &client->event_list, client_link) {
                if (node->is_public) {
                        n_dhcp4_c_event_node_free(node);
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
 * n_dhcp4_client_update_mtu() - update link mtu
 * @client:                     client to operate on
 * @mtu:                        new mtu
 *
 * This updates the link MTU used by the client object. By default, the minimum
 * requirement given by the IP specification is assumed, which means 576
 * bytes. The caller is advised to update this to the actual MTU used by the
 * link layer.
 *
 * This value reflects the MTU of the link layer. That is, it is the maximum
 * packet size that you can send on that link, excluding the link-header but
 * including the IP-header. On ethernet-v2 this would be 1500.
 *
 * If unsure, it is safe to leave this unset. However, in this case a DHCP
 * server will be required to omit information if it does not fit into the
 * default MTU.
 *
 * Unless you keep the default MTU, you should update the MTU whenever the link
 * MTU changes. That is, when it is increased *and* when it is decreased.
 * However, you must be aware that decreasing the MTU on a link might cause
 * temporary data loss.
 *
 * Background: Knowing the link MTU guarantees that we can possibly transmit
 *             packets bigger than the IP minimum (i.e., 576 bytes). However,
 *             it does not guarantee that a possible target supports parsing
 *             packets bigger than the IP minimum. Hence, the MTU is used by a
 *             client to send a hint to a server that it can receive replies
 *             bigger than the minimum. As such, a server can reply with more
 *             information than otherwise possible.
 *             Since this DHCP client does not support fragmented packets, we
 *             simply set the allowed packet-size to the local link MTU.
 *             Note that DHCP relays might cause DHCP packets to be routed.
 *             However, such relays are required to always reassemble any
 *             fragments they receive into full DHCP packets, before they
 *             forward them either way. This guarantees that incoming packets
 *             are never fragmented, unless they exceed the local link MTU
 *             (this would otherwise not neccessarily be true, if some other
 *             part of the routed network had a lower MTU).
 *
 * Return: 0 on success, negative error code on failure.
 */
_c_public_ int n_dhcp4_client_update_mtu(NDhcp4Client *client, uint16_t mtu) {
        int r;

        if (mtu == client->mtu)
                return 0;

        if (client->current_probe) {
                r = n_dhcp4_client_probe_update_mtu(client->current_probe, mtu);
                if (r)
                        return r;
        }

        client->mtu = mtu;
        return 0;
}

/**
 * n_dhcp4_client_probe() - create a new probe
 * @client:                     client to operate on
 * @probep:                     output argument to store new probe
 * @config:                     probe configuration to use
 *
 * This creates a new probe on @client. Probes represent DHCP requests and
 * track the state over the entire lifetime of a lease. Once a probe is created
 * it will start looking for DHCP servers, request a lease from them, and renew
 * the lease continously whenever it expires. Furthermore, if a lease cannot be
 * renewed, a new lease will be requested.
 *
 * The API allows for many probes to be run at the same time. However, the DHCP
 * specification forbids many of those cases (e.g., you must not reuse a client
 * id, otherwise it will be impossible to track who to forward received packets
 * to). Hence, so far only a single probe can run at a time. If you create a
 * new probe, all older probes that conflict with that probe will be canceled
 * (their state machine is halted and a N_DHCP4_CLIENT_EVENT_CANCELLED event is
 * raised.
 * This might change in the future, though. There might be cases where multiple
 * probes can be run in parallel (e.g., with different client-ids, or an INFORM
 * in parallel to a REQUEST, ...).
 *
 * Return: 0 on success, negative error code on failure.
 */
_c_public_ int n_dhcp4_client_probe(NDhcp4Client *client,
                                  NDhcp4ClientProbe **probep,
                                  NDhcp4ClientProbeConfig *config) {
        _c_cleanup_(n_dhcp4_client_probe_freep) NDhcp4ClientProbe *probe = NULL;
        uint64_t ns_now;
        int r;

        ns_now = n_dhcp4_gettime(CLOCK_BOOTTIME);

        r = n_dhcp4_client_probe_new(&probe, config, client, ns_now);
        if (r)
                return r;

        n_dhcp4_client_arm_timer(client);

        *probep = probe;
        probe = NULL;
        return 0;
}
