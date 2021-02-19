/*
 * Server Side of the Dynamic Host Configuration Protocol for IPv4
 *
 * XXX
 */

#include <assert.h>
#include <c-list.h>
#include <c-stdaux.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>
#include "n-dhcp4.h"
#include "n-dhcp4-private.h"
#include "util/packet.h"

/**
 * n_dhcp4_server_config_new() - XXX
 */
_c_public_ int n_dhcp4_server_config_new(NDhcp4ServerConfig **configp) {
        _c_cleanup_(n_dhcp4_server_config_freep) NDhcp4ServerConfig *config = NULL;

        config = calloc(1, sizeof(*config));
        if (!config)
                return -ENOMEM;

        *config = (NDhcp4ServerConfig)N_DHCP4_SERVER_CONFIG_NULL(*config);

        *configp = config;
        config = NULL;
        return 0;
}

/**
 * n_dhcp4_server_config_free() - XXX
 */
_c_public_ NDhcp4ServerConfig *n_dhcp4_server_config_free(NDhcp4ServerConfig *config) {
        if (!config)
                return NULL;

        free(config);

        return NULL;
}

/**
 * n_dhcp4_server_config_set_ifindex() - XXX
 */
_c_public_ void n_dhcp4_server_config_set_ifindex(NDhcp4ServerConfig *config, int ifindex) {
        config->ifindex = ifindex;
}

/**
 * n_dhcp4_s_event_node_new() - XXX
 */
int n_dhcp4_s_event_node_new(NDhcp4SEventNode **nodep) {
        NDhcp4SEventNode *node;

        node = calloc(1, sizeof(*node));
        if (!node)
                return -ENOMEM;

        *node = (NDhcp4SEventNode)N_DHCP4_S_EVENT_NODE_NULL(*node);

        *nodep = node;
        return 0;
}

/**
 * n_dhcp4_s_event_node_free() - XXX
 */
NDhcp4SEventNode *n_dhcp4_s_event_node_free(NDhcp4SEventNode *node) {
        if (!node)
                return NULL;

        c_list_unlink(&node->server_link);
        free(node);

        return NULL;
}

/**
 * n_dhcp4_server_new() - XXX
 */
_c_public_ int n_dhcp4_server_new(NDhcp4Server **serverp, NDhcp4ServerConfig *config) {
        _c_cleanup_(n_dhcp4_server_unrefp) NDhcp4Server *server = NULL;
        int r;

        c_assert(serverp);

        server = malloc(sizeof(*server));
        if (!server)
                return -ENOMEM;

        *server = (NDhcp4Server)N_DHCP4_SERVER_NULL(*server);

        r = n_dhcp4_s_connection_init(&server->connection, config->ifindex);
        if (r)
                return r;

        *serverp = server;
        server = NULL;
        return 0;
}

static void n_dhcp4_server_free(NDhcp4Server *server) {
        NDhcp4SEventNode *node, *t_node;

        c_list_for_each_entry_safe(node, t_node, &server->event_list, server_link)
                n_dhcp4_s_event_node_free(node);

        free(server);
}

/**
 * n_dhcp4_server_ref() - XXX
 */
_c_public_ NDhcp4Server *n_dhcp4_server_ref(NDhcp4Server *server) {
        if (server)
                ++server->n_refs;
        return server;
}

/**
 * n_dhcp4_server_unref() - XXX
 */
_c_public_ NDhcp4Server *n_dhcp4_server_unref(NDhcp4Server *server) {
        if (server && !--server->n_refs)
                n_dhcp4_server_free(server);
        return NULL;
}

/**
 * n_dhcp4_server_raise() - XXX
 */
int n_dhcp4_server_raise(NDhcp4Server *server, NDhcp4SEventNode **nodep, unsigned int event) {
        NDhcp4SEventNode *node;
        int r;

        r = n_dhcp4_s_event_node_new(&node);
        if (r)
                return r;

        node->event.event = event;
        c_list_link_tail(&server->event_list, &node->server_link);

        if (nodep)
                *nodep = node;
        return 0;
}

/**
 * n_dhcp4_server_get_fd() - XXX
 */
_c_public_ void n_dhcp4_server_get_fd(NDhcp4Server *server, int *fdp) {
        n_dhcp4_s_connection_get_fd(&server->connection, fdp);
}

/**
 * n_dhcp4_server_dispatch() - XXX
 */
_c_public_ int n_dhcp4_server_dispatch(NDhcp4Server *server) {
        int r;

        for (unsigned int i = 0; i < 128; ++i) {
                _c_cleanup_(n_dhcp4_incoming_freep) NDhcp4Incoming *message = NULL;

                r = n_dhcp4_s_connection_dispatch_io(&server->connection, &message);
                if (r) {
                        if (r == N_DHCP4_E_AGAIN)
                                return 0;
                        return r;
                }
        }

        return N_DHCP4_E_PREEMPTED;
}

/**
 * n_dhcp4_server_pop_event() - XXX
 */
_c_public_ int n_dhcp4_server_pop_event(NDhcp4Server *server, NDhcp4ServerEvent **eventp) {
        NDhcp4SEventNode *node, *t_node;

        c_list_for_each_entry_safe(node, t_node, &server->event_list, server_link) {
                if (node->is_public) {
                        n_dhcp4_s_event_node_free(node);
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
 * n_dhcp4_server_add_ip() - XXX
 */
_c_public_ int n_dhcp4_server_add_ip(NDhcp4Server *server, NDhcp4ServerIp **ipp, struct in_addr addr) {
        _c_cleanup_(n_dhcp4_server_ip_freep) NDhcp4ServerIp *ip = NULL;

        /* XXX: support more than one address */
        if (server->connection.ip)
                return -EBUSY;

        ip = malloc(sizeof(*ip));
        if (!ip)
                return -ENOMEM;

        *ip = (NDhcp4ServerIp)N_DHCP4_SERVER_IP_NULL(*ip);

        n_dhcp4_s_connection_ip_init(&ip->ip, addr);
        n_dhcp4_s_connection_ip_link(&ip->ip, &server->connection);

        *ipp = ip;
        ip = NULL;
        return 0;
}

/**
 * n_dhcp4_server_ip_free() - XXX
 */
_c_public_ NDhcp4ServerIp *n_dhcp4_server_ip_free(NDhcp4ServerIp *ip) {
        if (!ip)
                return NULL;

        n_dhcp4_s_connection_ip_unlink(&ip->ip);
        n_dhcp4_s_connection_ip_deinit(&ip->ip);

        free(ip);
        return NULL;
}
