#pragma once

/*
 * Dynamic Host Configuration Protocol for IPv4
 *
 * This is the public header of the n-dhcp4 library, implementing IPv4 Dynamic
 * Host Configuration Protocol as described in RFC-2132. This header defines
 * the public API and all entry points of n-dhcp4.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <inttypes.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdlib.h>

typedef struct NDhcp4Client NDhcp4Client;
typedef struct NDhcp4ClientConfig NDhcp4ClientConfig;
typedef struct NDhcp4ClientEvent NDhcp4ClientEvent;
typedef struct NDhcp4ClientLease NDhcp4ClientLease;
typedef struct NDhcp4ClientProbe NDhcp4ClientProbe;
typedef struct NDhcp4ClientProbeConfig NDhcp4ClientProbeConfig;
typedef struct NDhcp4Server NDhcp4Server;
typedef struct NDhcp4ServerConfig NDhcp4ServerConfig;
typedef struct NDhcp4ServerEvent NDhcp4ServerEvent;
typedef struct NDhcp4ServerIp NDhcp4ServerIp;
typedef struct NDhcp4ServerLease NDhcp4ServerLease;

#define N_DHCP4_CLIENT_START_DELAY_RFC2131 (UINT64_C(9000))

enum {
        _N_DHCP4_E_SUCCESS,

        N_DHCP4_E_PREEMPTED,
        N_DHCP4_E_INTERNAL,

        N_DHCP4_E_INVALID_IFINDEX,
        N_DHCP4_E_INVALID_TRANSPORT,
        N_DHCP4_E_INVALID_ADDRESS,
        N_DHCP4_E_INVALID_CLIENT_ID,
        N_DHCP4_E_DUPLICATE_OPTION,
        N_DHCP4_E_UNSET,

        _N_DHCP4_E_N,
};

enum {
        N_DHCP4_TRANSPORT_ETHERNET,
        N_DHCP4_TRANSPORT_INFINIBAND,
        _N_DHCP4_TRANSPORT_N,
};

enum {
        N_DHCP4_CLIENT_EVENT_DOWN,
        N_DHCP4_CLIENT_EVENT_OFFER,
        N_DHCP4_CLIENT_EVENT_GRANTED,
        N_DHCP4_CLIENT_EVENT_RETRACTED,
        N_DHCP4_CLIENT_EVENT_EXTENDED,
        N_DHCP4_CLIENT_EVENT_EXPIRED,
        N_DHCP4_CLIENT_EVENT_CANCELLED,
        _N_DHCP4_CLIENT_EVENT_N,
};

enum {
        N_DHCP4_SERVER_EVENT_DOWN,
        N_DHCP4_SERVER_EVENT_DISCOVER,
        N_DHCP4_SERVER_EVENT_REQUEST,
        N_DHCP4_SERVER_EVENT_RENEW,
        N_DHCP4_SERVER_EVENT_DECLINE,
        N_DHCP4_SERVER_EVENT_RELEASE,
        _N_DHCP4_SERVER_EVENT_N,
};

struct NDhcp4ClientEvent {
        unsigned int event;
        union {
                struct {
                } down;
                struct {
                        NDhcp4ClientProbe *probe;
                        NDhcp4ClientLease *lease;
                } offer, granted, extended;
                struct {
                        NDhcp4ClientProbe *probe;
                } retracted, expired, cancelled;
        };
};

struct NDhcp4ServerEvent {
        unsigned int event;
        union {
                struct {
                } down;
                struct {
                        NDhcp4ServerLease *lease;
                } discover, request, decline, release;
        };
};

/* client configs */

int n_dhcp4_client_config_new(NDhcp4ClientConfig **configp);
NDhcp4ClientConfig *n_dhcp4_client_config_free(NDhcp4ClientConfig *config);

void n_dhcp4_client_config_set_ifindex(NDhcp4ClientConfig *config, int ifindex);
void n_dhcp4_client_config_set_transport(NDhcp4ClientConfig *config, unsigned int transport);
void n_dhcp4_client_config_set_request_broadcast(NDhcp4ClientConfig *config, bool request_broadcast);
void n_dhcp4_client_config_set_mac(NDhcp4ClientConfig *config, const uint8_t *mac, size_t n_mac);
void n_dhcp4_client_config_set_broadcast_mac(NDhcp4ClientConfig *config, const uint8_t *mac, size_t n_mac);
int n_dhcp4_client_config_set_client_id(NDhcp4ClientConfig *config, const uint8_t *id, size_t n_id);

/* client-probe configs */

int n_dhcp4_client_probe_config_new(NDhcp4ClientProbeConfig **configp);
NDhcp4ClientProbeConfig *n_dhcp4_client_probe_config_free(NDhcp4ClientProbeConfig *config);

void n_dhcp4_client_probe_config_set_inform_only(NDhcp4ClientProbeConfig *config, bool inform_only);
void n_dhcp4_client_probe_config_set_init_reboot(NDhcp4ClientProbeConfig *config, bool init_reboot);
void n_dhcp4_client_probe_config_set_requested_ip(NDhcp4ClientProbeConfig *config, struct in_addr ip);
void n_dhcp4_client_probe_config_set_start_delay(NDhcp4ClientProbeConfig *config, uint64_t msecs);
void n_dhcp4_client_probe_config_request_option(NDhcp4ClientProbeConfig *config, uint8_t option);
int n_dhcp4_client_probe_config_append_option(NDhcp4ClientProbeConfig *config,
                                              uint8_t option,
                                              const void *data,
                                              uint8_t n_data);

/* clients */

int n_dhcp4_client_new(NDhcp4Client **clientp, NDhcp4ClientConfig *config);
NDhcp4Client *n_dhcp4_client_ref(NDhcp4Client *client);
NDhcp4Client *n_dhcp4_client_unref(NDhcp4Client *client);

void n_dhcp4_client_get_fd(NDhcp4Client *client, int *fdp);
int n_dhcp4_client_dispatch(NDhcp4Client *client);
int n_dhcp4_client_pop_event(NDhcp4Client *client, NDhcp4ClientEvent **eventp);

int n_dhcp4_client_update_mtu(NDhcp4Client *client, uint16_t mtu);

int n_dhcp4_client_probe(NDhcp4Client *client,
                         NDhcp4ClientProbe **probep,
                         NDhcp4ClientProbeConfig *config);

/* client probes */

NDhcp4ClientProbe *n_dhcp4_client_probe_free(NDhcp4ClientProbe *probe);

void n_dhcp4_client_probe_set_userdata(NDhcp4ClientProbe *probe, void *userdata);
void n_dhcp4_client_probe_get_userdata(NDhcp4ClientProbe *probe, void **userdatap);

/* client leases */

NDhcp4ClientLease *n_dhcp4_client_lease_ref(NDhcp4ClientLease *lease);
NDhcp4ClientLease *n_dhcp4_client_lease_unref(NDhcp4ClientLease *lease);

void n_dhcp4_client_lease_get_yiaddr(NDhcp4ClientLease *lease, struct in_addr *yiaddr);
void n_dhcp4_client_lease_get_lifetime(NDhcp4ClientLease *lease, uint64_t *ns_lifetimep);
int n_dhcp4_client_lease_query(NDhcp4ClientLease *lease, uint8_t option, uint8_t **datap, size_t *n_datap);

int n_dhcp4_client_lease_select(NDhcp4ClientLease *lease);
int n_dhcp4_client_lease_accept(NDhcp4ClientLease *lease);
int n_dhcp4_client_lease_decline(NDhcp4ClientLease *lease, const char *error);

/* server configs */

int n_dhcp4_server_config_new(NDhcp4ServerConfig **configp);
NDhcp4ServerConfig *n_dhcp4_server_config_free(NDhcp4ServerConfig *config);

void n_dhcp4_server_config_set_ifindex(NDhcp4ServerConfig *config, int ifindex);

/* servers */

int n_dhcp4_server_new(NDhcp4Server **serverp, NDhcp4ServerConfig *config);
NDhcp4Server *n_dhcp4_server_ref(NDhcp4Server *server);
NDhcp4Server *n_dhcp4_server_unref(NDhcp4Server *server);

void n_dhcp4_server_get_fd(NDhcp4Server *server, int *fdp);
int n_dhcp4_server_dispatch(NDhcp4Server *server);
int n_dhcp4_server_pop_event(NDhcp4Server *server, NDhcp4ServerEvent **eventp);

int n_dhcp4_server_add_ip(NDhcp4Server *server, NDhcp4ServerIp **ipp, struct in_addr ip);

/* server ip addresses */

NDhcp4ServerIp *n_dhcp4_server_ip_free(NDhcp4ServerIp *ip);

/* server leases */

NDhcp4ServerLease *n_dhcp4_server_lease_ref(NDhcp4ServerLease *lease);
NDhcp4ServerLease *n_dhcp4_server_lease_unref(NDhcp4ServerLease *lease);

int n_dhcp4_server_lease_query(NDhcp4ServerLease *lease, uint8_t option, uint8_t **datap, size_t *n_datap);
int n_dhcp4_server_lease_append(NDhcp4ServerLease *lease, uint8_t option, uint8_t *data, size_t n_data);

int n_dhcp4_server_lease_offer(NDhcp4ServerLease *lease);
int n_dhcp4_server_lease_ack(NDhcp4ServerLease *lease);
int n_dhcp4_server_lease_nack(NDhcp4ServerLease *lease);

/* inline helpers */

static inline void n_dhcp4_client_config_freep(NDhcp4ClientConfig **p) {
        if (*p)
                n_dhcp4_client_config_free(*p);
}

static inline void n_dhcp4_client_config_freev(NDhcp4ClientConfig *p) {
        n_dhcp4_client_config_free(p);
}

static inline void n_dhcp4_client_probe_config_freep(NDhcp4ClientProbeConfig **p) {
        if (*p)
                n_dhcp4_client_probe_config_free(*p);
}

static inline void n_dhcp4_client_probe_config_freev(NDhcp4ClientProbeConfig *p) {
        n_dhcp4_client_probe_config_free(p);
}

static inline void n_dhcp4_client_unrefp(NDhcp4Client **p) {
        if (*p)
                n_dhcp4_client_unref(*p);
}

static inline void n_dhcp4_client_unrefv(NDhcp4Client *p) {
        n_dhcp4_client_unref(p);
}

static inline void n_dhcp4_client_probe_freep(NDhcp4ClientProbe **p) {
        if (*p)
                n_dhcp4_client_probe_free(*p);
}

static inline void n_dhcp4_client_probe_freev(NDhcp4ClientProbe *p) {
        n_dhcp4_client_probe_free(p);
}

static inline void n_dhcp4_client_lease_unrefp(NDhcp4ClientLease **p) {
        if (*p)
                n_dhcp4_client_lease_unref(*p);
}

static inline void n_dhcp4_client_lease_unrefv(NDhcp4ClientLease *p) {
        n_dhcp4_client_lease_unref(p);
}

static inline void n_dhcp4_server_config_freep(NDhcp4ServerConfig **p) {
        if (*p)
                n_dhcp4_server_config_free(*p);
}

static inline void n_dhcp4_server_config_freev(NDhcp4ServerConfig *p) {
        n_dhcp4_server_config_free(p);
}

static inline void n_dhcp4_server_unrefp(NDhcp4Server **p) {
        if (*p)
                n_dhcp4_server_unref(*p);
}

static inline void n_dhcp4_server_unrefv(NDhcp4Server *p) {
        n_dhcp4_server_unref(p);
}

static inline void n_dhcp4_server_ip_freep(NDhcp4ServerIp **p) {
        if (*p)
                n_dhcp4_server_ip_free(*p);
}

static inline void n_dhcp4_server_ip_freev(NDhcp4ServerIp *p) {
        n_dhcp4_server_ip_free(p);
}

static inline void n_dhcp4_server_lease_unrefp(NDhcp4ServerLease **p) {
        if (*p)
                n_dhcp4_server_lease_unref(*p);
}

static inline void n_dhcp4_server_lease_unrefv(NDhcp4ServerLease *p) {
        n_dhcp4_server_lease_unref(p);
}

#ifdef __cplusplus
}
#endif
