#pragma once

/*
 * IPv4 Address Conflict Detection
 *
 * This is the public header of the n-acd library, implementing IPv4 Address
 * Conflict Detection as described in RFC-5227. This header defines the public
 * API and all entry points of n-acd.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <netinet/in.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>

typedef struct NAcd NAcd;
typedef struct NAcdConfig NAcdConfig;
typedef struct NAcdEvent NAcdEvent;
typedef struct NAcdProbe NAcdProbe;
typedef struct NAcdProbeConfig NAcdProbeConfig;

#define N_ACD_TIMEOUT_RFC5227 (UINT64_C(9000))

enum {
        _N_ACD_E_SUCCESS,

        N_ACD_E_PREEMPTED,
        N_ACD_E_INVALID_ARGUMENT,

        _N_ACD_E_N,
};

enum {
        N_ACD_TRANSPORT_ETHERNET,
        _N_ACD_TRANSPORT_N,
};

enum {
        N_ACD_EVENT_READY,
        N_ACD_EVENT_USED,
        N_ACD_EVENT_DEFENDED,
        N_ACD_EVENT_CONFLICT,
        N_ACD_EVENT_DOWN,
        _N_ACD_EVENT_N,
};

enum {
        N_ACD_DEFEND_NEVER,
        N_ACD_DEFEND_ONCE,
        N_ACD_DEFEND_ALWAYS,
        _N_ACD_DEFEND_N,
};

struct NAcdEvent {
        unsigned int event;
        union {
                struct {
                        NAcdProbe *probe;
                } ready;
                struct {
                } down;
                struct {
                        NAcdProbe *probe;
                        uint8_t *sender;
                        size_t n_sender;
                } used, defended, conflict;
        };
};

/* configs */

int n_acd_config_new(NAcdConfig **configp);
NAcdConfig *n_acd_config_free(NAcdConfig *config);

void n_acd_config_set_ifindex(NAcdConfig *config, int ifindex);
void n_acd_config_set_transport(NAcdConfig *config, unsigned int transport);
void n_acd_config_set_mac(NAcdConfig *config, const uint8_t *mac, size_t n_mac);

int n_acd_probe_config_new(NAcdProbeConfig **configp);
NAcdProbeConfig *n_acd_probe_config_free(NAcdProbeConfig *config);

void n_acd_probe_config_set_ip(NAcdProbeConfig *config, struct in_addr ip);
void n_acd_probe_config_set_timeout(NAcdProbeConfig *config, uint64_t msecs);

/* contexts */

int n_acd_new(NAcd **acdp, NAcdConfig *config);
NAcd *n_acd_ref(NAcd *acd);
NAcd *n_acd_unref(NAcd *acd);

void n_acd_get_fd(NAcd *acd, int *fdp);
int n_acd_dispatch(NAcd *acd);
int n_acd_pop_event(NAcd *acd, NAcdEvent **eventp);

int n_acd_probe(NAcd *acd, NAcdProbe **probep, NAcdProbeConfig *config);

/* probes */

NAcdProbe *n_acd_probe_free(NAcdProbe *probe);

void n_acd_probe_set_userdata(NAcdProbe *probe, void *userdata);
void n_acd_probe_get_userdata(NAcdProbe *probe, void **userdatap);

int n_acd_probe_announce(NAcdProbe *probe, unsigned int defend);

/* inline helpers */

static inline void n_acd_config_freep(NAcdConfig **config) {
        if (*config)
                n_acd_config_free(*config);
}

static inline void n_acd_config_freev(NAcdConfig *config) {
        n_acd_config_free(config);
}

static inline void n_acd_probe_config_freep(NAcdProbeConfig **config) {
        if (*config)
                n_acd_probe_config_free(*config);
}

static inline void n_acd_probe_config_freev(NAcdProbeConfig *config) {
        n_acd_probe_config_free(config);
}

static inline void n_acd_unrefp(NAcd **acd) {
        if (*acd)
                n_acd_unref(*acd);
}

static inline void n_acd_unrefv(NAcd *acd) {
        n_acd_unref(acd);
}

static inline void n_acd_probe_freep(NAcdProbe **probe) {
        if (*probe)
                n_acd_probe_free(*probe);
}

static inline void n_acd_probe_freev(NAcdProbe *probe) {
        n_acd_probe_free(probe);
}

#ifdef __cplusplus
}
#endif
