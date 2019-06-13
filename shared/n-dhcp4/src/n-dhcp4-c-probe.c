/*
 * DHCPv4 Client Probes
 *
 * The probe object is used to represent the lifetime of a DHCP client session.
 * A running probe discovers DHCP servers, requests a lease, and maintains that
 * lease.
 */

#include <assert.h>
#include <c-list.h>
#include <c-siphash.h>
#include <c-stdaux.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include "n-dhcp4.h"
#include "n-dhcp4-private.h"


static int n_dhcp4_client_probe_option_new(NDhcp4ClientProbeOption **optionp,
                                    uint8_t option,
                                    const void *data,
                                    uint8_t n_data) {
        NDhcp4ClientProbeOption *op;

        op = malloc(sizeof(op) + n_data);
        if (!op)
                return -ENOMEM;

        op->option = option;
        op->n_data = n_data;
        memcpy(op->data, data, n_data);

        *optionp = op;
        return 0;
}

static void n_dhcp4_client_probe_option_free(NDhcp4ClientProbeOption *option) {
        if (option)
                free(option);
}

/**
 * n_dhcp4_client_probe_config_new() - create new probe configuration
 * @configp:                    output argument to store new configuration
 *
 * This creates a new probe configuration object. The object is a collection of
 * parameters for probes. No data verification is done by the configuration
 * object. Instead, when passing the configuration to the constructor of a
 * probe, this constructor will perform parameter validation.
 *
 * A probe configuration is an unlinked object only used to pass information to
 * a probe constructor. The caller fully owns the returned configuration object
 * and is responsible to free it when no longer needed.
 *
 * Return: 0 on success, negative error code on failure.
 */
_c_public_ int n_dhcp4_client_probe_config_new(NDhcp4ClientProbeConfig **configp) {
        _c_cleanup_(n_dhcp4_client_probe_config_freep) NDhcp4ClientProbeConfig *config = NULL;

        config = calloc(1, sizeof(*config));
        if (!config)
                return -ENOMEM;

        *config = (NDhcp4ClientProbeConfig)N_DHCP4_CLIENT_PROBE_CONFIG_NULL(*config);

        *configp = config;
        config = NULL;
        return 0;
}

/**
 * n_dhcp4_client_probe_config_free() - destroy probe configuration
 * @config:                     configuration to operate on, or NULL
 *
 * This destroys a probe configuration object and deallocates all its
 * resources.
 *
 * If @config is NULL, this is a no-op.
 *
 * Return: NULL is returned.
 */
_c_public_ NDhcp4ClientProbeConfig *n_dhcp4_client_probe_config_free(NDhcp4ClientProbeConfig *config) {
        if (!config)
                return NULL;

        for (unsigned int i = 0; i <= UINT8_MAX; ++i)
                n_dhcp4_client_probe_option_free(config->options[i]);

        free(config);

        return NULL;
}

/**
 * n_dhcp4_client_probe_config_dup() - duplicate probe configuration
 * @config:                     configuration to operate on
 * @dupp:                       output argument for duplicate
 *
 * This duplicates the probe configuration given as @config and returns it in
 * @dupp to the caller.
 *
 * Return: 0 on success, negative error code on failure.
 */
int n_dhcp4_client_probe_config_dup(NDhcp4ClientProbeConfig *config,
                                    NDhcp4ClientProbeConfig **dupp) {
        _c_cleanup_(n_dhcp4_client_probe_config_freep) NDhcp4ClientProbeConfig *dup = NULL;
        int r;

        r = n_dhcp4_client_probe_config_new(&dup);
        if (r)
                return r;

        dup->inform_only = config->inform_only;
        dup->init_reboot = config->init_reboot;
        dup->requested_ip = config->requested_ip;
        dup->ms_start_delay = config->ms_start_delay;

        for (unsigned int i = 0; i < config->n_request_parameters; ++i)
                dup->request_parameters[dup->n_request_parameters++] = config->request_parameters[i];

        for (unsigned int i = 0; i <= UINT8_MAX; ++i) {
                if (!config->options[i])
                        break;

                r = n_dhcp4_client_probe_option_new(&dup->options[i],
                                                    config->options[i]->option,
                                                    config->options[i]->data,
                                                    config->options[i]->n_data);
                if (r)
                        return r;
        }

        *dupp = dup;
        dup = NULL;
        return 0;
}

/**
 * n_dhcp4_client_probe_config_set_inform_only() - set inform-only property
 * @config:                     configuration to operate on
 * @inform_only:                value to set
 *
 * This sets the inform-only property of the given configuration object. This
 * property controls whether the client probe should request a full lease, or
 * whether it should just ask for auxiliary information without requesting an
 * address.
 *
 * The default is to request a full lease and address. If inform-only is set to
 * true, only auxiliary information will be requested.
 *
 * XXX: This is currently not implemented, and setting the property has no effect.
 */
_c_public_ void n_dhcp4_client_probe_config_set_inform_only(NDhcp4ClientProbeConfig *config, bool inform_only) {
        config->inform_only = inform_only;
}

/**
 * n_dhcp4_client_probe_config_set_init_reboot() - set init-reboot property
 * @config:                     configuration to operate on
 * @init_reboot:                value to set
 *
 * This sets the init-reboot property of the given configuration object. If this
 * is enabled, a requested IP address must also be set.
 *
 * The default is false. If set to true, a probe will make use of the
 * INIT-REBOOT path, as described by the DHCP specification. In most cases, you
 * do not want this.
 *
 * XXX: This is currently not implemented, and setting the property has no effect.
 *
 * Background: The INIT-REBOOT path allows a DHCP client to skip
 *             server-discovery when rebooting/resuming their machine. The DHCP
 *             client simply re-requests the lease it had acquired before. This
 *             saves one roundtrip in the success-case, since the DISCOVER step
 *             is skipped. However, there are little to no timeouts involved,
 *             so the roundtrip should be barely noticeable. In contrast, if
 *             the INIT-REBOOT fails (because the lease is no longer valid, or
 *             not valid on this network), the client has to wait for a
 *             possible answer to the request before actually starting the DHCP
 *             process all over. This significantly increases the time needed
 *             to switch networks.
 *             The INIT-REBOOT state might have been a real improvements with
 *             the old resend-timeouts mandated by the DHCP specification.
 *             However, on modern networks with improved timeout values we
 *             recommend against using it.
 */
_c_public_ void n_dhcp4_client_probe_config_set_init_reboot(NDhcp4ClientProbeConfig *config, bool init_reboot) {
        config->init_reboot = init_reboot;
}

/**
 * n_dhcp4_client_probe_config_set_requested_ip() - set requested-ip property
 * @config:                     configuration to operate on
 * @ip:                         value to set
 *
 * This sets the requested-ip property of the given configuration object.
 *
 * The default is all 0. If set to something else, the DHCP discovery will
 * include this IP in its requests to tell DHCP servers which address to pick.
 * Servers are not required to honor this, nor does this have any effect on
 * servers not serving this address.
 *
 * This field should always be set if the caller knows of an address that was
 * previously acquired on this network. It serves as hint to servers and will
 * allow them to provide the same address again.
 */
_c_public_ void n_dhcp4_client_probe_config_set_requested_ip(NDhcp4ClientProbeConfig *config, struct in_addr ip) {
        config->requested_ip = ip;
}

/**
 * n_dhcp4_client_probe_config_set_start_delay() - set start delay
 * @config:                     configuration to operate on
 * @msecs:                      value to set
 *
 * This sets the start delay property of the given configuration object.
 *
 * The default is 9000 ms, which is based on RFC2131. In the RFC the start
 * delay is specified to be a random value in the range 1000 to 10.000 ms.
 * However, there does not appear to be any particular reason to
 * unconditionally wait at least one second, so we move the range down to
 * start at 0 ms. The reaon for the random delay is to avoid network-wide
 * events causing too much simultaneous network traffic. However, on modern
 * networks, a more reasonable value may be in the 10 ms range.
 */
_c_public_ void n_dhcp4_client_probe_config_set_start_delay(NDhcp4ClientProbeConfig *config, uint64_t msecs) {
        config->ms_start_delay = msecs;
}

/**
 * n_dhpc4_client_probe_config_request_option() - append option to request from the server
 * @config:                     configuration to operate on
 * @option:                     option to request
 *
 * This adds an option to the list of options to request from the server.
 *
 * A server may send options that we do not requst, and it may omit options
 * that we do request. However, to increase the likelyhood of uniform behavior
 * between server implementations, we do not expose options that were not
 * explicitly requested.
 *
 * When called multiple times, the order matters. Earlier requests are
 * considered higher priority than later requests, in case the server must omit
 * some, due to a lack of space. If the same option is requested more than once,
 * only the first call has an effect.
 */
_c_public_ void n_dhcp4_client_probe_config_request_option(NDhcp4ClientProbeConfig *config, uint8_t option) {
        for (unsigned int i = 0; i < config->n_request_parameters; ++i) {
                if (config->request_parameters[i] == option)
                        return;
        }

        c_assert(config->n_request_parameters <= UINT8_MAX);

        config->request_parameters[config->n_request_parameters++] = option;
}

/**
 * n_dhcp4_client_probe_config_append_option() - append option to outgoing messages
 * @config:                     configuration to operate on
 * @option:                     DHCP option number
 * @data:                       payload
 * @n_data:                     number of bytes in payload
 *
 * This sets extra options on a given configuration object.
 *
 * These options are appended verbatim to outgoing messages where
 * that is supported by the specification. The same options are
 * appended to all messages.
 *
 * No option may be appended more than once. Options considered internal
 * to the DHCP protocol may not be appended.
 *
 * Return: 0 on success, N_DHCP4_E_DUPLICATE_OPTION if an option has already been
 *         appended, N_DHCP4_E_INTERNAL if the option is not configurable, or
 *         a negative error code on failure.
 */
_c_public_ int n_dhcp4_client_probe_config_append_option(NDhcp4ClientProbeConfig *config,
                                                       uint8_t option,
                                                       const void *data,
                                                       uint8_t n_data) {
        int r;

        /* XXX: filter internal options */

        for (unsigned int i = 0; i <= UINT8_MAX; ++i) {
                if (config->options[i]) {
                        if (config->options[i]->option == option)
                                return N_DHCP4_E_DUPLICATE_OPTION;

                        continue;
                }

                r = n_dhcp4_client_probe_option_new(&config->options[i],
                                                    option,
                                                    data,
                                                    n_data);
                if (r)
                        return r;

                return 0;
        }

        c_assert(0);
        return -ENOTRECOVERABLE;
}

static void n_dhcp4_client_probe_config_initialize_random_seed(NDhcp4ClientProbeConfig *config) {
        uint8_t hash_seed[] = {
                0x25, 0x3f, 0x02, 0x75, 0x3a, 0xb8, 0x4f, 0x91,
                0x9d, 0x0a, 0xd6, 0x15, 0x9d, 0x72, 0x7b, 0xcb,
        };
        CSipHash hash = C_SIPHASH_NULL;
        unsigned short int seed16v[3];
        const uint8_t *p;
        uint64_t u64;
        int r;

        /*
         * Initialize seed48_r(3)
         *
         * We need random jitter for all timeouts and delays, used to reduce
         * network traffic during bursts. This is not meant as security measure
         * but only meant to improve network utilization during bursts. The
         * random source is thus negligible. However, we want, under all
         * circumstances, avoid two instances running with the same seed. Thus
         * we source the seed from AT_RANDOM, which grants us a per-process
         * unique seed. We then add the current time to make sure consequetive
         * instances use different seeds (to avoid clashes if processes are
         * duplicated, or similar), and lastly we add the config memory address
         * to avoid clashes of multiple parallel instances.
         *
         * Again, none of these are meant as security measure, but only to
         * avoid *ACCIDENTAL* seed clashes. That is, in the case that many
         * transactions are started in parallel, we delay the individual
         * messages (as described in the spec), to reduce the traffic on the
         * network and the chance of packets being dropped (and thus triggering
         * timeouts and resends).
         *
         * We hash everything through SipHash, to avoid exposing AT_RANDOM and
         * other sources to the network. We use a static salt to distinguish it
         * from other implementations using the same random source.
         */
        c_siphash_init(&hash, hash_seed);

        p = (const uint8_t *)getauxval(AT_RANDOM);
        if (p)
                c_siphash_append(&hash, p, 16);

        u64 = n_dhcp4_gettime(CLOCK_MONOTONIC);
        c_siphash_append(&hash, (const uint8_t *)&u64, sizeof(u64));

        c_siphash_append(&hash, (const uint8_t *)&config, sizeof(config));

        u64 = c_siphash_finalize(&hash);

        seed16v[0] = (u64 >>  0) ^ (u64 >> 48);
        seed16v[1] = (u64 >> 16) ^ (u64 >>  0);
        seed16v[2] = (u64 >> 32) ^ (u64 >> 16);

        r = seed48_r(seed16v, &config->entropy);
        c_assert(!r);
}

/**
 * n_dhcp4_client_probe_config_get_random() - get random data
 * @config:                     config object to operate on
 *
 * Fetch the next 32bit random number from the entropy pool in @config.
 * Note that this is in no way suitable for security purposes.
 *
 * Return: the random data.
 */
uint32_t n_dhcp4_client_probe_config_get_random(NDhcp4ClientProbeConfig *config) {
        long int result;
        int r;

        r = mrand48_r(&config->entropy, &result);
        c_assert(!r);

        return result;
};

/**
 * n_dhcp4_client_probe_new() - create new client probe
 * @probep:                     output argument for new client probe
 * @config:                     probe configuration
 * @client:                     client to probe on behalf of
 * @ns_now:                     the current time
 *
 * This creates a new client probe object.
 *
 * If one is already running, the new one will be immediately (but asynchronously)
 * cancelled. Otherwise, a DISCOVER event is scheduled after a randomized delay.
 *
 * Return: 0 on success, or a negative error code on failure.
 */
int n_dhcp4_client_probe_new(NDhcp4ClientProbe **probep,
                             NDhcp4ClientProbeConfig *config,
                             NDhcp4Client *client,
                             uint64_t ns_now) {
        _c_cleanup_(n_dhcp4_client_probe_freep) NDhcp4ClientProbe *probe = NULL;
        bool active;
        int r;

        /*
         * If there is already a probe attached, we create the new probe in
         * detached state. It will not be linked into the epoll context and not
         * be useful in any way. We immediately raise the CANCELLED event to
         * notify the caller about it.
         */
        active = !client->current_probe;

        probe = calloc(1, sizeof(*probe));
        if (!probe)
                return -ENOMEM;

        *probe = (NDhcp4ClientProbe)N_DHCP4_CLIENT_PROBE_NULL(*probe);
        probe->client = n_dhcp4_client_ref(client);

        r = n_dhcp4_client_probe_config_dup(config, &probe->config);
        if (r)
                return r;

        /*
         * XXX: make seed initialization optional, so the entropy can be reused.
         */
        n_dhcp4_client_probe_config_initialize_random_seed(probe->config);

        r = n_dhcp4_c_connection_init(&probe->connection,
                                      client->config,
                                      probe->config,
                                      active ? client->fd_epoll : -1);
        if (r)
                return r;

        if (active) {
                /*
                 * Defer the sending of DISCOVER by a random amount (by default up to 9 seconds).
                 */
                probe->ns_deferred = ns_now + (n_dhcp4_client_probe_config_get_random(probe->config) % (probe->config->ms_start_delay * 1000000ULL));
                probe->client->current_probe = probe;
        } else {
                r = n_dhcp4_client_probe_raise(probe,
                                               NULL,
                                               N_DHCP4_CLIENT_EVENT_CANCELLED);
                if (r)
                        return r;
        }

        *probep = probe;
        probe = NULL;
        return 0;
}

/**
 * n_dhcp4_client_probe_free() - destroy a probe
 * @probe:                      probe to operate on, or NULL
 *
 * This destroys a probe object and deallocates all its resources.
 *
 * If @probe is NULL, this is a no-op.
 *
 * Return: NULL is returned.
 */
_c_public_ NDhcp4ClientProbe *n_dhcp4_client_probe_free(NDhcp4ClientProbe *probe) {
        NDhcp4CEventNode *node, *t_node;
        NDhcp4ClientLease *lease, *t_lease;

        if (!probe)
                return NULL;

        c_list_for_each_entry_safe(lease, t_lease, &probe->lease_list, probe_link)
                n_dhcp4_client_lease_unlink(lease);

        c_list_for_each_entry_safe(node, t_node, &probe->event_list, probe_link)
                n_dhcp4_c_event_node_free(node);

        if (probe == probe->client->current_probe)
                probe->client->current_probe = NULL;

        n_dhcp4_client_lease_unref(probe->current_lease);
        n_dhcp4_c_connection_deinit(&probe->connection);
        n_dhcp4_client_unref(probe->client);
        n_dhcp4_client_probe_config_free(probe->config);

        c_assert(c_list_is_empty(&probe->lease_list));
        c_assert(c_list_is_empty(&probe->event_list));
        free(probe);

        return NULL;
}

/**
 * n_dhcp4_client_probe_set_userdata() - set userdata pointer
 * @probe:                      the probe to operate on
 * @userdata:                   pointer to userdata
 *
 * Set a userdata pointer. The pointed to data is still owned by the caller, and
 * is completely opaque to the probe.
 */
_c_public_ void n_dhcp4_client_probe_set_userdata(NDhcp4ClientProbe *probe, void *userdata) {
        probe->userdata = userdata;
}

/**
 * n_dhcp4_client_probe_get_userdata() - get userdata pointer
 * @probe:                      the probe to operate on
 * @userdatap:                  return pointer for userdata pointer
 *
 * Get the userdata pointer. The lifetime of the userdata and making sure it is
 * still valid when accessed via the probe is the responsibility of the caller.
 */
_c_public_ void n_dhcp4_client_probe_get_userdata(NDhcp4ClientProbe *probe, void **userdatap) {
        *userdatap = probe->userdata;
}

/**
 * n_dhcp4_client_probe_raise() - XXX
 */
int n_dhcp4_client_probe_raise(NDhcp4ClientProbe *probe, NDhcp4CEventNode **nodep, unsigned int event) {
        NDhcp4CEventNode *node;
        int r;

        r = n_dhcp4_client_raise(probe->client, &node, event);
        if (r)
                return r;

        switch (event) {
        case N_DHCP4_CLIENT_EVENT_OFFER:
                node->event.offer.probe = probe;
                break;
        case N_DHCP4_CLIENT_EVENT_GRANTED:
                node->event.granted.probe = probe;
                break;
        case N_DHCP4_CLIENT_EVENT_RETRACTED:
                node->event.retracted.probe = probe;
                break;
        case N_DHCP4_CLIENT_EVENT_EXTENDED:
                node->event.extended.probe = probe;
                break;
        case N_DHCP4_CLIENT_EVENT_EXPIRED:
                node->event.expired.probe = probe;
                break;
        case N_DHCP4_CLIENT_EVENT_CANCELLED:
                node->event.cancelled.probe = probe;
                break;
        default:
                c_assert(0);
                n_dhcp4_c_event_node_free(node);
                return -ENOTRECOVERABLE;
        }

        if (nodep)
                *nodep = node;
        return 0;
}

void n_dhcp4_client_probe_get_timeout(NDhcp4ClientProbe *probe, uint64_t *timeoutp) {
        uint64_t t1 = 0;
        uint64_t t2 = 0;
        uint64_t lifetime = 0;
        uint64_t timeout = 0;

        if (probe->current_lease) {
                t1 = probe->current_lease->t1;
                t2 = probe->current_lease->t2;
                lifetime = probe->current_lease->lifetime;
        }

        n_dhcp4_c_connection_get_timeout(&probe->connection, &timeout);

        switch (probe->state) {
        case N_DHCP4_CLIENT_PROBE_STATE_INIT:
                if (probe->ns_deferred && (!timeout || probe->ns_deferred < timeout))
                        timeout = probe->ns_deferred;

                break;
        case N_DHCP4_CLIENT_PROBE_STATE_BOUND:
                if (t1 && (!timeout || t1 < timeout))
                        timeout = t1;

                /* fall-through */
        case N_DHCP4_CLIENT_PROBE_STATE_RENEWING:
                if (t2 && (!timeout || t2 < timeout))
                        timeout = t2;

                /* fall-through */
        case N_DHCP4_CLIENT_PROBE_STATE_REBINDING:
        case N_DHCP4_CLIENT_PROBE_STATE_GRANTED:
                if (lifetime && (!timeout || lifetime < timeout))
                        timeout = lifetime;
                break;
        default:
                /* ignore */
                break;
        }

        *timeoutp = timeout;
}

static int n_dhcp4_client_probe_outgoing_append_options(NDhcp4ClientProbe *probe, NDhcp4Outgoing *outgoing) {
        int r;

        for (unsigned int i = 0; i <= UINT8_MAX; ++i) {
                if (!probe->config->options[i])
                        break;

                r = n_dhcp4_outgoing_append(outgoing,
                                            probe->config->options[i]->option,
                                            probe->config->options[i]->data,
                                            probe->config->options[i]->n_data);
                if (r) {
                        if (r == N_DHCP4_E_NO_SPACE)
                                /* XXX */
                                break;

                        return r;
                }
        }

        return 0;
}

static int n_dhcp4_client_probe_transition_deferred(NDhcp4ClientProbe *probe, uint64_t ns_now) {
        _c_cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *request = NULL;
        int r;

        switch (probe->state) {
        case N_DHCP4_CLIENT_PROBE_STATE_INIT:
                r = n_dhcp4_c_connection_listen(&probe->connection);
                if (r)
                        return r;

                r = n_dhcp4_c_connection_discover_new(&probe->connection, &request);
                if (r)
                        return r;

                if (probe->config->requested_ip.s_addr != INADDR_ANY) {
                        r = n_dhcp4_outgoing_append_requested_ip(request, probe->config->requested_ip);
                        if (r)
                                return r;
                }

                r = n_dhcp4_client_probe_outgoing_append_options(probe, request);
                if (r)
                        return r;

                r = n_dhcp4_c_connection_start_request(&probe->connection, request, ns_now);
                if (r)
                        return r;
                else
                        request = NULL; /* consumed */

                probe->state = N_DHCP4_CLIENT_PROBE_STATE_SELECTING;
                probe->ns_deferred = 0;

                break;

        case N_DHCP4_CLIENT_PROBE_STATE_SELECTING:
        case N_DHCP4_CLIENT_PROBE_STATE_INIT_REBOOT:
        case N_DHCP4_CLIENT_PROBE_STATE_REBOOTING:
        case N_DHCP4_CLIENT_PROBE_STATE_REQUESTING:
        case N_DHCP4_CLIENT_PROBE_STATE_GRANTED:
        case N_DHCP4_CLIENT_PROBE_STATE_BOUND:
        case N_DHCP4_CLIENT_PROBE_STATE_RENEWING:
        case N_DHCP4_CLIENT_PROBE_STATE_REBINDING:
        case N_DHCP4_CLIENT_PROBE_STATE_EXPIRED:
        default:
                abort();
                break;
        }

        return 0;
}

static int n_dhcp4_client_probe_transition_t1(NDhcp4ClientProbe *probe, uint64_t ns_now) {
        _c_cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *request = NULL;
        int r;

        switch (probe->state) {
        case N_DHCP4_CLIENT_PROBE_STATE_BOUND:
                r = n_dhcp4_c_connection_renew_new(&probe->connection, &request);
                if (r)
                        return r;

                r = n_dhcp4_client_probe_outgoing_append_options(probe, request);
                if (r)
                        return r;

                r = n_dhcp4_c_connection_start_request(&probe->connection, request, ns_now);
                if (r)
                        return r;
                else
                        request = NULL; /* consumed */

                probe->state = N_DHCP4_CLIENT_PROBE_STATE_RENEWING;

                break;

        case N_DHCP4_CLIENT_PROBE_STATE_INIT:
        case N_DHCP4_CLIENT_PROBE_STATE_SELECTING:
        case N_DHCP4_CLIENT_PROBE_STATE_INIT_REBOOT:
        case N_DHCP4_CLIENT_PROBE_STATE_REBOOTING:
        case N_DHCP4_CLIENT_PROBE_STATE_REQUESTING:
        case N_DHCP4_CLIENT_PROBE_STATE_GRANTED:
        case N_DHCP4_CLIENT_PROBE_STATE_RENEWING:
        case N_DHCP4_CLIENT_PROBE_STATE_REBINDING:
        case N_DHCP4_CLIENT_PROBE_STATE_EXPIRED:
        default:
                abort();
                break;
        }

        return 0;
}

static int n_dhcp4_client_probe_transition_t2(NDhcp4ClientProbe *probe, uint64_t ns_now) {
        _c_cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *request = NULL;
        int r;

        switch (probe->state) {
        case N_DHCP4_CLIENT_PROBE_STATE_BOUND:
        case N_DHCP4_CLIENT_PROBE_STATE_RENEWING:
                r = n_dhcp4_c_connection_rebind_new(&probe->connection, &request);
                if (r)
                        return r;

                r = n_dhcp4_client_probe_outgoing_append_options(probe, request);
                if (r)
                        return r;

                r = n_dhcp4_c_connection_start_request(&probe->connection, request, ns_now);
                if (r)
                        return r;
                else
                        request = NULL; /* consumed */

                probe->state = N_DHCP4_CLIENT_PROBE_STATE_REBINDING;

                break;

        case N_DHCP4_CLIENT_PROBE_STATE_INIT:
        case N_DHCP4_CLIENT_PROBE_STATE_SELECTING:
        case N_DHCP4_CLIENT_PROBE_STATE_INIT_REBOOT:
        case N_DHCP4_CLIENT_PROBE_STATE_REBOOTING:
        case N_DHCP4_CLIENT_PROBE_STATE_REQUESTING:
        case N_DHCP4_CLIENT_PROBE_STATE_GRANTED:
        case N_DHCP4_CLIENT_PROBE_STATE_REBINDING:
        case N_DHCP4_CLIENT_PROBE_STATE_EXPIRED:
        default:
                abort();
                break;
        }

        return 0;
}

static int n_dhcp4_client_probe_transition_lifetime(NDhcp4ClientProbe *probe) {
        int r;

        switch (probe->state) {
        case N_DHCP4_CLIENT_PROBE_STATE_BOUND:
        case N_DHCP4_CLIENT_PROBE_STATE_GRANTED:
        case N_DHCP4_CLIENT_PROBE_STATE_RENEWING:
        case N_DHCP4_CLIENT_PROBE_STATE_REBINDING:

                /* XXX */

                r = n_dhcp4_client_probe_raise(probe,
                                               NULL,
                                               N_DHCP4_CLIENT_EVENT_EXPIRED);
                if (r)
                        return r;

                c_assert(probe->client->current_probe == probe);
                probe->client->current_probe = NULL;

                n_dhcp4_c_connection_close(&probe->connection);

                probe->state = N_DHCP4_CLIENT_PROBE_STATE_EXPIRED;

                break;

        case N_DHCP4_CLIENT_PROBE_STATE_INIT:
        case N_DHCP4_CLIENT_PROBE_STATE_SELECTING:
        case N_DHCP4_CLIENT_PROBE_STATE_INIT_REBOOT:
        case N_DHCP4_CLIENT_PROBE_STATE_REBOOTING:
        case N_DHCP4_CLIENT_PROBE_STATE_REQUESTING:
        case N_DHCP4_CLIENT_PROBE_STATE_EXPIRED:
        default:
                abort();
                break;
        }

        return 0;
}

static int n_dhcp4_client_probe_transition_offer(NDhcp4ClientProbe *probe, NDhcp4Incoming *message) {
        _c_cleanup_(n_dhcp4_client_lease_unrefp) NDhcp4ClientLease *lease = NULL;
        NDhcp4CEventNode *node;
        int r;

        switch (probe->state) {
        case N_DHCP4_CLIENT_PROBE_STATE_SELECTING:

                r = n_dhcp4_client_probe_raise(probe,
                                               &node,
                                               N_DHCP4_CLIENT_EVENT_OFFER);
                if (r)
                        return r;

                r = n_dhcp4_client_lease_new(&lease, message);
                if (r)
                        return r;

                /* message consumed, do not fail */

                n_dhcp4_client_lease_link(lease, probe);

                node->event.offer.lease = n_dhcp4_client_lease_ref(lease);

                break;

        case N_DHCP4_CLIENT_PROBE_STATE_INIT:
        case N_DHCP4_CLIENT_PROBE_STATE_INIT_REBOOT:
        case N_DHCP4_CLIENT_PROBE_STATE_REBOOTING:
        case N_DHCP4_CLIENT_PROBE_STATE_REQUESTING:
        case N_DHCP4_CLIENT_PROBE_STATE_BOUND:
        case N_DHCP4_CLIENT_PROBE_STATE_GRANTED:
        case N_DHCP4_CLIENT_PROBE_STATE_RENEWING:
        case N_DHCP4_CLIENT_PROBE_STATE_REBINDING:
        case N_DHCP4_CLIENT_PROBE_STATE_EXPIRED:
        default:
                /* ignore */
                break;
        }

        return 0;
}

static int n_dhcp4_client_probe_transition_ack(NDhcp4ClientProbe *probe, NDhcp4Incoming *message) {
        _c_cleanup_(n_dhcp4_client_lease_unrefp) NDhcp4ClientLease *lease = NULL;
        NDhcp4CEventNode *node;
        int r;

        switch (probe->state) {
        case N_DHCP4_CLIENT_PROBE_STATE_RENEWING:
        case N_DHCP4_CLIENT_PROBE_STATE_REBINDING:

                r = n_dhcp4_client_probe_raise(probe,
                                               &node,
                                               N_DHCP4_CLIENT_EVENT_EXTENDED);
                if (r)
                        return r;

                r = n_dhcp4_client_lease_new(&lease, message);
                if (r)
                        return r;

                /* message consumed, do not fail */

                n_dhcp4_client_lease_link(lease, probe);

                node->event.extended.lease = n_dhcp4_client_lease_ref(lease);
                n_dhcp4_client_lease_unref(probe->current_lease);
                probe->current_lease = n_dhcp4_client_lease_ref(lease);
                probe->state = N_DHCP4_CLIENT_PROBE_STATE_BOUND;

                break;

        case N_DHCP4_CLIENT_PROBE_STATE_REQUESTING:

                r = n_dhcp4_client_probe_raise(probe,
                                               &node,
                                               N_DHCP4_CLIENT_EVENT_GRANTED);
                if (r)
                        return r;

                r = n_dhcp4_client_lease_new(&lease, message);
                if (r)
                        return r;

                /* message consumed, don to fail */

                n_dhcp4_client_lease_link(lease, probe);

                node->event.granted.lease = n_dhcp4_client_lease_ref(lease);
                probe->current_lease = n_dhcp4_client_lease_ref(lease);
                probe->state = N_DHCP4_CLIENT_PROBE_STATE_GRANTED;

                break;

        case N_DHCP4_CLIENT_PROBE_STATE_INIT:
        case N_DHCP4_CLIENT_PROBE_STATE_SELECTING:
        case N_DHCP4_CLIENT_PROBE_STATE_INIT_REBOOT:
        case N_DHCP4_CLIENT_PROBE_STATE_REBOOTING:
        case N_DHCP4_CLIENT_PROBE_STATE_BOUND:
        case N_DHCP4_CLIENT_PROBE_STATE_GRANTED:
        case N_DHCP4_CLIENT_PROBE_STATE_EXPIRED:
        default:
                /* ignore */
                break;
        }

        return 0;
}

static int n_dhcp4_client_probe_transition_nak(NDhcp4ClientProbe *probe) {
        int r;

        switch (probe->state) {
        case N_DHCP4_CLIENT_PROBE_STATE_REBOOTING:
        case N_DHCP4_CLIENT_PROBE_STATE_REQUESTING:
        case N_DHCP4_CLIENT_PROBE_STATE_RENEWING:
        case N_DHCP4_CLIENT_PROBE_STATE_REBINDING:

                /* XXX */

                r = n_dhcp4_client_probe_raise(probe,
                                               NULL,
                                               N_DHCP4_CLIENT_EVENT_RETRACTED);
                if (r)
                        return r;

                probe->state = N_DHCP4_CLIENT_PROBE_STATE_INIT;

                break;

        case N_DHCP4_CLIENT_PROBE_STATE_SELECTING:
        case N_DHCP4_CLIENT_PROBE_STATE_INIT_REBOOT:
        case N_DHCP4_CLIENT_PROBE_STATE_INIT:
        case N_DHCP4_CLIENT_PROBE_STATE_BOUND:
        case N_DHCP4_CLIENT_PROBE_STATE_GRANTED:
        case N_DHCP4_CLIENT_PROBE_STATE_EXPIRED:
        default:
                /* ignore */
                break;
        }

        return 0;
}

int n_dhcp4_client_probe_transition_select(NDhcp4ClientProbe *probe, NDhcp4Incoming *offer, uint64_t ns_now) {
        _c_cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *request = NULL;
        int r;

        switch (probe->state) {
        case N_DHCP4_CLIENT_PROBE_STATE_SELECTING:
                r = n_dhcp4_c_connection_select_new(&probe->connection, &request, offer);
                if (r)
                        return r;

                r = n_dhcp4_client_probe_outgoing_append_options(probe, request);
                if (r)
                        return r;

                r = n_dhcp4_c_connection_start_request(&probe->connection, request, ns_now);
                if (r)
                        return r;
                else
                        request = NULL; /* consumed */

                /* XXX: ignore other offers */

                probe->state = N_DHCP4_CLIENT_PROBE_STATE_REQUESTING;

                break;
        case N_DHCP4_CLIENT_PROBE_STATE_INIT:
        case N_DHCP4_CLIENT_PROBE_STATE_INIT_REBOOT:
        case N_DHCP4_CLIENT_PROBE_STATE_REBOOTING:
        case N_DHCP4_CLIENT_PROBE_STATE_REQUESTING:
        case N_DHCP4_CLIENT_PROBE_STATE_BOUND:
        case N_DHCP4_CLIENT_PROBE_STATE_GRANTED:
        case N_DHCP4_CLIENT_PROBE_STATE_RENEWING:
        case N_DHCP4_CLIENT_PROBE_STATE_REBINDING:
        case N_DHCP4_CLIENT_PROBE_STATE_EXPIRED:
        default:
                /* ignore */
                break;
        }

        return 0;
}

/**
 * n_dhcp4_client_probe_transition_accept() - XXX
 */
int n_dhcp4_client_probe_transition_accept(NDhcp4ClientProbe *probe, NDhcp4Incoming *ack) {
        struct in_addr client = {};
        struct in_addr server = {};
        int r;

        switch (probe->state) {
        case N_DHCP4_CLIENT_PROBE_STATE_GRANTED:
                n_dhcp4_incoming_get_yiaddr(ack, &client);

                r = n_dhcp4_incoming_query_server_identifier(ack, &server);
                if (r)
                        return r;

                r = n_dhcp4_c_connection_connect(&probe->connection, &client, &server);
                if (r)
                        return r;

                probe->state = N_DHCP4_CLIENT_PROBE_STATE_BOUND;

                /* XXX: trigger timers */

                break;

        case N_DHCP4_CLIENT_PROBE_STATE_INIT:
        case N_DHCP4_CLIENT_PROBE_STATE_INIT_REBOOT:
        case N_DHCP4_CLIENT_PROBE_STATE_REBOOTING:
        case N_DHCP4_CLIENT_PROBE_STATE_SELECTING:
        case N_DHCP4_CLIENT_PROBE_STATE_REQUESTING:
        case N_DHCP4_CLIENT_PROBE_STATE_BOUND:
        case N_DHCP4_CLIENT_PROBE_STATE_RENEWING:
        case N_DHCP4_CLIENT_PROBE_STATE_REBINDING:
        case N_DHCP4_CLIENT_PROBE_STATE_EXPIRED:
        default:
                /* ignore */
                break;
        }

        return 0;
}

/**
 * n_dhc4_client_probe_transition_decline() - XXX
 */
int n_dhcp4_client_probe_transition_decline(NDhcp4ClientProbe *probe, NDhcp4Incoming *offer, const char *error, uint64_t ns_now) {
        _c_cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *request = NULL;
        int r;

        switch (probe->state) {
        case N_DHCP4_CLIENT_PROBE_STATE_GRANTED:
                r = n_dhcp4_c_connection_decline_new(&probe->connection, &request, offer, error);
                if (r)
                        return r;

                r = n_dhcp4_c_connection_start_request(&probe->connection, request, ns_now);
                if (r)
                        return r;
                else
                        request = NULL; /* consumed */

                /* XXX: what state to transition to? */

                break;

        case N_DHCP4_CLIENT_PROBE_STATE_INIT:
        case N_DHCP4_CLIENT_PROBE_STATE_INIT_REBOOT:
        case N_DHCP4_CLIENT_PROBE_STATE_REBOOTING:
        case N_DHCP4_CLIENT_PROBE_STATE_SELECTING:
        case N_DHCP4_CLIENT_PROBE_STATE_REQUESTING:
        case N_DHCP4_CLIENT_PROBE_STATE_BOUND:
        case N_DHCP4_CLIENT_PROBE_STATE_RENEWING:
        case N_DHCP4_CLIENT_PROBE_STATE_REBINDING:
        case N_DHCP4_CLIENT_PROBE_STATE_EXPIRED:
        default:
                /* ignore */
                break;
        }

        return 0;
}

/**
 * n_dhcp4_client_probe_dispatch_timer() - XXX
 */
int n_dhcp4_client_probe_dispatch_timer(NDhcp4ClientProbe *probe, uint64_t ns_now) {
        int r;

        switch (probe->state) {
        case N_DHCP4_CLIENT_PROBE_STATE_INIT:
                if (ns_now >= probe->ns_deferred) {
                        r = n_dhcp4_client_probe_transition_deferred(probe, ns_now);
                        if (r)
                                return r;
                }

                break;
        case N_DHCP4_CLIENT_PROBE_STATE_GRANTED:
                if (ns_now >= probe->current_lease->lifetime) {
                        r = n_dhcp4_client_probe_transition_lifetime(probe);
                        if (r)
                                return r;
                }

                break;
        case N_DHCP4_CLIENT_PROBE_STATE_BOUND:
        case N_DHCP4_CLIENT_PROBE_STATE_RENEWING:
        case N_DHCP4_CLIENT_PROBE_STATE_REBINDING:
                if (ns_now >= probe->current_lease->lifetime) {
                        r = n_dhcp4_client_probe_transition_lifetime(probe);
                        if (r)
                                return r;
                } else if (ns_now >= probe->current_lease->t2) {
                        r = n_dhcp4_client_probe_transition_t2(probe, ns_now);
                        if (r)
                                return r;
                } else if (ns_now >= probe->current_lease->t1) {
                        r = n_dhcp4_client_probe_transition_t1(probe, ns_now);
                        if (r)
                                return r;
                }

                break;
        default:
                /* ignore */
                break;
        }

        r = n_dhcp4_c_connection_dispatch_timer(&probe->connection, ns_now);
        if (r)
                return r;

        return 0;
}

/**
 * n_dhcp4_client_probe_dispatch_connection() - XXX
 */
int n_dhcp4_client_probe_dispatch_io(NDhcp4ClientProbe *probe, uint32_t events) {
        _c_cleanup_(n_dhcp4_incoming_freep) NDhcp4Incoming *message = NULL;
        uint8_t type;
        int r;

        r = n_dhcp4_c_connection_dispatch_io(&probe->connection, &message);
        if (r) {
                if (r == N_DHCP4_E_AGAIN)
                        return 0;
                else if (r == N_DHCP4_E_MALFORMED || r == N_DHCP4_E_UNEXPECTED) {
                        /*
                         * We fetched something from the sockets, which we
                         * discarded. We don't know whether there is more data
                         * to fetch, so we set the preempted flag to notify the
                         * caller we want to be called again.
                         */
                        probe->client->preempted = true;
                        return 0;
                }

                return r;
        }

        /*
         * We fetched something from the sockets, which we will handle below.
         * We don't know whether there is more data to fetch, so we set the
         * preempted flag to notify the caller we want to be called again.
         */
        probe->client->preempted = true;

        r = n_dhcp4_incoming_query_message_type(message, &type);
        if (r == N_DHCP4_E_UNSET || r == N_DHCP4_E_MALFORMED)
                /*
                 * XXX: this can never happen as we already queried the message
                 * type.
                 */
                return 0;

        switch (type) {
        case N_DHCP4_MESSAGE_OFFER:
                r = n_dhcp4_client_probe_transition_offer(probe, message);
                if (r)
                        return r;
                else
                        message = NULL; /* consumed */
                break;
        case N_DHCP4_MESSAGE_ACK:
                r = n_dhcp4_client_probe_transition_ack(probe, message);
                if (r)
                        return r;
                else
                        message = NULL; /* consumed */
                break;
        case N_DHCP4_MESSAGE_NAK:
                r = n_dhcp4_client_probe_transition_nak(probe);
                if (r)
                        return r;
                break;
        default:
                /*
                 * We receiveda message type we do not support, simply discard
                 * it.
                 */
                break;
        }

        return 0;
}

/**
 * n_dhcp4_client_probe_update_mtu() - XXX
 */
int n_dhcp4_client_probe_update_mtu(NDhcp4ClientProbe *probe, uint16_t mtu) {
        return 0;
}
