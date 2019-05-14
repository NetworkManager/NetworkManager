/*
 * DHCP Client Runner
 *
 * This test implements a DHCP client. It takes parameters via the command-line
 * and runs a DHCP client. It is mainly meant for testing, as such it allows
 * tweaking that an exported DHCP client should not provide.
 */

#include <assert.h>
#include <c-stdaux.h>
#include <errno.h>
#include <getopt.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "n-dhcp4.h"
#include "n-dhcp4-private.h"
#include "test.h"

typedef struct Manager Manager;

enum {
        _MAIN_SUCCESS,
        MAIN_EXIT,
        MAIN_FAILED,
};

struct Manager {
        NDhcp4Client *client;
        NDhcp4ClientProbe *probe;
};

#define MANAGER_NULL(_x) {}

static struct ether_addr        main_arg_broadcast_mac = {};
static bool                     main_arg_broadcast_mac_set = false;
static uint8_t*                 main_arg_client_id = NULL;
static size_t                   main_arg_n_client_id = 0;
static int                      main_arg_ifindex = 0;
static struct in_addr           main_arg_requested_ip = { INADDR_ANY };
static long long int            main_arg_requested_lifetime = -1;
static uint8_t                  main_arg_requested_parameters[UINT8_MAX] = {};
static size_t                   main_arg_n_requested_parameters = 0;
static struct ether_addr        main_arg_mac = {};
static bool                     main_arg_mac_set = false;
static bool                     main_arg_request_broadcast = false;
static bool                     main_arg_test = false;

static Manager *manager_free(Manager *manager) {
        if (!manager)
                return NULL;

        n_dhcp4_client_probe_free(manager->probe);
        n_dhcp4_client_unref(manager->client);
        free(manager);

        return NULL;
}

static void manager_freep(Manager **manager) {
        manager_free(*manager);
}

static int manager_new(Manager **managerp) {
        _c_cleanup_(n_dhcp4_client_config_freep) NDhcp4ClientConfig *config = NULL;
        _c_cleanup_(manager_freep) Manager *manager = NULL;
        int r;

        manager = malloc(sizeof(*manager));
        if (!manager)
                return -ENOMEM;

        *manager = (Manager)MANAGER_NULL(*manager);

        r = n_dhcp4_client_config_new(&config);
        if (r)
                return r;

        n_dhcp4_client_config_set_broadcast_mac(config,
                                                &main_arg_broadcast_mac.ether_addr_octet[0],
                                                sizeof(main_arg_broadcast_mac.ether_addr_octet));
        n_dhcp4_client_config_set_mac(config,
                                      &main_arg_mac.ether_addr_octet[0],
                                      sizeof(main_arg_mac.ether_addr_octet));
        n_dhcp4_client_config_set_client_id(config,
                                            main_arg_client_id,
                                            main_arg_n_client_id);
        n_dhcp4_client_config_set_ifindex(config, main_arg_ifindex);
        n_dhcp4_client_config_set_request_broadcast(config, main_arg_request_broadcast);
        n_dhcp4_client_config_set_transport(config, N_DHCP4_TRANSPORT_ETHERNET);

        r = n_dhcp4_client_new(&manager->client, config);
        if (r)
                return r;

        *managerp = manager;
        manager = NULL;
        return 0;
}

static int manager_lease_get_dns(NDhcp4ClientLease *lease, struct in_addr *dns) {
        uint8_t *data;
        size_t n_data;
        int r;

        r = n_dhcp4_client_lease_query(lease, N_DHCP4_OPTION_DOMAIN_NAME_SERVER, &data, &n_data);
        if (r)
                return r;

        if (n_data < sizeof(dns->s_addr))
                return N_DHCP4_E_MALFORMED;

        memcpy(&dns->s_addr, data, sizeof(dns->s_addr));

        return 0;
}

static int manager_lease_get_router(NDhcp4ClientLease *lease, struct in_addr *router) {
        uint8_t *data;
        size_t n_data;
        int r;

        r = n_dhcp4_client_lease_query(lease, N_DHCP4_OPTION_ROUTER, &data, &n_data);
        if (r)
                return r;

        if (n_data < sizeof(router->s_addr))
                return N_DHCP4_E_MALFORMED;

        memcpy(&router->s_addr, data, sizeof(router->s_addr));

        return 0;
}

static int manager_lease_get_subnetmask(NDhcp4ClientLease *lease, struct in_addr *mask) {
        uint8_t *data;
        size_t n_data;
        int r;

        r = n_dhcp4_client_lease_query(lease, N_DHCP4_OPTION_SUBNET_MASK, &data, &n_data);
        if (r)
                return r;

        if (n_data != sizeof(mask->s_addr))
                return N_DHCP4_E_MALFORMED;

        memcpy(&mask->s_addr, data, sizeof(mask->s_addr));

        return 0;
}

static int manager_lease_get_prefix(NDhcp4ClientLease *lease, unsigned int *prefixp) {
        struct in_addr mask = {};
        unsigned int postfix;
        int r;

        r = manager_lease_get_subnetmask(lease, &mask);
        if (r)
                return r;

        postfix =__builtin_ctz(ntohl(mask.s_addr));
        c_assert(postfix <= 32);

        if (postfix < 32) {
                if ((~ntohl(mask.s_addr)) >> postfix != 0)
                        return N_DHCP4_E_MALFORMED;
        }

        *prefixp = 32 - postfix;
        return 0;
}

static int manager_check(Manager *manager, NDhcp4ClientLease *lease) {
        int r;

        r = n_dhcp4_client_lease_query(lease, N_DHCP4_OPTION_ROUTER, NULL, NULL);
        if (r) {
                fprintf(stderr, "No router\n");
                return r;
        }

        r = n_dhcp4_client_lease_query(lease, N_DHCP4_OPTION_SUBNET_MASK, NULL, NULL);
        if (r) {
                fprintf(stderr, "No subnet mask\n");
                return r;
        }

        return r;
}

static int manager_add(Manager *manager, NDhcp4ClientLease *lease) {
        char *p, ifname[IF_NAMESIZE + 1] = {};
        struct in_addr router = {}, yiaddr = {}, dns = {};
        unsigned int prefix;
        uint64_t lifetime;
        int r;

        n_dhcp4_client_lease_get_yiaddr(lease, &yiaddr);
        n_dhcp4_client_lease_get_lifetime(lease, &lifetime);

        r = manager_lease_get_router(lease, &router);
        if (r)
                return r;

        r = manager_lease_get_prefix(lease, &prefix);
        if (r)
                return r;

        p = if_indextoname(main_arg_ifindex, ifname);
        c_assert(p);

        if (lifetime == UINT64_MAX) {
                r = asprintf(&p, "ip addr add %s/%u dev %s preferred_lft forever valid_lft forever", inet_ntoa(yiaddr), prefix, ifname);
                c_assert(r >= 0);
        } else {
                r = asprintf(&p, "ip addr add %s/%u dev %s preferred_lft %llu valid_lft %llu", inet_ntoa(yiaddr), prefix, ifname, lifetime / 1000000000ULL, lifetime / 1000000000ULL);
                c_assert(r >= 0);
        }
        r = system(p);
        c_assert(r == 0);
        free(p);

        r = asprintf(&p, "ip route add %s/32 dev %s", inet_ntoa(router), ifname);
        c_assert(r >= 0);
        r = system(p);
        c_assert(r == 0);
        free(p);

        r = asprintf(&p, "ip route add default via %s dev %s", inet_ntoa(router), ifname);
        c_assert(r >= 0);
        r = system(p);
        c_assert(r == 0);
        free(p);

        r = manager_lease_get_dns(lease, &dns);
        if (r) {
                if (r != N_DHCP4_E_UNSET)
                        return r;
        } else {
                fprintf(stderr, "DNS: %s\n", inet_ntoa(dns));
        }

        return 0;
}

static int manager_dispatch(Manager *manager) {
        NDhcp4ClientEvent *event;
        int r;

        r = n_dhcp4_client_dispatch(manager->client);
        if (r) {
                if (r != N_DHCP4_E_PREEMPTED) {
                        /*
                         * We are level-triggered, so we do not need to react
                         * to preemption. We simply continue the mainloop.
                         */
                        return r;
                }
        }

        for (;;) {
                r = n_dhcp4_client_pop_event(manager->client, &event);
                if (r)
                        return r;

                if (!event)
                        break;

                switch (event->event) {
                case N_DHCP4_CLIENT_EVENT_DOWN:
                        fprintf(stderr, "DOWN\n");

                        break;

                case N_DHCP4_CLIENT_EVENT_OFFER:
                        fprintf(stderr, "OFFER\n");

                        r = manager_check(manager, event->granted.lease);
                        if (r) {
                                if (r == N_DHCP4_E_UNSET) {
                                        fprintf(stderr, "Missing mandatory option, ignoring lease.\n");
                                } else {
                                        return r;
                                }
                        } else {
                                r = n_dhcp4_client_lease_select(event->offer.lease);
                                if (r)
                                        return r;
                        }

                        break;

                case N_DHCP4_CLIENT_EVENT_GRANTED:
                        fprintf(stderr, "GRANTED\n");

                        r = manager_add(manager, event->granted.lease);
                        if (r) {
                                if (r == N_DHCP4_E_UNSET) {
                                        fprintf(stderr, "Missing mandatory option, declining lease.\n");

                                        r = n_dhcp4_client_lease_decline(event->granted.lease, "Missing mandatory option.");
                                        if (r)
                                                return r;
                                } else {
                                        return r;
                                }
                        } else {
                                r = n_dhcp4_client_lease_accept(event->granted.lease);
                                if (r)
                                        return r;
                        }

                        break;

                case N_DHCP4_CLIENT_EVENT_RETRACTED:
                        fprintf(stderr, "RETRACTED\n");

                        break;

                case N_DHCP4_CLIENT_EVENT_EXTENDED:
                        fprintf(stderr, "EXTENDED\n");

                        break;

                case N_DHCP4_CLIENT_EVENT_EXPIRED:
                        fprintf(stderr, "EXPIRED\n");

                        break;

                case N_DHCP4_CLIENT_EVENT_CANCELLED:
                        fprintf(stderr, "CANCELLED\n");

                        break;

                default:
                        fprintf(stderr, "Unexpected event: %u\n", event->event);

                        break;
                }
        }

        return 0;
}

static int manager_run(Manager *manager) {
        _c_cleanup_(n_dhcp4_client_probe_config_freep) NDhcp4ClientProbeConfig *config = NULL;
        int r;

        r = n_dhcp4_client_probe_config_new(&config);
        if (r)
                return r;

        /*
         * Let's speed up our tests, while still making sure the code-path
         * for the deferrment is actually tested (so don't set it to zero).
         */
        n_dhcp4_client_probe_config_set_start_delay(config, 10);

        n_dhcp4_client_probe_config_set_requested_ip(config, main_arg_requested_ip);

        if (main_arg_n_requested_parameters > 0) {
                for (unsigned int i = 0; i < main_arg_n_requested_parameters; ++i)
                        n_dhcp4_client_probe_config_request_option(config, main_arg_requested_parameters[i]);
        } else {
                n_dhcp4_client_probe_config_request_option(config, N_DHCP4_OPTION_ROUTER);
                n_dhcp4_client_probe_config_request_option(config, N_DHCP4_OPTION_SUBNET_MASK);
                n_dhcp4_client_probe_config_request_option(config, N_DHCP4_OPTION_DOMAIN_NAME_SERVER);
        }

        if (main_arg_requested_lifetime >= 0) {
                uint32_t lifetime = ntohl(main_arg_requested_lifetime);

                r = n_dhcp4_client_probe_config_append_option(config, N_DHCP4_OPTION_IP_ADDRESS_LEASE_TIME, &lifetime, sizeof(lifetime));
                if (r)
                        return r;
        }

        r = n_dhcp4_client_probe(manager->client, &manager->probe, config);
        if (r)
                return r;

        /*
         * The test-suite runs this with the --test argument. So far, we do not
         * perform any fancy runtime tests, but simply exit the main-loop
         * immediately. We can add more elaborate tests in the future.
         */
        if (main_arg_test)
                return 0;

        for (;;) {
                struct pollfd pfds[] = {
                        { .fd = -1, .events = POLLIN },
                };
                size_t i;
                int n;

                n_dhcp4_client_get_fd(manager->client, &pfds[0].fd);

                n = poll(pfds, sizeof(pfds) / sizeof(*pfds), -1);
                if (n < 0)
                        return -errno;

                for (i = 0; i < (size_t)n; ++i) {
                        if (pfds[i].revents & ~POLLIN)
                                return -ENOTRECOVERABLE;

                        if (!(pfds[i].revents & POLLIN))
                                continue;

                        r = manager_dispatch(manager);
                        if (r)
                                return r;
                }
        }

        return 0;
}

static int run(void) {
        _c_cleanup_(manager_freep) Manager *manager = NULL;
        int r;

        r = manager_new(&manager);
        if (r)
                return r;

        return manager_run(manager);
}

static void print_help(void) {
        printf("%s [GLOBALS...] ...\n\n"
               "DHCP Test Client\n\n"
               "  -h --help                            Show this help\n"
               "     --test                            Run as part of the test suite\n"
               "     --ifindex IDX                     Index of interface to run on\n"
               "     --mac HEX                         Hardware address to use\n"
               "     --broadcast-mac HEX               Broadcast hardware address to use\n"
               "     --requested-ip IP                 Requested IP adress\n"
               "     --requested-lifetime SECS         Requested lease lifetime in seconds\n"
               "     --requested-parameters P1,P2,...  Requested parameters\n"
               "     --client-id HEX                   Client Identifier to use\n"
               , program_invocation_short_name);
}

static int setup_test(void) {
        test_setup();

        /* --broadcast-mac */
        {
                main_arg_broadcast_mac_set = true;
        }

        /* --ifindex */
        {
                main_arg_ifindex = 1;
        }

        /* --mac */
        {
                main_arg_mac_set = true;
        }

        return 0;
}

static int parse_hexstr(const char *in, uint8_t **outp, size_t *n_outp) {
        _c_cleanup_(c_freep) uint8_t *out = NULL;
        size_t i, n_in, n_out;

        n_in = strlen(in);
        n_out = (n_in + 1) / 2;

        out = malloc(n_out);
        if (!out)
                return -ENOMEM;

        for (i = 0; i < n_in; ++i) {
                uint8_t v = 0;

                switch (in[i]) {
                case '0'...'9':
                        v = in[i] - '0';
                        break;
                case 'a'...'f':
                        v = in[i] - 'a' + 0xa;
                        break;
                case 'A'...'F':
                        v = in[i] - 'A' + 0xa;
                        break;
                }

                if (i % 2) {
                        out[i / 2] <<= 4;
                        out[i / 2] |= v;
                } else {
                        out[i / 2] = v;
                }
        }

        *outp = out;
        out = NULL;
        *n_outp = n_out;
        return 0;
}

static int parse_argv(int argc, char **argv) {
        enum {
                _ARG_0 = 0x100,
                ARG_BROADCAST_MAC,
                ARG_CLIENT_ID,
                ARG_IFINDEX,
                ARG_MAC,
                ARG_REQUEST_BROADCAST,
                ARG_REQUESTED_IP,
                ARG_REQUESTED_LIFETIME,
                ARG_REQUESTED_PARAMETERS,
                ARG_TEST,
        };
        static const struct option options[] = {
                { "help",                       no_argument,            NULL,   'h'                             },
                { "broadcast-mac",              required_argument,      NULL,   ARG_BROADCAST_MAC               },
                { "client-id",                  required_argument,      NULL,   ARG_CLIENT_ID                   },
                { "ifindex",                    required_argument,      NULL,   ARG_IFINDEX                     },
                { "mac",                        required_argument,      NULL,   ARG_MAC                         },
                { "request-broadcast",          no_argument,            NULL,   ARG_REQUEST_BROADCAST           },
                { "requested-ip",               required_argument,      NULL,   ARG_REQUESTED_IP                },
                { "requested-lifetime",         required_argument,      NULL,   ARG_REQUESTED_LIFETIME          },
                { "requested-parameters",       required_argument,      NULL,   ARG_REQUESTED_PARAMETERS        },
                { "test",                       no_argument,            NULL,   ARG_TEST                        },
                {}
        };
        struct ether_addr *addr;
        long long int lli;
        size_t n;
        void *t;
        int r, c;

        /*
         * Most of the argument-parsers are short-and-dirty hacks to make the
         * conversions work. This is sufficient for a test-client, but needs
         * proper error-checking if done outside of tests.
         */

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0) {
                switch (c) {
                case 'h':
                        print_help();
                        return MAIN_EXIT;

                case ARG_BROADCAST_MAC:
                        addr = ether_aton_r(optarg, &main_arg_broadcast_mac);
                        if (!addr) {
                                fprintf(stderr,
                                        "%s: invalid broadcast mac address -- '%s'\n",
                                        program_invocation_name,
                                        optarg);
                                return MAIN_FAILED;
                        }

                        main_arg_broadcast_mac_set = true;
                        break;

                case ARG_CLIENT_ID:
                        r = parse_hexstr(optarg, (uint8_t **)&t, &n);
                        if (r)
                                return r;

                        free(main_arg_client_id);
                        main_arg_client_id = t;
                        main_arg_n_client_id = n;
                        break;

                case ARG_IFINDEX:
                        main_arg_ifindex = atoi(optarg);
                        break;

                case ARG_MAC:
                        addr = ether_aton_r(optarg, &main_arg_mac);
                        if (!addr) {
                                fprintf(stderr,
                                        "%s: invalid mac address -- '%s'\n",
                                        program_invocation_name,
                                        optarg);
                                return MAIN_FAILED;
                        }

                        main_arg_mac_set = true;
                        break;

                case ARG_REQUEST_BROADCAST:
                        main_arg_request_broadcast = true;
                        break;

                case ARG_REQUESTED_IP:
                        r = inet_aton(optarg, &main_arg_requested_ip);
                        if (r != 1) {
                                fprintf(stderr,
                                        "%s: invalid requested IP -- '%s'\n",
                                        program_invocation_name,
                                        optarg);
                                return MAIN_FAILED;
                        }
                        break;

                case ARG_REQUESTED_LIFETIME:
                        lli = atoll(optarg);
                        if (lli < 0 || lli > UINT32_MAX) {
                                fprintf(stderr,
                                        "%s: invalid requested lifetime -- '%s'\n",
                                        program_invocation_name,
                                        optarg);
                                return MAIN_FAILED;
                        }
                        main_arg_requested_lifetime = lli;
                        break;

                case ARG_REQUESTED_PARAMETERS:
                        for (const char *param = optarg; param; param = strchr(param, ',') ? strchr(param, ',')  + 1 : NULL) {
                                c_assert(main_arg_n_requested_parameters <= UINT8_MAX);

                                lli = atoll(param);
                                if (lli < 0 || lli > UINT8_MAX) {
                                        fprintf(stderr,
                                                "%s: invalid requested parameters -- '%s'\n",
                                                program_invocation_name,
                                                optarg);
                                        return MAIN_FAILED;
                                }
                                main_arg_requested_parameters[main_arg_n_requested_parameters++] = lli;
                        }
                        break;

                case ARG_TEST:
                        r = setup_test();
                        if (r)
                                return r;

                        main_arg_test = true;
                        break;

                case '?':
                        /* getopt_long() prints warning */
                        return MAIN_FAILED;

                default:
                        return -ENOTRECOVERABLE;
                }
        }

        if (optind != argc) {
                fprintf(stderr,
                        "%s: invalid arguments -- '%s'\n",
                        program_invocation_name,
                        argv[optind]);
                return MAIN_FAILED;
        }

        if (!main_arg_broadcast_mac_set ||
            !main_arg_ifindex ||
            !main_arg_mac_set) {
                fprintf(stderr,
                        "%s: required arguments: broadcast-mac, ifindex, mac\n",
                        program_invocation_name);
                return MAIN_FAILED;
        }

        return 0;
}

int main(int argc, char **argv) {
        int r;

        /* --client-id */
        {
                uint8_t *b;
                size_t n;

                n = strlen("client-id");
                b = malloc(n);
                c_assert(b);
                memcpy(b, "client-id", n);

                free(main_arg_client_id);
                main_arg_client_id = b;
                main_arg_n_client_id = n;
        }

        r = parse_argv(argc, argv);
        if (r)
                goto exit;

        r = run();

exit:
        if (r == MAIN_EXIT) {
                r = 0;
        } else if (r < 0) {
                errno = -r;
                fprintf(stderr, "Failed with system errno %d: %m\n", r);
                r = 127;
        } else if (r > 0) {
                fprintf(stderr, "Failed with internal error %d\n", r);
        }

        free(main_arg_client_id);

        return r;
}
