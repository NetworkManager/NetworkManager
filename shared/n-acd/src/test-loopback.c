/*
 * Test on loopback device
 * This runs the ACD engine on the loopback device, effectively testing the BPF
 * filter of ACD to discard its own packets. This might happen on
 * non-spanning-tree networks, or on networks that echo packets.
 */

#undef NDEBUG
#include <c-stdaux.h>
#include <stdlib.h>
#include "test.h"

static void test_loopback(int ifindex, uint8_t *mac, size_t n_mac) {
        NAcdConfig *config;
        NAcd *acd;
        struct pollfd pfds;
        int r, fd;

        r = n_acd_config_new(&config);
        c_assert(!r);

        n_acd_config_set_ifindex(config, ifindex);
        n_acd_config_set_transport(config, N_ACD_TRANSPORT_ETHERNET);
        n_acd_config_set_mac(config, mac, n_mac);

        r = n_acd_new(&acd, config);
        c_assert(!r);

        n_acd_config_free(config);

        {
                NAcdProbeConfig *probe_config;
                NAcdProbe *probe;
                struct in_addr ip = { htobe32((192 << 24) | (168 << 16) | (1 << 0)) };

                r = n_acd_probe_config_new(&probe_config);
                c_assert(!r);

                n_acd_probe_config_set_ip(probe_config, ip);
                n_acd_probe_config_set_timeout(probe_config, 100);

                r = n_acd_probe(acd, &probe, probe_config);
                c_assert(!r);

                n_acd_probe_config_free(probe_config);

                n_acd_get_fd(acd, &fd);

                for (;;) {
                        NAcdEvent *event;
                        pfds = (struct pollfd){ .fd = fd, .events = POLLIN };
                        r = poll(&pfds, 1, -1);
                        c_assert(r >= 0);

                        r = n_acd_dispatch(acd);
                        c_assert(!r);

                        r = n_acd_pop_event(acd, &event);
                        c_assert(!r);
                        if (event) {
                                c_assert(event->event == N_ACD_EVENT_READY);
                                break;
                        }
                }

                n_acd_probe_free(probe);
        }

        n_acd_unref(acd);
}

int main(int argc, char **argv) {
        struct ether_addr mac;
        int ifindex;

        test_setup();

        test_loopback_up(&ifindex, &mac);
        test_loopback(ifindex, mac.ether_addr_octet, sizeof(mac.ether_addr_octet));

        return 0;
}
