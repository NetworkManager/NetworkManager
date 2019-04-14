/*
 * Test on a veth link
 *
 * This essentially mimics a real network with two peers.
 *
 * Run one ACD context on each end of the tunnel. On one end probe for N,
 * addresses on the other end pre-configure N/3 of the same addresses and probe
 * for another N/3 of the addresses.
 *
 * Verify that in the case of simultaneous probes of the same address at most one
 * succeed, in the case of probing for a configured address it always fails, and
 * probing for a non-existent address always succeeds.
 *
 * Make sure to keep N fairly high as the protocol is probabilistic, and we also
 * want to verify that resizing the internal maps works correctly.
 */

#undef NDEBUG
#include <c-stdaux.h>
#include <stdlib.h>
#include "test.h"

#define TEST_ACD_N_PROBES (9)

typedef enum {
        TEST_ACD_STATE_UNKNOWN,
        TEST_ACD_STATE_USED,
        TEST_ACD_STATE_READY,
} TestAcdState;

static void test_veth(int ifindex1, uint8_t *mac1, size_t n_mac1,
                      int ifindex2, uint8_t *mac2, size_t n_mac2) {
        NAcdConfig *config;
        NAcd *acd1, *acd2;
        NAcdProbe *probes1[TEST_ACD_N_PROBES];
        NAcdProbe *probes2[TEST_ACD_N_PROBES];
        unsigned long state1, state2;
        size_t n_running = 0;
        int r;

        r = n_acd_config_new(&config);
        c_assert(!r);

        n_acd_config_set_transport(config, N_ACD_TRANSPORT_ETHERNET);

        n_acd_config_set_ifindex(config, ifindex1);
        n_acd_config_set_mac(config, mac1, n_mac1);
        r = n_acd_new(&acd1, config);
        c_assert(!r);

        n_acd_config_set_ifindex(config, ifindex2);
        n_acd_config_set_mac(config, mac2, n_mac2);
        r = n_acd_new(&acd2, config);
        c_assert(!r);

        n_acd_config_free(config);

        {
                NAcdProbeConfig *probe_config;

                r = n_acd_probe_config_new(&probe_config);
                c_assert(!r);
                n_acd_probe_config_set_timeout(probe_config, 1024);

                c_assert(TEST_ACD_N_PROBES <= 10 << 24);

                for (size_t i = 0; i < TEST_ACD_N_PROBES; ++i) {
                        struct in_addr ip = { htobe32((10 << 24) | i) };

                        n_acd_probe_config_set_ip(probe_config, ip);

                        switch (i % 3) {
                        case 0:
                                /*
                                 * Probe on one side, and leave the address
                                 * unset on the other. The probe must succeed.
                                 */
                                break;
                        case 1:
                                /*
                                 * Preconfigure the address on one side, and
                                 * probe on the other. The probe must fail.
                                 */
                                test_add_child_ip(&ip);
                                break;
                        case 2:
                                /*
                                 * Probe both sides for the same address, at
                                 * most one may succeed.
                                 */

                                r = n_acd_probe(acd2, &probes2[i], probe_config);
                                c_assert(!r);

                                ++n_running;
                                break;
                        default:
                                c_assert(0);
                                abort();
                                break;
                        }

                        r = n_acd_probe(acd1, &probes1[i], probe_config);
                        c_assert(!r);

                        ++n_running;
                }

                n_acd_probe_config_free(probe_config);

                while (n_running > 0) {
                        NAcdEvent *event;
                        struct pollfd pfds[2] = {
                                { .events = POLLIN },
                                { .events = POLLIN },
                        };

                        n_acd_get_fd(acd1, &pfds[0].fd);
                        n_acd_get_fd(acd2, &pfds[1].fd);

                        r = poll(pfds, 2, -1);
                        c_assert(r >= 0);

                        if (pfds[0].revents & POLLIN) {
                                r = n_acd_dispatch(acd1);
                                c_assert(!r || r == N_ACD_E_PREEMPTED);

                                for (;;) {
                                        r = n_acd_pop_event(acd1, &event);
                                        c_assert(!r);
                                        if (event) {
                                                switch (event->event) {
                                                case N_ACD_EVENT_READY:
                                                        n_acd_probe_get_userdata(event->ready.probe, (void**)&state1);
                                                        c_assert(state1 == TEST_ACD_STATE_UNKNOWN);
                                                        state1 = TEST_ACD_STATE_READY;
                                                        n_acd_probe_set_userdata(event->ready.probe, (void*)state1);

                                                        break;
                                                case N_ACD_EVENT_USED:
                                                        n_acd_probe_get_userdata(event->used.probe, (void**)&state1);
                                                        c_assert(state1 == TEST_ACD_STATE_UNKNOWN);
                                                        state1 = TEST_ACD_STATE_USED;
                                                        n_acd_probe_set_userdata(event->used.probe, (void*)state1);

                                                        break;
                                                default:
                                                        c_assert(0);
                                                }

                                                --n_running;
                                        } else {
                                                break;
                                        }
                                }
                        }

                        if (pfds[1].revents & POLLIN) {
                                r = n_acd_dispatch(acd2);
                                c_assert(!r || r == N_ACD_E_PREEMPTED);

                                for (;;) {
                                        r = n_acd_pop_event(acd2, &event);
                                        c_assert(!r);
                                        if (event) {
                                                switch (event->event) {
                                                case N_ACD_EVENT_READY:
                                                        n_acd_probe_get_userdata(event->ready.probe, (void**)&state2);
                                                        c_assert(state2 == TEST_ACD_STATE_UNKNOWN);
                                                        state2 = TEST_ACD_STATE_READY;
                                                        n_acd_probe_set_userdata(event->ready.probe, (void*)state2);

                                                        break;
                                                case N_ACD_EVENT_USED:
                                                        n_acd_probe_get_userdata(event->used.probe, (void**)&state2);
                                                        c_assert(state2 == TEST_ACD_STATE_UNKNOWN);
                                                        state2 = TEST_ACD_STATE_USED;
                                                        n_acd_probe_set_userdata(event->used.probe, (void*)state2);

                                                        break;
                                                default:
                                                        c_assert(0);
                                                }

                                                --n_running;
                                        } else {
                                                break;
                                        }
                                }
                        }
                }

                for (size_t i = 0; i < TEST_ACD_N_PROBES; ++i) {
                        struct in_addr ip = { htobe32((10 << 24) | i) };

                        switch (i % 3) {
                        case 0:
                                n_acd_probe_get_userdata(probes1[i], (void **)&state1);
                                c_assert(state1 == TEST_ACD_STATE_READY);

                                break;
                        case 1:
                                test_del_child_ip(&ip);

                                n_acd_probe_get_userdata(probes1[i], (void **)&state1);
                                c_assert(state1 == TEST_ACD_STATE_USED);

                                break;
                        case 2:
                                n_acd_probe_get_userdata(probes1[i], (void **)&state1);
                                n_acd_probe_get_userdata(probes2[i], (void **)&state2);
                                c_assert(state1 != TEST_ACD_STATE_UNKNOWN);
                                c_assert(state2 != TEST_ACD_STATE_UNKNOWN);
                                c_assert(state1 == TEST_ACD_STATE_USED || state2 == TEST_ACD_STATE_USED);
                                n_acd_probe_free(probes2[i]);

                                break;
                        }
                        n_acd_probe_free(probes1[i]);
                }
        }

        n_acd_unref(acd2);
        n_acd_unref(acd1);
}

int main(int argc, char **argv) {
        struct ether_addr mac1, mac2;
        int ifindex1, ifindex2;

        test_setup();

        test_veth_new(&ifindex1, &mac1, &ifindex2, &mac2);
        for (unsigned int i = 0; i < 8; ++i) {
                test_veth(ifindex1, mac1.ether_addr_octet, sizeof(mac1.ether_addr_octet),
                          ifindex2, mac2.ether_addr_octet, sizeof(mac2.ether_addr_octet));
        }

        return 0;
}
