/*
 * Test with unused address twice in parallel
 * This runs the ACD engine with an unused address on a veth pair, but it runs
 * it on both ends. We expect the PROBE to fail on at least one of the devices.
 */

#include <stdlib.h>
#include "test.h"

static void test_unused(int ifindex1, uint8_t *mac1, size_t n_mac1, int ifindex2, uint8_t *mac2, size_t n_mac2) {
        NAcdConfig config1 = {
                .ifindex = ifindex1,
                .transport = N_ACD_TRANSPORT_ETHERNET,
                .mac = mac1,
                .n_mac = n_mac1,
                .ip = { htobe32((192 << 24) | (168 << 16) | (1 << 0)) },
                .timeout_msec = 100,
        };
        NAcdConfig config2 = {
                .ifindex = ifindex2,
                .transport = N_ACD_TRANSPORT_ETHERNET,
                .mac = mac2,
                .n_mac = n_mac2,
                .ip = { htobe32((192 << 24) | (168 << 16) | (1 << 0)) },
                .timeout_msec = 100,
        };
        struct pollfd pfds[2];
        NAcd *acd1, *acd2;
        int r, fd1, fd2, state1, state2;

        r = n_acd_new(&acd1);
        assert(!r);
        r = n_acd_new(&acd2);
        assert(!r);

        n_acd_get_fd(acd1, &fd1);
        n_acd_get_fd(acd2, &fd2);

        r = n_acd_start(acd1, &config1);
        assert(!r);
        r = n_acd_start(acd2, &config2);
        assert(!r);

        for (state1 = state2 = -1; state1 == -1 || state2 == -1; ) {
                NAcdEvent *event;
                pfds[0] = (struct pollfd){ .fd = fd1, .events = (state1 == -1) ? POLLIN : 0 };
                pfds[1] = (struct pollfd){ .fd = fd2, .events = (state2 == -1) ? POLLIN : 0 };

                r = poll(pfds, sizeof(pfds) / sizeof(*pfds), -1);
                assert(r >= 0);

                if (state1 == -1) {
                        r = n_acd_dispatch(acd1);
                        assert(!r);

                        r = n_acd_pop_event(acd1, &event);
                        if (!r) {
                                assert(event->event == N_ACD_EVENT_READY || event->event == N_ACD_EVENT_USED);
                                state1 = !!(event->event == N_ACD_EVENT_READY);
                        } else {
                                assert(r == N_ACD_E_DONE);
                        }
                }

                if (state2 == -1) {
                        r = n_acd_dispatch(acd2);
                        assert(!r);

                        r = n_acd_pop_event(acd2, &event);
                        if (!r) {
                                assert(event->event == N_ACD_EVENT_READY || event->event == N_ACD_EVENT_USED);
                                state2 = !!(event->event == N_ACD_EVENT_READY);
                        } else {
                                assert(r == N_ACD_E_DONE);
                        }
                }
        }

        n_acd_free(acd1);
        n_acd_free(acd2);

        assert(!state1 || !state2);
}

int main(int argc, char **argv) {
        struct ether_addr mac1, mac2;
        int r, ifindex1, ifindex2;

        r = test_setup();
        if (r)
                return r;

        test_veth_new(&ifindex1, &mac1, &ifindex2, &mac2);
        test_unused(ifindex1, mac1.ether_addr_octet, sizeof(mac2.ether_addr_octet), ifindex2, mac2.ether_addr_octet, sizeof(mac2.ether_addr_octet));

        return 0;
}
