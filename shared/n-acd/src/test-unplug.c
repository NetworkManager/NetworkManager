/*
 * Unplug device during test run
 * Run the ACD engine with an address that is not used by anyone else on the
 * link, but DOWN or UNPLUG the device while running.
 */

#include <stdlib.h>
#include "test.h"

static void test_unplug_down(int ifindex, uint8_t *mac, size_t n_mac, unsigned int run) {
        NAcdConfig config = {
                .ifindex = ifindex,
                .transport = N_ACD_TRANSPORT_ETHERNET,
                .mac = mac,
                .n_mac = n_mac,
                .ip = { htobe32((192 << 24) | (168 << 16) | (1 << 0)) },
                .timeout_msec = 100,
        };
        struct pollfd pfds;
        NAcd *acd;
        int r, fd;

        if (!run--)
                test_veth_cmd(ifindex, "down");

        r = n_acd_new(&acd);
        assert(!r);

        if (!run--)
                test_veth_cmd(ifindex, "down");

        n_acd_get_fd(acd, &fd);
        r = n_acd_start(acd, &config);
        assert(!r);

        if (!run--)
                test_veth_cmd(ifindex, "down");

        for (;;) {
                NAcdEvent *event;
                pfds = (struct pollfd){ .fd = fd, .events = POLLIN };
                r = poll(&pfds, 1, -1);
                assert(r >= 0);

                if (!run--)
                        test_veth_cmd(ifindex, "down");

                r = n_acd_dispatch(acd);
                assert(!r);

                r = n_acd_pop_event(acd, &event);
                if (!r) {
                        if (event->event == N_ACD_EVENT_DOWN) {
                                break;
                        } else {
                                assert(event->event == N_ACD_EVENT_READY);
                                test_veth_cmd(ifindex, "down");
                        }
                } else {
                        assert(r == N_ACD_E_DONE);
                }
        }

        n_acd_free(acd);
}

int main(int argc, char **argv) {
        struct ether_addr mac;
        unsigned int i;
        int r, ifindex;

        r = test_setup();
        if (r)
                return r;

        test_veth_new(&ifindex, &mac, NULL, NULL);

        for (i = 0; i < 5; ++i) {
                test_unplug_down(ifindex, mac.ether_addr_octet, sizeof(mac.ether_addr_octet), i);
                test_veth_cmd(ifindex, "up");
        }

        return 0;
}
