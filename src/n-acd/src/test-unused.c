/*
 * Test with unused address
 * Run the ACD engine with an address that is not used by anyone else on the
 * link. This should just pass through, with a short, random timeout.
 */

#undef NDEBUG
#include <c-stdaux.h>
#include <stdlib.h>
#include "test.h"

static void test_unused(int ifindex, const uint8_t *mac, size_t n_mac) {
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

        r = n_acd_new(&acd);
        c_assert(!r);

        n_acd_get_fd(acd, &fd);
        r = n_acd_start(acd, &config);
        c_assert(!r);

        for (;;) {
                NAcdEvent *event;
                pfds = (struct pollfd){ .fd = fd, .events = POLLIN };
                r = poll(&pfds, 1, -1);
                c_assert(r >= 0);

                r = n_acd_dispatch(acd);
                c_assert(!r);

                r = n_acd_pop_event(acd, &event);
                if (!r) {
                        c_assert(event->event == N_ACD_EVENT_READY);
                        break;
                } else {
                        c_assert(r == N_ACD_E_DONE);
                }
        }

        n_acd_free(acd);
}

int main(int argc, char **argv) {
        struct ether_addr mac;
        int ifindex;

        test_setup();

        test_veth_new(&ifindex, &mac, NULL, NULL);
        test_unused(ifindex, mac.ether_addr_octet, sizeof(mac.ether_addr_octet));

        return 0;
}
