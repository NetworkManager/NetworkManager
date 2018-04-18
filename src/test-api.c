/*
 * Tests for n-acd API
 * This verifies the visibility and availability of the public API of the
 * n-acd library.
 */

#include <stdlib.h>
#include "test.h"

static void test_api_constants(void) {
        assert(N_ACD_DEFEND_NEVER != _N_ACD_DEFEND_N);
        assert(N_ACD_DEFEND_ONCE != _N_ACD_DEFEND_N);
        assert(N_ACD_DEFEND_ALWAYS != _N_ACD_DEFEND_N);

        assert(N_ACD_EVENT_READY != _N_ACD_EVENT_N);
        assert(N_ACD_EVENT_USED != _N_ACD_EVENT_N);
        assert(N_ACD_EVENT_DEFENDED != _N_ACD_EVENT_N);
        assert(N_ACD_EVENT_CONFLICT != _N_ACD_EVENT_N);
        assert(N_ACD_EVENT_DOWN != _N_ACD_EVENT_N);
}

static void test_api_management(void) {
        NAcd *acd = NULL;
        int r;

        /* new/free/freep */

        n_acd_freep(&acd);

        r = n_acd_new(&acd);
        assert(!r);

        n_acd_free(acd);
}

static void test_api_runtime(void) {
        NAcdConfig config = {
                .ifindex = 1,
                .transport = N_ACD_TRANSPORT_ETHERNET,
                .mac = (uint8_t[]){ 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54 },
                .n_mac = ETH_ALEN,
                .ip = { htobe32((127 << 24) | (1 << 0)) },
                .timeout_msec = 100,
        };
        NAcd *acd;
        int r;

        /* get_fd/dispatch/pop_event/start/stop/announce */

        r = n_acd_new(&acd);
        assert(!r);

        n_acd_get_fd(acd, &r);
        assert(r >= 0);
        r = n_acd_dispatch(acd);
        assert(!r);
        r = n_acd_pop_event(acd, NULL);
        assert(r == N_ACD_E_STOPPED);
        r = n_acd_start(acd, &config);
        assert(!r);
        r = n_acd_start(acd, &config);
        assert(r == N_ACD_E_BUSY);
        r = n_acd_pop_event(acd, NULL);
        assert(r == N_ACD_E_DONE);
        r = n_acd_stop(acd);
        assert(!r);
        r = n_acd_announce(acd, N_ACD_DEFEND_NEVER);
        assert(r == N_ACD_E_BUSY);

        n_acd_free(acd);
}

int main(int argc, char **argv) {
        int r;

        r = test_setup();
        if (r)
                return r;

        test_api_constants();
        test_api_management();
        test_api_runtime();
        return 0;
}
