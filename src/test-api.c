/*
 * Tests for n-acd API
 * This verifies the visibility and availability of the public API.
 */

#undef NDEBUG
#include <assert.h>
#include <stdlib.h>
#include "n-acd.h"

static void test_api_constants(void) {
        assert(1 + N_ACD_TIMEOUT_RFC5227);

        assert(1 + _N_ACD_E_SUCCESS);
        assert(1 + N_ACD_E_PREEMPTED);
        assert(1 + N_ACD_E_INVALID_ARGUMENT);
        assert(1 + _N_ACD_E_N);

        assert(1 + N_ACD_TRANSPORT_ETHERNET);
        assert(1 + _N_ACD_TRANSPORT_N);

        assert(1 + N_ACD_EVENT_READY);
        assert(1 + N_ACD_EVENT_USED);
        assert(1 + N_ACD_EVENT_DEFENDED);
        assert(1 + N_ACD_EVENT_CONFLICT);
        assert(1 + N_ACD_EVENT_DOWN);
        assert(1 + _N_ACD_EVENT_N);

        assert(1 + N_ACD_DEFEND_NEVER);
        assert(1 + N_ACD_DEFEND_ONCE);
        assert(1 + N_ACD_DEFEND_ALWAYS);
        assert(1 + _N_ACD_DEFEND_N);
}

static void test_api_types(void) {
        assert(sizeof(NAcdEvent*));
        assert(sizeof(NAcdConfig*));
        assert(sizeof(NAcdProbeConfig*));
        assert(sizeof(NAcd*));
        assert(sizeof(NAcdProbe*));
}

static void test_api_functions(void) {
        void *fns[] = {
                (void *)n_acd_config_new,
                (void *)n_acd_config_free,
                (void *)n_acd_config_set_ifindex,
                (void *)n_acd_config_set_transport,
                (void *)n_acd_config_set_mac,
                (void *)n_acd_probe_config_new,
                (void *)n_acd_probe_config_free,
                (void *)n_acd_probe_config_set_ip,
                (void *)n_acd_probe_config_set_timeout,

                (void *)n_acd_new,
                (void *)n_acd_ref,
                (void *)n_acd_unref,
                (void *)n_acd_get_fd,
                (void *)n_acd_dispatch,
                (void *)n_acd_pop_event,
                (void *)n_acd_probe,

                (void *)n_acd_probe_free,
                (void *)n_acd_probe_set_userdata,
                (void *)n_acd_probe_get_userdata,
                (void *)n_acd_probe_announce,

                (void *)n_acd_config_freep,
                (void *)n_acd_config_freev,
                (void *)n_acd_probe_config_freep,
                (void *)n_acd_probe_config_freev,
                (void *)n_acd_unrefp,
                (void *)n_acd_unrefv,
                (void *)n_acd_probe_freep,
                (void *)n_acd_probe_freev,
        };
        size_t i;

        for (i = 0; i < sizeof(fns) / sizeof(*fns); ++i)
                assert(!!fns[i]);
}

int main(int argc, char **argv) {
        test_api_constants();
        test_api_types();
        test_api_functions();
        return 0;
}
