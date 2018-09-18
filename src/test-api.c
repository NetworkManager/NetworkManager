/*
 * Tests for n-acd API
 * This verifies the visibility and availability of the public API of the
 * n-acd library.
 */

#include <stdlib.h>
#include "test.h"

static void test_api(void) {
        NAcdConfig *config = NULL;
        NAcd *acd = NULL;
        int r;

        assert(N_ACD_E_PREEMPTED);
        assert(N_ACD_E_INVALID_ARGUMENT);

        assert(N_ACD_TRANSPORT_ETHERNET != _N_ACD_TRANSPORT_N);

        assert(N_ACD_EVENT_READY != _N_ACD_EVENT_N);
        assert(N_ACD_EVENT_USED != _N_ACD_EVENT_N);
        assert(N_ACD_EVENT_DEFENDED != _N_ACD_EVENT_N);
        assert(N_ACD_EVENT_CONFLICT != _N_ACD_EVENT_N);
        assert(N_ACD_EVENT_DOWN != _N_ACD_EVENT_N);

        assert(N_ACD_DEFEND_NEVER != _N_ACD_DEFEND_N);
        assert(N_ACD_DEFEND_ONCE != _N_ACD_DEFEND_N);
        assert(N_ACD_DEFEND_ALWAYS != _N_ACD_DEFEND_N);

        n_acd_config_freep(&config);

        r = n_acd_config_new(&config);
        assert(!r);

        n_acd_config_set_ifindex(config, 1);
        n_acd_config_set_transport(config, N_ACD_TRANSPORT_ETHERNET);
        n_acd_config_set_mac(config, (uint8_t[6]){ }, 6);

        {
                NAcdEvent *event;
                int fd;

                n_acd_unrefp(&acd);
                n_acd_ref(NULL);

                r = n_acd_new(&acd, config);
                assert(!r);

                n_acd_get_fd(acd, &fd);
                n_acd_dispatch(acd);
                n_acd_pop_event(acd, &event);

                {
                        NAcdProbeConfig *c = NULL;

                        n_acd_probe_config_freep(&c);

                        r = n_acd_probe_config_new(&c);
                        assert(!r);

                        n_acd_probe_config_set_ip(c, (struct in_addr){ 1 });
                        n_acd_probe_config_set_timeout(c, N_ACD_TIMEOUT_RFC5227);

                        {
                                NAcdProbe *probe = NULL;
                                void *userdata;

                                r = n_acd_probe(acd, &probe, c);
                                assert(!r);

                                n_acd_probe_get_userdata(probe, &userdata);
                                assert(userdata == NULL);
                                n_acd_probe_set_userdata(probe, acd);
                                n_acd_probe_get_userdata(probe, &userdata);
                                assert(userdata == acd);

                                r = n_acd_probe_announce(probe, N_ACD_DEFEND_ONCE);
                                assert(!r);

                                n_acd_probe_free(probe);
                                n_acd_probe_freev(NULL);
                        }

                        n_acd_probe_config_free(c);
                        n_acd_probe_config_freev(NULL);
                }

                n_acd_unref(acd);
                n_acd_unrefv(NULL);
        }

        n_acd_config_free(config);
        n_acd_config_freev(NULL);
}

int main(int argc, char **argv) {
        int r;

        r = test_setup();
        if (r)
                return r;

        test_api();
        return 0;
}
