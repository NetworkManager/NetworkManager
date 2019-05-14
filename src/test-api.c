/*
 * API Visibility Tests
 * This verifies the visibility and availability of the exported API.
 */

#undef NDEBUG
#include <assert.h>
#include <stdlib.h>
#include "n-dhcp4.h"

static void test_api_constants(void) {
        assert(1 + N_DHCP4_CLIENT_START_DELAY_RFC2131);

        assert(1 + _N_DHCP4_E_SUCCESS);
        assert(1 + N_DHCP4_E_PREEMPTED);
        assert(1 + N_DHCP4_E_INTERNAL);
        assert(1 + N_DHCP4_E_INVALID_IFINDEX);
        assert(1 + N_DHCP4_E_INVALID_TRANSPORT);
        assert(1 + N_DHCP4_E_INVALID_ADDRESS);
        assert(1 + N_DHCP4_E_INVALID_CLIENT_ID);
        assert(1 + N_DHCP4_E_DUPLICATE_OPTION);
        assert(1 + N_DHCP4_E_UNSET);
        assert(1 + _N_DHCP4_E_N);

        assert(1 + N_DHCP4_TRANSPORT_ETHERNET);
        assert(1 + N_DHCP4_TRANSPORT_INFINIBAND);
        assert(1 + _N_DHCP4_TRANSPORT_N);

        assert(1 + N_DHCP4_CLIENT_EVENT_DOWN);
        assert(1 + N_DHCP4_CLIENT_EVENT_OFFER);
        assert(1 + N_DHCP4_CLIENT_EVENT_GRANTED);
        assert(1 + N_DHCP4_CLIENT_EVENT_RETRACTED);
        assert(1 + N_DHCP4_CLIENT_EVENT_EXTENDED);
        assert(1 + N_DHCP4_CLIENT_EVENT_EXPIRED);
        assert(1 + N_DHCP4_CLIENT_EVENT_CANCELLED);
        assert(1 + _N_DHCP4_CLIENT_EVENT_N);

        assert(1 + N_DHCP4_SERVER_EVENT_DOWN);
        assert(1 + N_DHCP4_SERVER_EVENT_DISCOVER);
        assert(1 + N_DHCP4_SERVER_EVENT_REQUEST);
        assert(1 + N_DHCP4_SERVER_EVENT_RENEW);
        assert(1 + N_DHCP4_SERVER_EVENT_DECLINE);
        assert(1 + N_DHCP4_SERVER_EVENT_RELEASE);
        assert(1 + _N_DHCP4_SERVER_EVENT_N);
}

static void test_api_types(void) {
        assert(sizeof(NDhcp4ClientConfig*) > 0);
        assert(sizeof(NDhcp4ClientProbeConfig*) > 0);
        assert(sizeof(NDhcp4Client*) > 0);
        assert(sizeof(NDhcp4ClientEvent) > 0);
        assert(sizeof(NDhcp4ClientProbe*) > 0);
        assert(sizeof(NDhcp4ClientLease*) > 0);
        assert(sizeof(NDhcp4Server*) > 0);
        assert(sizeof(NDhcp4ServerConfig*) > 0);
        assert(sizeof(NDhcp4ServerEvent) > 0);
        assert(sizeof(NDhcp4ServerIp*) > 0);
        assert(sizeof(NDhcp4ServerLease*) > 0);
}

static void test_api_functions(void) {
        void *fns[] = {
                (void *)n_dhcp4_client_config_new,
                (void *)n_dhcp4_client_config_free,
                (void *)n_dhcp4_client_config_freep,
                (void *)n_dhcp4_client_config_freev,
                (void *)n_dhcp4_client_config_set_ifindex,
                (void *)n_dhcp4_client_config_set_transport,
                (void *)n_dhcp4_client_config_set_request_broadcast,
                (void *)n_dhcp4_client_config_set_mac,
                (void *)n_dhcp4_client_config_set_broadcast_mac,
                (void *)n_dhcp4_client_config_set_client_id,

                (void *)n_dhcp4_client_probe_config_new,
                (void *)n_dhcp4_client_probe_config_free,
                (void *)n_dhcp4_client_probe_config_freep,
                (void *)n_dhcp4_client_probe_config_freev,
                (void *)n_dhcp4_client_probe_config_set_inform_only,
                (void *)n_dhcp4_client_probe_config_set_init_reboot,
                (void *)n_dhcp4_client_probe_config_set_requested_ip,
                (void *)n_dhcp4_client_probe_config_set_start_delay,
                (void *)n_dhcp4_client_probe_config_request_option,
                (void *)n_dhcp4_client_probe_config_append_option,

                (void *)n_dhcp4_client_new,
                (void *)n_dhcp4_client_ref,
                (void *)n_dhcp4_client_unref,
                (void *)n_dhcp4_client_unrefp,
                (void *)n_dhcp4_client_unrefv,
                (void *)n_dhcp4_client_get_fd,
                (void *)n_dhcp4_client_dispatch,
                (void *)n_dhcp4_client_pop_event,
                (void *)n_dhcp4_client_update_mtu,
                (void *)n_dhcp4_client_probe,

                (void *)n_dhcp4_client_probe_free,
                (void *)n_dhcp4_client_probe_freep,
                (void *)n_dhcp4_client_probe_freev,
                (void *)n_dhcp4_client_probe_get_userdata,
                (void *)n_dhcp4_client_probe_set_userdata,

                (void *)n_dhcp4_client_lease_ref,
                (void *)n_dhcp4_client_lease_unref,
                (void *)n_dhcp4_client_lease_unrefp,
                (void *)n_dhcp4_client_lease_unrefv,
                (void *)n_dhcp4_client_lease_get_yiaddr,
                (void *)n_dhcp4_client_lease_get_lifetime,
                (void *)n_dhcp4_client_lease_query,
                (void *)n_dhcp4_client_lease_select,
                (void *)n_dhcp4_client_lease_accept,
                (void *)n_dhcp4_client_lease_decline,

                (void *)n_dhcp4_server_config_new,
                (void *)n_dhcp4_server_config_free,
                (void *)n_dhcp4_server_config_freep,
                (void *)n_dhcp4_server_config_freev,
                (void *)n_dhcp4_server_config_set_ifindex,

                (void *)n_dhcp4_server_new,
                (void *)n_dhcp4_server_ref,
                (void *)n_dhcp4_server_unref,
                (void *)n_dhcp4_server_unrefp,
                (void *)n_dhcp4_server_unrefv,
                (void *)n_dhcp4_server_get_fd,
                (void *)n_dhcp4_server_dispatch,
                (void *)n_dhcp4_server_pop_event,
                (void *)n_dhcp4_server_add_ip,

                (void *)n_dhcp4_server_ip_free,
                (void *)n_dhcp4_server_ip_freep,
                (void *)n_dhcp4_server_ip_freev,

                (void *)n_dhcp4_server_lease_ref,
                (void *)n_dhcp4_server_lease_unref,
                (void *)n_dhcp4_server_lease_unrefp,
                (void *)n_dhcp4_server_lease_unrefv,
                (void *)n_dhcp4_server_lease_query,
                (void *)n_dhcp4_server_lease_append,
                (void *)n_dhcp4_server_lease_offer,
                (void *)n_dhcp4_server_lease_ack,
                (void *)n_dhcp4_server_lease_nack,
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
