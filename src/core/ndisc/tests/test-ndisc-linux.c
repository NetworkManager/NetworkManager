/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include <syslog.h>

#include "ndisc/nm-ndisc.h"
#include "ndisc/nm-lndp-ndisc.h"

#include "libnm-platform/nm-linux-platform.h"
#include "nm-netns.h"
#include "nm-l3cfg.h"

#include "nm-test-utils-core.h"

NMTST_DEFINE();

int
main(int argc, char **argv)
{
    gs_unref_object NML3Cfg *l3cfg = NULL;
    NMNDiscConfig            config;
    GMainLoop               *loop;
    NMNDisc                 *ndisc;
    int                      ifindex = 1;
    const char              *ifname;
    NMUtilsIPv6IfaceId       iid   = {};
    GError                  *error = NULL;
    int                      max_addresses;
    int                      router_solicitations;
    int                      router_solicitation_interval;
    guint32                  ra_timeout;

    nmtst_init_with_logging(&argc, &argv, NULL, "DEFAULT");

    if (getuid() != 0) {
        g_print("Missing permission: must run as root\n");
        return EXIT_FAILURE;
    }

    loop = g_main_loop_new(NULL, FALSE);

    nm_linux_platform_setup();

    if (argv[1]) {
        ifname  = argv[1];
        ifindex = nm_platform_link_get_ifindex(NM_PLATFORM_GET, ifname);
    } else {
        g_print("Missing command line argument \"interface-name\"\n");
        return EXIT_FAILURE;
    }

    nm_ndisc_get_sysctl(NM_PLATFORM_GET,
                        ifname,
                        &max_addresses,
                        &router_solicitations,
                        &router_solicitation_interval,
                        &ra_timeout);

    l3cfg = nm_netns_l3cfg_acquire(NM_NETNS_GET, ifindex);

    config = (NMNDiscConfig){
        .l3cfg                        = l3cfg,
        .ifname                       = nm_l3cfg_get_ifname(l3cfg, TRUE),
        .stable_type                  = NM_UTILS_STABLE_TYPE_UUID,
        .network_id                   = "8ce666e8-d34d-4fb1-b858-f15a7al28086",
        .addr_gen_mode                = NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_EUI64,
        .node_type                    = NM_NDISC_NODE_TYPE_HOST,
        .max_addresses                = max_addresses,
        .router_solicitations         = router_solicitations,
        .router_solicitation_interval = router_solicitation_interval,
        .ra_timeout                   = ra_timeout,
        .ip6_privacy                  = NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR,
    };

    ndisc = nm_lndp_ndisc_new(&config);
    if (!ndisc) {
        g_print("Failed to create NMNDisc instance: %s\n", error->message);
        g_error_free(error);
        return EXIT_FAILURE;
    }

    iid.id_u8[7] = 1;
    nm_ndisc_set_iid(ndisc, iid, FALSE);
    nm_ndisc_start(ndisc);
    g_main_loop_run(loop);

    g_clear_object(&ndisc);

    return EXIT_SUCCESS;
}
