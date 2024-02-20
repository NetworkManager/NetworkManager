/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2024 Red Hat, Inc.
 */

#ifndef __NMP_DEVLINK_H__
#define __NMP_DEVLINK_H__

#include "libnm-base/nm-base.h"
#include <linux/devlink.h>

struct nl_sock;
typedef struct _NMPlatform NMPlatform;
typedef struct _NMDevlink  NMDevlink;

typedef struct {
    _NMSriovEswitchMode       mode;
    _NMSriovEswitchInlineMode inline_mode;
    _NMSriovEswitchEncapMode  encap_mode;
} NMDevlinkEswitchParams;

NMDevlink *nm_devlink_new(NMPlatform *platform, struct nl_sock *genl_sock_sync, int ifindex);
gboolean
nm_devlink_get_dev_identifier(NMDevlink *self, char **out_bus, char **out_addr, GError **error);
gboolean
nm_devlink_get_eswitch_params(NMDevlink *self, NMDevlinkEswitchParams *out_params, GError **error);
gboolean
nm_devlink_set_eswitch_params(NMDevlink *self, NMDevlinkEswitchParams params, GError **error);

#endif /* __NMP_DEVLINK_H__ */