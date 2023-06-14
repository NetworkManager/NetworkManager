/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2008 Novell, Inc.
 * Copyright (C) 2008 - 2016 Red Hat, Inc.
 */

#ifndef __NM_PPP_STATUS_H__
#define __NM_PPP_STATUS_H__

typedef enum {

    /* The numeric values correspond to the PHASE_{DEAD,} defines from <pppd/pppd.h>. */
    NM_PPP_STATUS_DEAD         = 0,
    NM_PPP_STATUS_INITIALIZE   = 1,
    NM_PPP_STATUS_SERIALCONN   = 2,
    NM_PPP_STATUS_DORMANT      = 3,
    NM_PPP_STATUS_ESTABLISH    = 4,
    NM_PPP_STATUS_AUTHENTICATE = 5,
    NM_PPP_STATUS_CALLBACK     = 6,
    NM_PPP_STATUS_NETWORK      = 7,
    NM_PPP_STATUS_RUNNING      = 8,
    NM_PPP_STATUS_TERMINATE    = 9,
    NM_PPP_STATUS_DISCONNECT   = 10,
    NM_PPP_STATUS_HOLDOFF      = 11,
    NM_PPP_STATUS_MASTER       = 12,

    /* these states are internal and not announced by the pppd plugin. */
    NM_PPP_STATUS_INTERN_UNKNOWN = 20,
    NM_PPP_STATUS_INTERN_DEAD,
} NMPPPStatus;

/*****************************************************************************/

/* The plugin name "(rp-)pppoe.so" depends on the ppp version. */

#define NM_PPPOE_PLUGIN_NAME (NM_PPP_VERSION_2_5_OR_NEWER ? "pppoe.so" : "rp-pppoe.so")

#endif /* __NM_PPP_STATUS_H__ */
