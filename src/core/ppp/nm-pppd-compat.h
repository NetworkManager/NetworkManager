/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2023 Eivind Næss, eivnaes@yahoo.com
 */

#ifndef __NM_PPPD_COMPAT_H__
#define __NM_PPPD_COMPAT_H__

#define NM_PPPD_COMPAT_MAXNAMELEN   256
#define NM_PPPD_COMPAT_MAXSECRETLEN 256

int nm_pppd_compat_get_ifunit(void);

const char *nm_pppd_compat_get_ifname(void);
void        nm_pppd_compat_set_ifname(const char *ifname);

const char *nm_pppd_compat_get_ipparam(void);

typedef struct {
    /* has information from "ipcp_options" */
    in_addr_t ouraddr;
    in_addr_t hisaddr;
    in_addr_t dnsaddr[2];
    in_addr_t winsaddr[2];
} NMPppdCompatIPCPOptions;

void nm_pppd_compat_get_ipcp_options(NMPppdCompatIPCPOptions *out_got,
                                     NMPppdCompatIPCPOptions *out_his);

typedef struct {
    /* has information from "ipv6cp_options" */
    guint64 ourid;
    guint64 hisid;
} NMPppdCompatIPV6CPOptions;

void nm_pppd_compat_get_ipv6cp_options(NMPppdCompatIPV6CPOptions *out_got,
                                       NMPppdCompatIPV6CPOptions *out_his);

void nm_pppd_compat_set_chap_passwd_hook(int (*hook)(char *user, char *password));

void nm_pppd_compat_set_chap_check_hook(int (*hook)(void));

void nm_pppd_compat_set_pap_passwd_hook(int (*hook)(char *user, char *passwd));

void nm_pppd_compat_set_pap_check_hook(int (*hook)(void));

typedef enum {
    NM_PPPD_COMPAT_NF_PID_CHANGE,
    NM_PPPD_COMPAT_NF_PHASE_CHANGE,
    NM_PPPD_COMPAT_NF_EXIT,
    NM_PPPD_COMPAT_NF_SIGNALED,
    NM_PPPD_COMPAT_NF_IP_UP,
    NM_PPPD_COMPAT_NF_IP_DOWN,
    NM_PPPD_COMPAT_NF_IPV6_UP,
    NM_PPPD_COMPAT_NF_IPV6_DOWN,
    NM_PPPD_COMPAT_NF_AUTH_UP,
    NM_PPPD_COMPAT_NF_LINK_DOWN,
    NM_PPPD_COMPAT_NF_FORK,
} NMPppdCompatNotifyT;

gboolean
nm_pppd_compat_add_notify(NMPppdCompatNotifyT type, void (*func)(void *ctx, int arg), void *ctx);

#endif /* #ifdef __NM_PPPD_COMPAT_H__ */
