/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-platform.c - Handle runtime kernel networking configuration
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2018 Red Hat, Inc.
 */

#ifndef __NM_NETLINK_H__
#define __NM_NETLINK_H__

#include <netlink/msg.h>
#include <netlink/attr.h>

/*****************************************************************************
 * libnl3 compat code
 *****************************************************************************/

static inline int
_nl_nla_parse (struct nlattr *tb[], int maxtype, struct nlattr *head, int len,
               const struct nla_policy *policy)
{
	return nla_parse (tb, maxtype, head, len, (struct nla_policy *) policy);
}
#define nla_parse(...) _nl_nla_parse(__VA_ARGS__)

static inline int
_nl_nlmsg_parse (struct nlmsghdr *nlh, int hdrlen, struct nlattr *tb[],
                 int maxtype, const struct nla_policy *policy)
{
	return nlmsg_parse (nlh, hdrlen, tb, maxtype, (struct nla_policy *) policy);
}
#define nlmsg_parse(...) _nl_nlmsg_parse(__VA_ARGS__)

static inline int
_nl_nla_parse_nested (struct nlattr *tb[], int maxtype, struct nlattr *nla,
                      const struct nla_policy *policy)
{
	return nla_parse_nested (tb, maxtype, nla, (struct nla_policy *) policy);
}
#define nla_parse_nested(...) _nl_nla_parse_nested(__VA_ARGS__)

/*****************************************************************************
 * helpers
 *****************************************************************************/

static inline void
_nm_auto_nl_msg_cleanup (struct nl_msg **ptr)
{
	nlmsg_free (*ptr);
}
#define nm_auto_nlmsg nm_auto(_nm_auto_nl_msg_cleanup)

/*****************************************************************************/

#endif /* __NM_NETLINK_H__ */
