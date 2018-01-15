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

#include "nm-default.h"

#include "nm-netlink.h"

/*****************************************************************************
 *  Reimplementations/copied from libnl3/genl
 *****************************************************************************/

void *
genlmsg_put (struct nl_msg *msg, uint32_t port, uint32_t seq, int family,
             int hdrlen, int flags, uint8_t cmd, uint8_t version)
{
	struct nlmsghdr *nlh;
	struct genlmsghdr hdr = {
		.cmd = cmd,
		.version = version,
	};

	nlh = nlmsg_put (msg, port, seq, family, GENL_HDRLEN + hdrlen, flags);
	if (nlh == NULL)
		return NULL;

	memcpy (nlmsg_data (nlh), &hdr, sizeof (hdr));

	return (char *) nlmsg_data (nlh) + GENL_HDRLEN;
}

void *
genlmsg_data (const struct genlmsghdr *gnlh)
{
	return ((unsigned char *) gnlh + GENL_HDRLEN);
}

void *
genlmsg_user_hdr (const struct genlmsghdr *gnlh)
{
	return genlmsg_data (gnlh);
}

struct genlmsghdr *
genlmsg_hdr (struct nlmsghdr *nlh)
{
	return nlmsg_data (nlh);
}

void *
genlmsg_user_data (const struct genlmsghdr *gnlh, const int hdrlen)
{
	return (char *) genlmsg_user_hdr (gnlh) + NLMSG_ALIGN (hdrlen);
}

struct nlattr *
genlmsg_attrdata (const struct genlmsghdr *gnlh, int hdrlen)
{
	return genlmsg_user_data (gnlh, hdrlen);
}

int
genlmsg_len (const struct genlmsghdr *gnlh)
{
	const struct nlmsghdr *nlh;

	nlh = (const struct nlmsghdr *) ((const unsigned char *) gnlh - NLMSG_HDRLEN);
	return (nlh->nlmsg_len - GENL_HDRLEN - NLMSG_HDRLEN);
}

int
genlmsg_attrlen (const struct genlmsghdr *gnlh, int hdrlen)
{
	return genlmsg_len (gnlh) - NLMSG_ALIGN (hdrlen);
}

int
genlmsg_valid_hdr (struct nlmsghdr *nlh, int hdrlen)
{
	struct genlmsghdr *ghdr;

	if (!nlmsg_valid_hdr (nlh, GENL_HDRLEN))
		return 0;

	ghdr = nlmsg_data (nlh);
	if (genlmsg_len (ghdr) < NLMSG_ALIGN (hdrlen))
		return 0;

	return 1;
}

int
genlmsg_parse (struct nlmsghdr *nlh, int hdrlen, struct nlattr *tb[],
               int maxtype, const struct nla_policy *policy)
{
	struct genlmsghdr *ghdr;

	if (!genlmsg_valid_hdr (nlh, hdrlen))
		return -NLE_MSG_TOOSHORT;

	ghdr = nlmsg_data (nlh);
	return nla_parse (tb, maxtype, genlmsg_attrdata (ghdr, hdrlen),
	                  genlmsg_attrlen (ghdr, hdrlen), policy);
}

/*****************************************************************************/
