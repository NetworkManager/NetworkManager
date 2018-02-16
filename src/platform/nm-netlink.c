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

/*****************************************************************************/

const char *
nl_nlmsghdr_to_str (const struct nlmsghdr *hdr, char *buf, gsize len)
{
	const char *b;
	const char *s;
	guint flags, flags_before;
	const char *prefix;

	if (!nm_utils_to_string_buffer_init_null (hdr, &buf, &len))
		return buf;

	b = buf;

	switch (hdr->nlmsg_type) {
	case RTM_NEWLINK:    s = "RTM_NEWLINK";  break;
	case RTM_DELLINK:    s = "RTM_DELLINK";  break;
	case RTM_NEWADDR:    s = "RTM_NEWADDR";  break;
	case RTM_DELADDR:    s = "RTM_DELADDR";  break;
	case RTM_NEWROUTE:   s = "RTM_NEWROUTE"; break;
	case RTM_DELROUTE:   s = "RTM_DELROUTE"; break;
	case RTM_NEWQDISC:   s = "RTM_NEWQDISC"; break;
	case RTM_DELQDISC:   s = "RTM_DELQDISC"; break;
	case RTM_NEWTFILTER: s = "RTM_NEWTFILTER"; break;
	case RTM_DELTFILTER: s = "RTM_DELTFILTER"; break;
	case NLMSG_NOOP:     s = "NLMSG_NOOP"; break;
	case NLMSG_ERROR:    s = "NLMSG_ERROR"; break;
	case NLMSG_DONE:     s = "NLMSG_DONE"; break;
	case NLMSG_OVERRUN:  s = "NLMSG_OVERRUN"; break;
	default:             s = NULL;       break;
	}

	if (s)
		nm_utils_strbuf_append_str (&buf, &len, s);
	else
		nm_utils_strbuf_append (&buf, &len, "(%u)", (unsigned) hdr->nlmsg_type);

	flags = hdr->nlmsg_flags;

	if (!flags) {
		nm_utils_strbuf_append_str (&buf, &len, ", flags 0");
		goto flags_done;
	}

#define _F(f, n) \
	G_STMT_START { \
		if (NM_FLAGS_ALL (flags, f)) { \
			flags &= ~(f); \
			nm_utils_strbuf_append (&buf, &len, "%s%s", prefix, n); \
			if (!flags) \
				goto flags_done; \
			prefix = ","; \
		} \
	} G_STMT_END

	prefix = ", flags ";
	flags_before = flags;
	_F (NLM_F_REQUEST, "request");
	_F (NLM_F_MULTI, "multi");
	_F (NLM_F_ACK, "ack");
	_F (NLM_F_ECHO, "echo");
	_F (NLM_F_DUMP_INTR, "dump_intr");
	_F (0x20 /*NLM_F_DUMP_FILTERED*/, "dump_filtered");

	if (flags_before != flags)
		prefix = ";";

	switch (hdr->nlmsg_type) {
	case RTM_NEWLINK:
	case RTM_NEWADDR:
	case RTM_NEWROUTE:
	case RTM_NEWQDISC:
	case RTM_NEWTFILTER:
		_F (NLM_F_REPLACE, "replace");
		_F (NLM_F_EXCL, "excl");
		_F (NLM_F_CREATE, "create");
		_F (NLM_F_APPEND, "append");
		break;
	case RTM_GETLINK:
	case RTM_GETADDR:
	case RTM_GETROUTE:
	case RTM_DELQDISC:
	case RTM_DELTFILTER:
		_F (NLM_F_DUMP, "dump");
		_F (NLM_F_ROOT, "root");
		_F (NLM_F_MATCH, "match");
		_F (NLM_F_ATOMIC, "atomic");
		break;
	}

#undef _F

	if (flags_before != flags)
		prefix = ";";
	nm_utils_strbuf_append (&buf, &len, "%s0x%04x", prefix, flags);

flags_done:

	nm_utils_strbuf_append (&buf, &len, ", seq %u", (unsigned) hdr->nlmsg_seq);

	return b;
}

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
