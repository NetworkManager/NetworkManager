/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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

#include "nm-wpan-utils.h"

#include <linux/if.h>

#include "platform/linux/nl802154.h"
#include "platform/nm-netlink.h"
#include "platform/nm-platform-utils.h"

#define _NMLOG_PREFIX_NAME "wpan-nl802154"
#define _NMLOG(level, domain, ...) \
	G_STMT_START { \
		char _ifname_buf[IFNAMSIZ]; \
		const char *_ifname = self ? nmp_utils_if_indextoname (self->ifindex, _ifname_buf) : NULL; \
		\
		nm_log ((level), (domain), _ifname ?: NULL, NULL, \
		        "%s%s%s%s: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
		        _NMLOG_PREFIX_NAME, \
		        NM_PRINT_FMT_QUOTED (_ifname, " (", _ifname, ")", "") \
		        _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
	} G_STMT_END

/*****************************************************************************/

struct NMWpanUtils {
        GObject parent;
	int ifindex;
	struct nl_sock *nl_sock;
	int id;
};

typedef struct {
        GObjectClass parent;
} NMWpanUtilsClass;

G_DEFINE_TYPE (NMWpanUtils, nm_wpan_utils, G_TYPE_OBJECT)

/*****************************************************************************/

static int
ack_handler (struct nl_msg *msg, void *arg)
{
	int *done = arg;
	*done = 1;
	return NL_STOP;
}

static int
finish_handler (struct nl_msg *msg, void *arg)
{
	int *done = arg;
	*done = 1;
	return NL_SKIP;
}

static int
error_handler (struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg)
{
	int *done = arg;
	*done = err->error;
	return NL_SKIP;
}

static struct nl_msg *
_nl802154_alloc_msg (int id, int ifindex, guint32 cmd, guint32 flags)
{
	nm_auto_nlmsg struct nl_msg *msg = NULL;

	msg = nlmsg_alloc ();
	genlmsg_put (msg, 0, 0, id, 0, flags, cmd, 0);
	NLA_PUT_U32 (msg, NL802154_ATTR_IFINDEX, ifindex);
	return g_steal_pointer (&msg);

nla_put_failure:
	return NULL;
}

static struct nl_msg *
nl802154_alloc_msg (NMWpanUtils *self, guint32 cmd, guint32 flags)
{
	return _nl802154_alloc_msg (self->id, self->ifindex, cmd, flags);
}

static int
nl802154_send_and_recv (NMWpanUtils *self,
                        struct nl_msg *msg,
                        int (*valid_handler) (struct nl_msg *, void *),
                        void *valid_data)
{
	int err;
	int done = 0;
	const struct nl_cb cb = {
		.err_cb     = error_handler,
		.err_arg    = &done,
		.finish_cb  = finish_handler,
		.finish_arg = &done,
		.ack_cb     = ack_handler,
		.ack_arg    = &done,
		.valid_cb   = valid_handler,
		.valid_arg  = valid_data,
	};

	g_return_val_if_fail (msg != NULL, -ENOMEM);

	err = nl_send_auto (self->nl_sock, msg);
	if (err < 0)
		return err;

	/* Loop until one of our NL callbacks says we're done; on success
	 * done will be 1, on error it will be < 0.
	 */
	while (!done) {
		err = nl_recvmsgs (self->nl_sock, &cb);
		if (err < 0 && err != -EAGAIN) {
			_LOGW (LOGD_PLATFORM, "nl_recvmsgs() error: (%d) %s",
			       err, nm_strerror (err));
			break;
		}
	}

	if (err >= 0 && done < 0)
		err = done;
	return err;
}

struct nl802154_interface {
	guint16 pan_id;
	guint16 short_addr;

	gboolean valid;
};

static int
nl802154_get_interface_handler (struct nl_msg *msg, void *arg)
{
	static const struct nla_policy nl802154_policy[] = {
		[NL802154_ATTR_PAN_ID]     = { .type = NLA_U16 },
		[NL802154_ATTR_SHORT_ADDR] = { .type = NLA_U16 },
	};
	struct nlattr *tb[G_N_ELEMENTS (nl802154_policy)];
	struct nl802154_interface *info = arg;
	struct genlmsghdr *gnlh = nlmsg_data (nlmsg_hdr (msg));

	if (nla_parse_arr (tb,
	                   genlmsg_attrdata (gnlh, 0),
	                   genlmsg_attrlen (gnlh, 0),
	                   nl802154_policy) < 0)
		return NL_SKIP;

	if (tb[NL802154_ATTR_PAN_ID])
		info->pan_id = le16toh (nla_get_u16 (tb[NL802154_ATTR_PAN_ID]));

	if (tb[NL802154_ATTR_SHORT_ADDR])
		info->short_addr = le16toh (nla_get_u16 (tb[NL802154_ATTR_SHORT_ADDR]));

	info->valid = TRUE;

	return NL_SKIP;
}

static void
nl802154_get_interface (NMWpanUtils *self,
                        struct nl802154_interface *interface)
{
	nm_auto_nlmsg struct nl_msg *msg = NULL;

	memset (interface, 0, sizeof (*interface));

	msg = nl802154_alloc_msg (self, NL802154_CMD_GET_INTERFACE, 0);

	nl802154_send_and_recv (self, msg, nl802154_get_interface_handler, interface);
}

/*****************************************************************************/

guint16
nm_wpan_utils_get_pan_id (NMWpanUtils *self)
{
	struct nl802154_interface interface;

	nl802154_get_interface (self, &interface);

	return interface.pan_id;
}

gboolean
nm_wpan_utils_set_pan_id (NMWpanUtils *self, guint16 pan_id)
{
	nm_auto_nlmsg struct nl_msg *msg = NULL;
	int err;

	g_return_val_if_fail (self != NULL, FALSE);

	msg = nl802154_alloc_msg (self, NL802154_CMD_SET_PAN_ID, 0);
	NLA_PUT_U16 (msg, NL802154_ATTR_PAN_ID, htole16 (pan_id));
	err = nl802154_send_and_recv (self, msg, NULL, NULL);
	return err >= 0;

nla_put_failure:
	return FALSE;
}

guint16
nm_wpan_utils_get_short_addr (NMWpanUtils *self)
{
	struct nl802154_interface interface;

	nl802154_get_interface (self, &interface);

	return interface.short_addr;
}

gboolean
nm_wpan_utils_set_short_addr (NMWpanUtils *self, guint16 short_addr)
{
	nm_auto_nlmsg struct nl_msg *msg = NULL;
	int err;

	g_return_val_if_fail (self != NULL, FALSE);

	msg = nl802154_alloc_msg (self, NL802154_CMD_SET_SHORT_ADDR, 0);
	NLA_PUT_U16 (msg, NL802154_ATTR_SHORT_ADDR, htole16 (short_addr));
	err = nl802154_send_and_recv (self, msg, NULL, NULL);
	return err >= 0;

nla_put_failure:
	return FALSE;
}

gboolean
nm_wpan_utils_set_channel (NMWpanUtils *self, guint8 page, guint8 channel)
{
	nm_auto_nlmsg struct nl_msg *msg = NULL;
	int err;

	g_return_val_if_fail (self != NULL, FALSE);

	msg = nl802154_alloc_msg (self, NL802154_CMD_SET_CHANNEL, 0);
	NLA_PUT_U8 (msg, NL802154_ATTR_PAGE, page);
	NLA_PUT_U8 (msg, NL802154_ATTR_CHANNEL, channel);
	err = nl802154_send_and_recv (self, msg, NULL, NULL);
	return err >= 0;

nla_put_failure:
	return FALSE;
}

/*****************************************************************************/

static void
nm_wpan_utils_init (NMWpanUtils *self)
{
}

static void
nm_wpan_utils_class_init (NMWpanUtilsClass *klass)
{
}

NMWpanUtils *
nm_wpan_utils_new (int ifindex, struct nl_sock *genl, gboolean check_scan)
{
	NMWpanUtils *self;

	g_return_val_if_fail (ifindex > 0, NULL);

	if (!genl)
		return NULL;

	self = g_object_new (NM_TYPE_WPAN_UTILS, NULL);
	self->ifindex = ifindex;
	self->nl_sock = genl;
	self->id = genl_ctrl_resolve (genl, "nl802154");

	if (self->id < 0) {
		_LOGD (LOGD_PLATFORM, "genl_ctrl_resolve: failed to resolve \"nl802154\"");
		g_object_unref (self);
		return NULL;
	}

	return self;
}
