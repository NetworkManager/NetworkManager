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
 * Copyright (C) 2016 Red Hat, Inc.
 */

#include "nm-default.h"
#include "nmp-netns.h"

#include <fcntl.h>
#include <errno.h>
#include <sys/mount.h>

#include "NetworkManagerUtils.h"

/*********************************************************************************************/

#define _NMLOG_DOMAIN        LOGD_PLATFORM
#define _NMLOG_PREFIX_NAME   "netns"
#define _NMLOG(level, netns, ...) \
    G_STMT_START { \
        NMLogLevel _level = (level); \
        \
        if (nm_logging_enabled (_level, _NMLOG_DOMAIN)) { \
            NMPNetns *_netns = (netns); \
            char _sbuf[20]; \
            \
            _nm_log (_level, _NMLOG_DOMAIN, 0, \
                     "%s%s: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
                     _NMLOG_PREFIX_NAME, \
                     (_netns ? nm_sprintf_buf (_sbuf, "[%p]", _netns) : "") \
                     _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
        } \
    } G_STMT_END

/*********************************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_FD_NET,
	PROP_FD_MNT,
);

typedef struct _NMPNetnsPrivate NMPNetnsPrivate;

struct _NMPNetnsPrivate {
	int fd_net;
	int fd_mnt;
};

typedef struct {
	NMPNetns *netns;
	int count;
} NetnsInfo;

static void _stack_push (NMPNetns *netns);
static NMPNetns *_netns_new (GError **error);

/*********************************************************************************************/

static GArray *netns_stack = NULL;

static void
_stack_ensure_init_impl (void)
{
	NMPNetns *netns;
	GError *error = NULL;

	nm_assert (!netns_stack);

	netns_stack = g_array_new (FALSE, FALSE, sizeof (NetnsInfo));

	/* at the bottom of the stack we must try to create a netns instance
	 * that we never pop. It's the base to which we need to return. */

	netns = _netns_new (&error);

	if (!netns) {
		/* don't know how to recover from this error. Netns are not supported. */
		_LOGE (NULL, "failed to create initial netns: %s", error->message);
		g_clear_error (&error);
		return;
	}

	_stack_push (netns);

	/* we leak this instance inside netns_stack. It cannot be popped. */
	g_object_unref (netns);
}
#define _stack_ensure_init() \
	G_STMT_START { \
		if (G_UNLIKELY (!netns_stack)) { \
			_stack_ensure_init_impl (); \
		} \
	} G_STMT_END

static NetnsInfo *
_stack_peek (void)
{
	nm_assert (netns_stack);

	if (netns_stack->len > 0)
		return &g_array_index (netns_stack, NetnsInfo, (netns_stack->len - 1));
	return NULL;
}

static NetnsInfo *
_stack_peek2 (void)
{
	nm_assert (netns_stack);

	if (netns_stack->len > 1)
		return &g_array_index (netns_stack, NetnsInfo, (netns_stack->len - 2));
	return NULL;
}

static NetnsInfo *
_stack_bottom (void)
{
	nm_assert (netns_stack);

	if (netns_stack->len > 0)
		return &g_array_index (netns_stack, NetnsInfo, 0);
	return NULL;
}

static void
_stack_push (NMPNetns *netns)
{
	NetnsInfo *info;

	nm_assert (netns_stack);
	nm_assert (NMP_IS_NETNS (netns));

	g_array_set_size (netns_stack, netns_stack->len + 1);

	info = &g_array_index (netns_stack, NetnsInfo, (netns_stack->len - 1));
	info->netns = g_object_ref (netns);
	info->count = 1;
}

static void
_stack_pop (void)
{
	NetnsInfo *info;

	nm_assert (netns_stack);
	nm_assert (netns_stack->len > 1);

	info = &g_array_index (netns_stack, NetnsInfo, (netns_stack->len - 1));

	nm_assert (NMP_IS_NETNS (info->netns));
	nm_assert (info->count == 1);

	g_object_unref (info->netns);

	g_array_set_size (netns_stack, netns_stack->len - 1);
}

static guint
_stack_size (void)
{
	nm_assert (netns_stack);

	return netns_stack->len;
}

/*********************************************************************************************/

G_DEFINE_TYPE (NMPNetns, nmp_netns, G_TYPE_OBJECT);

#define NMP_NETNS_GET_PRIVATE(o) ((o)->priv)

/*********************************************************************************************/

static NMPNetns *
_netns_new (GError **error)
{
	NMPNetns *self;
	int fd_net, fd_mnt;
	int errsv;

	fd_net = open ("/proc/self/ns/net", O_RDONLY);
	if (fd_net == -1) {
		errsv = errno;
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             "Failed opening netns: %s",
		             g_strerror (errsv));
		return NULL;
	}

	fd_mnt = open ("/proc/self/ns/mnt", O_RDONLY);
	if (fd_mnt == -1) {
		errsv = errno;
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             "Failed opening mntns: %s",
		             g_strerror (errsv));
		close (fd_net);
		return NULL;
	}

	self = g_object_new (NMP_TYPE_NETNS,
	                     NMP_NETNS_FD_NET, fd_net,
	                     NMP_NETNS_FD_MNT, fd_mnt,
	                     NULL);

	_LOGD (self, "new netns (net:%d, mnt:%d)", fd_net, fd_mnt);

	return self;
}

static gboolean
_netns_switch (NMPNetns *self, NMPNetns *netns_fail)
{
	int errsv;

	if (setns (self->priv->fd_net, CLONE_NEWNET) != 0) {
		errsv = errno;
		_LOGE (self, "failed to switch netns: %s", g_strerror (errsv));
		return FALSE;
	}
	if (setns (self->priv->fd_mnt, CLONE_NEWNS) != 0) {
		errsv = errno;
		_LOGE (self, "failed to switch mntns: %s", g_strerror (errsv));

		/* try to fix the mess by returning to the previous netns. */
		if (netns_fail) {
			if (setns (netns_fail->priv->fd_net, CLONE_NEWNET) != 0) {
				errsv = errno;
				_LOGE (netns_fail, "failed to restore netns: %s", g_strerror (errsv));
			}
		}
		return FALSE;
	}

	return TRUE;
}

/*********************************************************************************************/

int
nmp_netns_get_fd_net (NMPNetns *self)
{
	g_return_val_if_fail (NMP_IS_NETNS (self), 0);

	return self->priv->fd_net;
}

int
nmp_netns_get_fd_mnt (NMPNetns *self)
{
	g_return_val_if_fail (NMP_IS_NETNS (self), 0);

	return self->priv->fd_mnt;
}

/*********************************************************************************************/

gboolean
nmp_netns_push (NMPNetns *self)
{
	NetnsInfo *info;

	g_return_val_if_fail (NMP_IS_NETNS (self), FALSE);

	_stack_ensure_init ();

	info = _stack_peek ();
	g_return_val_if_fail (info, FALSE);

	if (info->netns == self) {
		info->count++;
		_LOGt (self, "push (increase count to %d)", info->count);
		return TRUE;
	}

	_LOGD (self, "push (was %p)", info->netns);

	if (!_netns_switch (self, info->netns))
		return FALSE;

	_stack_push (self);
	return TRUE;
}

NMPNetns *
nmp_netns_new (void)
{
	NetnsInfo *info;
	NMPNetns *self;
	int errsv;
	GError *error = NULL;

	_stack_ensure_init ();

	if (!_stack_peek ()) {
		/* there are no netns instances. We cannot create a new one
		 * (because after unshare we couldn't return to the original one). */
		return NULL;
	}

	if (unshare (CLONE_NEWNET | CLONE_NEWNS) != 0) {
		errsv = errno;
		_LOGE (NULL, "failed to create new net and mnt namespace: %s", g_strerror (errsv));
		return NULL;
	}

	if (mount ("", "/", "none", MS_SLAVE | MS_REC, NULL)) {
		_LOGE (NULL, "failed mount --make-rslave: %s", error->message);
		goto err_out;
	}

	if (umount2 ("/sys", MNT_DETACH) < 0) {
		_LOGE (NULL, "failed umount /sys: %s", error->message);
		goto err_out;
	}

	if (mount ("sysfs", "/sys", "sysfs", 0, NULL) < 0) {
		_LOGE (NULL, "failed mount /sys: %s", error->message);
		goto err_out;
	}

	self = _netns_new (&error);
	if (!self) {
		_LOGE (NULL, "failed to create netns after unshare: %s", error->message);
		g_clear_error (&error);
		goto err_out;
	}

	_stack_push (self);

	return self;
err_out:
	info = _stack_peek ();
	_netns_switch (info->netns, NULL);
	return NULL;
}

gboolean
nmp_netns_pop (NMPNetns *self)
{
	NetnsInfo *info;

	g_return_val_if_fail (NMP_IS_NETNS (self), FALSE);

	_stack_ensure_init ();

	info = _stack_peek ();

	g_return_val_if_fail (info, FALSE);
	g_return_val_if_fail (info->netns == self, FALSE);

	if (info->count > 1) {
		info->count--;
		_LOGt (self, "pop (decrease count to %d)", info->count);
		return TRUE;
	}
	g_return_val_if_fail (info->count == 1, FALSE);

	/* cannot pop the original netns. */
	g_return_val_if_fail (_stack_size () > 1, FALSE);

	_LOGD (self, "pop (restore %p)", _stack_peek2 ());

	_stack_pop ();
	info = _stack_peek ();

	nm_assert (info);

	return _netns_switch (info->netns, NULL);
}

NMPNetns *
nmp_netns_get_current (void)
{
	NetnsInfo *info;

	_stack_ensure_init ();

	info = _stack_peek ();
	return info ? info->netns : NULL;
}

NMPNetns *
nmp_netns_get_initial (void)
{
	NetnsInfo *info;

	_stack_ensure_init ();

	info = _stack_bottom ();
	return info ? info->netns : NULL;
}

gboolean
nmp_netns_is_initial (void)
{
	if (G_UNLIKELY (!netns_stack))
		return TRUE;

	return nmp_netns_get_current () == nmp_netns_get_initial ();
}

/*********************************************************************************************/

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMPNetns *self = NMP_NETNS (object);

	switch (prop_id) {
	case PROP_FD_NET:
		/* construct only */
		self->priv->fd_net = g_value_get_int (value);
		g_return_if_fail (self->priv->fd_net > 0);
		break;
	case PROP_FD_MNT:
		/* construct only */
		self->priv->fd_mnt = g_value_get_int (value);
		g_return_if_fail (self->priv->fd_mnt > 0);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmp_netns_init (NMPNetns *self)
{
	self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self, NMP_TYPE_NETNS, NMPNetnsPrivate);
}

static void
dispose (GObject *object)
{
	NMPNetns *self = NMP_NETNS (object);

	if (self->priv->fd_net > 0) {
		close (self->priv->fd_net);
		self->priv->fd_net = 0;
	}

	if (self->priv->fd_mnt > 0) {
		close (self->priv->fd_mnt);
		self->priv->fd_mnt = 0;
	}

	G_OBJECT_CLASS (nmp_netns_parent_class)->dispose (object);
}

static void
nmp_netns_class_init (NMPNetnsClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMPNetnsPrivate));

	object_class->set_property = set_property;
	object_class->dispose = dispose;

	obj_properties[PROP_FD_NET]
	    = g_param_spec_int (NMP_NETNS_FD_NET, "", "",
	                        0, G_MAXINT, 0,
	                        G_PARAM_WRITABLE |
	                        G_PARAM_CONSTRUCT_ONLY |
	                        G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_FD_MNT]
	    = g_param_spec_int (NMP_NETNS_FD_MNT, "", "",
	                        0, G_MAXINT, 0,
	                        G_PARAM_WRITABLE |
	                        G_PARAM_CONSTRUCT_ONLY |
	                        G_PARAM_STATIC_STRINGS);
	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}
