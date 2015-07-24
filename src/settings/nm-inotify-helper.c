/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service
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
 * (C) Copyright 2008 Red Hat, Inc.
 */

#include "config.h"

#include <unistd.h>
#include <string.h>
#include <sys/inotify.h>
#include <glib.h>
#include <errno.h>

#include "nm-inotify-helper.h"
#include "nm-logging.h"
#include "NetworkManagerUtils.h"

/* NOTE: this code should be killed once we depend on a new enough glib to
 * include the patches from https://bugzilla.gnome.org/show_bug.cgi?id=532815
 */

G_DEFINE_TYPE (NMInotifyHelper, nm_inotify_helper, G_TYPE_OBJECT)

#define NM_INOTIFY_HELPER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_INOTIFY_HELPER, NMInotifyHelperPrivate))

typedef struct {
	int ifd;

	GHashTable *wd_refs;
} NMInotifyHelperPrivate;

/* Signals */
enum {
	EVENT,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

int
nm_inotify_helper_add_watch (NMInotifyHelper *self, const char *path)
{
	NMInotifyHelperPrivate *priv = NM_INOTIFY_HELPER_GET_PRIVATE (self);
	int wd;
	guint refcount;

	if (priv->ifd < 0)
		return -1;

	/* We only care about modifications since we're just trying to get change
	 * notifications on hardlinks.
	 */

	wd = inotify_add_watch (priv->ifd, path, IN_CLOSE_WRITE);
	if (wd < 0)
		return -1;

	refcount = GPOINTER_TO_UINT (g_hash_table_lookup (priv->wd_refs, GINT_TO_POINTER (wd)));
	refcount++;
	g_hash_table_replace (priv->wd_refs, GINT_TO_POINTER (wd), GUINT_TO_POINTER (refcount));

	return wd;
}

void
nm_inotify_helper_remove_watch (NMInotifyHelper *self, int wd)
{
	NMInotifyHelperPrivate *priv = NM_INOTIFY_HELPER_GET_PRIVATE (self);
	guint refcount;

	if (priv->ifd < 0)
		return;

	refcount = GPOINTER_TO_UINT (g_hash_table_lookup (priv->wd_refs, GINT_TO_POINTER (wd)));
	if (!refcount)
		return;

	refcount--;
	if (!refcount) {
		g_hash_table_remove (priv->wd_refs, GINT_TO_POINTER (wd));
		inotify_rm_watch (priv->ifd, wd);
	} else
		g_hash_table_replace (priv->wd_refs, GINT_TO_POINTER (wd), GUINT_TO_POINTER (refcount));
}

static gboolean
inotify_event_handler (GIOChannel *channel, GIOCondition cond, gpointer user_data)
{
	NMInotifyHelper *self = NM_INOTIFY_HELPER (user_data);
	struct inotify_event evt;

	/* read the notifications from the watch descriptor */
	while (g_io_channel_read_chars (channel, (gchar *) &evt, sizeof (struct inotify_event), NULL, NULL) == G_IO_STATUS_NORMAL) {
		gchar filename[PATH_MAX + 1];

		filename[0] = '\0';
		if (evt.len > 0) {
			g_io_channel_read_chars (channel,
			                        filename,
			                        evt.len > PATH_MAX ? PATH_MAX : evt.len,
			                        NULL, NULL);
		}

		if (!(evt.mask & IN_IGNORED))
			g_signal_emit (self, signals[EVENT], 0, &evt, &filename[0]);
	}

	return TRUE;
}

static gboolean
init_inotify (NMInotifyHelper *self)
{
	NMInotifyHelperPrivate *priv = NM_INOTIFY_HELPER_GET_PRIVATE (self);
	GIOChannel *channel;
	guint source_id;

	priv->ifd = inotify_init ();
	if (priv->ifd == -1) {
		int errsv = errno;

		nm_log_warn (LOGD_SETTINGS, "couldn't initialize inotify: %s (%d)", strerror (errsv), errsv);
		return FALSE;
	}

	/* Watch the inotify descriptor for file/directory change events */
	channel = g_io_channel_unix_new (priv->ifd);
	g_io_channel_set_flags (channel, G_IO_FLAG_NONBLOCK, NULL);
	g_io_channel_set_encoding (channel, NULL, NULL); 

	source_id = g_io_add_watch (channel,
	                            G_IO_IN | G_IO_ERR,
	                            (GIOFunc) inotify_event_handler,
	                            (gpointer) self);
	g_io_channel_unref (channel);
	return TRUE;
}

NM_DEFINE_SINGLETON_GETTER (NMInotifyHelper, nm_inotify_helper_get, NM_TYPE_INOTIFY_HELPER);

static void
nm_inotify_helper_init (NMInotifyHelper *self)
{
	NMInotifyHelperPrivate *priv = NM_INOTIFY_HELPER_GET_PRIVATE (self);

	priv->wd_refs = g_hash_table_new (g_direct_hash, g_direct_equal);
}

static void
constructed (GObject *object)
{
	G_OBJECT_CLASS (nm_inotify_helper_parent_class)->constructed (object);

	init_inotify (NM_INOTIFY_HELPER (object));
}

static void
finalize (GObject *object)
{
	NMInotifyHelperPrivate *priv = NM_INOTIFY_HELPER_GET_PRIVATE (object);

	if (priv->ifd >= 0)
		close (priv->ifd);

	g_hash_table_destroy (priv->wd_refs);

	G_OBJECT_CLASS (nm_inotify_helper_parent_class)->finalize (object);
}

static void
nm_inotify_helper_class_init (NMInotifyHelperClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMInotifyHelperPrivate));

	/* Virtual methods */
	object_class->constructed = constructed;
	object_class->finalize = finalize;

	/* Signals */
	signals[EVENT] =
		g_signal_new ("event",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMInotifyHelperClass, event),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 2, G_TYPE_POINTER, G_TYPE_STRING);
}

