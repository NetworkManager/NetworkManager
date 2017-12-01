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

#ifndef __NM_INOTIFY_HELPER_H__
#define __NM_INOTIFY_HELPER_H__

/* NOTE: this code should be killed once we depend on a new enough glib to
 * include the patches from https://bugzilla.gnome.org/show_bug.cgi?id=532815
 */

#define NM_TYPE_INOTIFY_HELPER            (nm_inotify_helper_get_type ())
#define NM_INOTIFY_HELPER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_INOTIFY_HELPER, NMInotifyHelper))
#define NM_INOTIFY_HELPER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_INOTIFY_HELPER, NMInotifyHelperClass))
#define NM_IS_INOTIFY_HELPER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_INOTIFY_HELPER))
#define NM_IS_INOTIFY_HELPER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_INOTIFY_HELPER))
#define NM_INOTIFY_HELPER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_INOTIFY_HELPER, NMInotifyHelperClass))

typedef struct _NMInotifyHelper NMInotifyHelper;
typedef struct _NMInotifyHelperClass NMInotifyHelperClass;

GType nm_inotify_helper_get_type (void);

NMInotifyHelper * nm_inotify_helper_get (void);

int nm_inotify_helper_add_watch (NMInotifyHelper *helper, const char *path);

void nm_inotify_helper_remove_watch (NMInotifyHelper *helper, int wd);

static inline gboolean
nm_inotify_helper_clear_watch (NMInotifyHelper *helper, int *wd)
{
	int x;

	if (wd && ((x = *wd) >= 0)) {
		*wd = -1;
		nm_inotify_helper_remove_watch (helper, x);
		return TRUE;
	}
	return FALSE;
}

#endif  /* __NM_INOTIFY_HELPER_H__ */
