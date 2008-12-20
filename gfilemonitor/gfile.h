/*
 * Copyright (C) 2008 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Author: Dan Williams <dcbw@redhat.com>
 */

#ifndef __G_FILE_H__
#define __G_FILE_H__

#include <glib-object.h>

G_BEGIN_DECLS

#define G_TYPE_FILE            (g_file_get_type ())
#define G_FILE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), G_TYPE_FILE, GFile))
#define G_FILE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), G_TYPE_FILE, GFileClass))
#define G_IS_FILE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), G_TYPE_FILE))
#define G_IS_FILE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), G_TYPE_FILE))
#define G_FILE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), G_TYPE_FILE, GFileClass))

typedef enum  {
  G_FILE_MONITOR_NONE = 0,
} GFileMonitorFlags;

typedef struct _GFileMonitor GFileMonitor;

typedef struct {
	GObject parent;
} GFile;

typedef struct {
	GObjectClass parent;
} GFileClass;

GType g_file_get_type (void) G_GNUC_CONST;

GFile *        g_file_new_for_path      (const char *path);

char *         g_file_get_basename      (GFile *file);

char *         g_file_get_path          (GFile *file);

const char *   g_file_get_const_path    (GFile *file);

GFileMonitor * g_file_monitor_directory (GFile *file,
                                         GFileMonitorFlags flags,
                                         void *unused,
                                         GError **error);

GFileMonitor * g_file_monitor_file      (GFile *file,
                                         GFileMonitorFlags flags,
                                         void *unused,
                                         GError **error);

G_END_DECLS

#endif /* __G_FILE_H__ */
