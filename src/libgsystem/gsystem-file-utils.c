/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*-
 *
 * Copyright (C) 2012 William Jon McCann <mccann@redhat.com>
 * Copyright (C) 2012 Colin Walters <walters@verbum.org>
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
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include "config.h"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "libgsystem.h"
#include <glib/gstdio.h>
#include <gio/gunixinputstream.h>
#include <glib-unix.h>
 
static int
_open_fd_noatime (const char *path)
{
  int fd;

#ifdef O_NOATIME
  fd = g_open (path, O_RDONLY | O_NOATIME, 0);
  /* Only the owner or superuser may use O_NOATIME; so we may get
   * EPERM.  EINVAL may happen if the kernel is really old...
   */
  if (fd == -1 && (errno == EPERM || errno == EINVAL))
#endif
    fd = g_open (path, O_RDONLY, 0);
  
  return fd;
}

/**
 * gs_file_read_noatime:
 * @file: a #GFile
 * @cancellable: a #GCancellable
 * @error: a #GError
 *
 * Like g_file_read(), but try to avoid updating the file's
 * access time.  This should be used by background scanning
 * components such as search indexers, antivirus programs, etc.
 *
 * Returns: (transfer full): A new input stream, or %NULL on error
 */
GInputStream *
gs_file_read_noatime (GFile         *file,
                      GCancellable  *cancellable,
                      GError       **error)
{
  gs_lfree char *path = NULL;
  int fd;

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return NULL;

  path = g_file_get_path (file);
  if (path == NULL)
    return NULL;

  fd = _open_fd_noatime (path);
  if (fd < 0)
    {
      g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (errno),
                   "%s", g_strerror (errno));
      return NULL;
    }

  return g_unix_input_stream_new (fd, TRUE);
}
