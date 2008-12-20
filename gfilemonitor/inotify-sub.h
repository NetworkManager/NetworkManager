/* inotify-sub.h - GVFS Directory Monitor using inotify

   Copyright (C) 2006 John McCutchan

   The Gnome Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The Gnome Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the
   Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301 USA.

   Author: John McCutchan <john@johnmccutchan.com>
*/


#ifndef __INOTIFY_SUB_H
#define __INOTIFY_SUB_H

typedef struct
{
	gchar*   dirname;
	gchar*   filename;
	gboolean cancelled;
	gpointer user_data;
} inotify_sub;

inotify_sub* _ih_sub_new (const gchar* dirname, const gchar* filename, gpointer user_data);
void         _ih_sub_free (inotify_sub* sub);

#endif /* __INOTIFY_SUB_H */
