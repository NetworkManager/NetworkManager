/* -*- mode: C; c-file-style: "linux" -*- */

/* MemProf -- memory profiler and leak detector
 * Copyright 1999, 2000, 2001, Red Hat, Inc.
 * Copyright 2002, Kristian Rietveld
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
/*====*/

#include <glib.h>
#include <sys/stat.h>
#include <dirent.h>
#include "memprof.h"

/************************************************************
 * Inode finding code - not needed for kernel 2.2 or greater
 ************************************************************/

GHashTable *inode_table = NULL;

typedef struct {
	dev_t device;
	ino_t inode;
	gchar *name;
} Inode;

static guint
inode_hash (gconstpointer data)
{
	return (((Inode *)data)->device + (((Inode *)data)->inode << 11));
}

static gint
inode_compare (gconstpointer a, gconstpointer b)
{
	return ((((Inode *)a)->device == ((Inode *)b)->device) &&
		(((Inode *)a)->inode == ((Inode *)b)->inode));
}

void
read_inode (const gchar *path)
{
	struct stat stbuf;

	g_return_if_fail (path != NULL);

	if (!inode_table)
	        inode_table = g_hash_table_new (inode_hash, inode_compare);

	if (!stat (path, &stbuf)) {
		Inode *inode = g_new (Inode, 1);
		inode->device = stbuf.st_dev;
		inode->inode = stbuf.st_ino;
		if (!g_hash_table_lookup (inode_table, inode)) {
			inode->name = g_strdup (path);
			g_hash_table_insert (inode_table, inode, inode);
		} else
			g_free (inode);
	}
}

static void
read_inodes ()
{
	static const char *directories[] = {
		"/lib",
		"/usr/lib",
		"/usr/X11R6/lib",
		"/usr/local/lib",
		"/opt/gnome/lib",
		NULL
	};

	const char **dirname;

	for (dirname = directories; *dirname; dirname++)
	{
		DIR *dir = opendir (*dirname);
      
		if (dir) {
			struct dirent *ent;
			while ((ent = readdir (dir))) {
				gchar buf[1024];
				snprintf(buf, 1024-1, "%s/%s", *dirname, ent->d_name);
				read_inode (buf);
			}
	  
			closedir (dir);
		}
	}
}

gchar *
locate_inode (dev_t device, ino_t inode)
{
	Inode lookup;
	Inode *result;

	lookup.device = device;
	lookup.inode = inode;

	if (!inode_table)
		read_inodes ();
	
	result = g_hash_table_lookup (inode_table, &lookup);
	if (result)
		return result->name;
	else
		return NULL;
}

