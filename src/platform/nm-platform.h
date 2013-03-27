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
 * Copyright (C) 2009 - 2010 Red Hat, Inc.
 */

#ifndef NM_PLATFORM_H
#define NM_PLATFORM_H

#include <glib-object.h>
#include <netinet/in.h>
#include <linux/if.h>

#define NM_TYPE_PLATFORM            (nm_platform_get_type ())
#define NM_PLATFORM(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_PLATFORM, NMPlatform))
#define NM_PLATFORM_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_PLATFORM, NMPlatformClass))
#define NM_IS_PLATFORM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_PLATFORM))
#define NM_IS_PLATFORM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_PLATFORM))
#define NM_PLATFORM_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_PLATFORM, NMPlatformClass))

/******************************************************************/

typedef enum {
	NM_LINK_TYPE_NONE,
	NM_LINK_TYPE_UNKNOWN,
	NM_LINK_TYPE_GENERIC,
	NM_LINK_TYPE_LOOPBACK,
	NM_LINK_TYPE_ETHERNET,
	NM_LINK_TYPE_DUMMY,
} NMLinkType;

typedef struct {
	int ifindex;
	char name[IFNAMSIZ];
	NMLinkType type;
} NMPlatformLink;

/******************************************************************/

/* NMPlatform abstract class and its implementations provide a layer between
 * networkmanager's device management classes and the operating system kernel.
 *
 * How it works, is best seen in tests/nm-platform-test.c source file.
 *
 * NMPlatform provides interface to configure kernel interfaces and receive
 * notifications about both internal and external configuration changes. It
 * respects the following rules:
 *
 * 1) Every change made through NMPlatform is readily available and the respective
 * signals are called synchronously.
 *
 * 2) State of an object retrieved from NMPlatform (through functions or events)
 * is at least as recent than the state retrieved before.
 *
 * Any failure of the above rules should be fixed in NMPlatform implementations
 * and tested in nm-platform-test. Synchronization hacks should never be put
 * to any other code. That's why NMPlatform was created and that's why the
 * testing code was written for it.
 *
 * In future, parts of linux platform implementation may be moved to the libnl
 * library.
 *
 * If you have any problems related to NMPlatform on your system, you should
 * always first run tests/nm-linux-platform-test as root and with all
 * network configuration daemons stopped. Look at the code first.
 */

typedef struct {
	GObject parent;

	int error;
} NMPlatform;

typedef struct {
	GObjectClass parent;

	gboolean (*setup) (NMPlatform *);

	GArray *(*link_get_all) (NMPlatform *);
	gboolean (*link_add) (NMPlatform *, const char *name, NMLinkType type);
	gboolean (*link_delete) (NMPlatform *, int ifindex);
	int (*link_get_ifindex) (NMPlatform *, const char *name);
	const char *(*link_get_name) (NMPlatform *, int ifindex);
	NMLinkType (*link_get_type) (NMPlatform *, int ifindex);
} NMPlatformClass;

/* NMPlatform signals
 *
 * Each signal handler is called with a type-specific object that provides
 * key attributes that constitute identity of the object. They may also
 * provide additional attributes for convenience.
 *
 * The object only intended to be used by the signal handler to determine
 * the current values. It is no longer valid after the signal handler exits
 * but you are free to copy the provided information and use it for later
 * reference.
 */
#define NM_PLATFORM_LINK_ADDED "link-added"
#define NM_PLATFORM_LINK_CHANGED "link-changed"
#define NM_PLATFORM_LINK_REMOVED "link-removed"

/* NMPlatform error codes */
enum {
	/* no error specified, sometimes this means the arguments were wrong */
	NM_PLATFORM_ERROR_NONE,
	/* object was not found */
	NM_PLATFORM_ERROR_NOT_FOUND,
	/* object already exists */
	NM_PLATFORM_ERROR_EXISTS,
};

/******************************************************************/

GType nm_platform_get_type (void);

void nm_platform_setup (GType type);
NMPlatform *nm_platform_get (void);
void nm_platform_free (void);

/******************************************************************/

int nm_platform_get_error (void);
const char *nm_platform_get_error_msg (void);

GArray *nm_platform_link_get_all (void);
gboolean nm_platform_dummy_add (const char *name);
gboolean nm_platform_link_exists (const char *name);
gboolean nm_platform_link_delete (int ifindex);
gboolean nm_platform_link_delete_by_name (const char *ifindex);
int nm_platform_link_get_ifindex (const char *name);
const char *nm_platform_link_get_name (int ifindex);
NMLinkType nm_platform_link_get_type (int ifindex);

#endif /* NM_PLATFORM_H */
