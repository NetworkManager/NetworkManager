/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*-
 *
 * Copyright (C) 2012 Colin Walters <walters@verbum.org>.
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

#ifndef __GSYSTEM_LOCAL_ALLOC_H__
#define __GSYSTEM_LOCAL_ALLOC_H__

#define NM_AUTO_DEFINE_FCN_VOID(CastType, name, func) \
static inline void name (void *v) \
{ \
	func (*((CastType *) v)); \
}

#define NM_AUTO_DEFINE_FCN_VOID0(CastType, name, func) \
static inline void name (void *v) \
{ \
	if (*((CastType *) v)) \
		func (*((CastType *) v)); \
}

#define NM_AUTO_DEFINE_FCN(Type, name, func) \
static inline void name (Type *v) \
{ \
	func (*v); \
}

#define NM_AUTO_DEFINE_FCN0(Type, name, func) \
static inline void name (Type *v) \
{ \
	if (*v) \
		func (*v); \
}

#define NM_AUTO_DEFINE_FCN_STRUCT(Type, name, func) \
static inline void name (Type *v) \
{ \
	func (v); \
}

/**
 * gs_free:
 *
 * Call g_free() on a variable location when it goes out of scope.
 */
#define gs_free __attribute__ ((cleanup(gs_local_free)))
NM_AUTO_DEFINE_FCN_VOID (void *, gs_local_free, g_free)

/**
 * gs_unref_object:
 *
 * Call g_object_unref() on a variable location when it goes out of
 * scope.  Note that unlike g_object_unref(), the variable may be
 * %NULL.
 */
#define gs_unref_object __attribute__ ((cleanup(gs_local_obj_unref)))
NM_AUTO_DEFINE_FCN_VOID0 (GObject *, gs_local_obj_unref, g_object_unref)

/**
 * gs_unref_variant:
 *
 * Call g_variant_unref() on a variable location when it goes out of
 * scope.  Note that unlike g_variant_unref(), the variable may be
 * %NULL.
 */
#define gs_unref_variant __attribute__ ((cleanup(gs_local_variant_unref)))
NM_AUTO_DEFINE_FCN0 (GVariant *, gs_local_variant_unref, g_variant_unref)

/**
 * gs_unref_array:
 *
 * Call g_array_unref() on a variable location when it goes out of
 * scope.  Note that unlike g_array_unref(), the variable may be
 * %NULL.

 */
#define gs_unref_array __attribute__ ((cleanup(gs_local_array_unref)))
NM_AUTO_DEFINE_FCN0 (GArray *, gs_local_array_unref, g_array_unref)

/**
 * gs_unref_ptrarray:
 *
 * Call g_ptr_array_unref() on a variable location when it goes out of
 * scope.  Note that unlike g_ptr_array_unref(), the variable may be
 * %NULL.

 */
#define gs_unref_ptrarray __attribute__ ((cleanup(gs_local_ptrarray_unref)))
NM_AUTO_DEFINE_FCN0 (GPtrArray *, gs_local_ptrarray_unref, g_ptr_array_unref)

/**
 * gs_unref_hashtable:
 *
 * Call g_hash_table_unref() on a variable location when it goes out
 * of scope.  Note that unlike g_hash_table_unref(), the variable may
 * be %NULL.
 */
#define gs_unref_hashtable __attribute__ ((cleanup(gs_local_hashtable_unref)))
NM_AUTO_DEFINE_FCN0 (GHashTable *, gs_local_hashtable_unref, g_hash_table_unref)

/**
 * gs_free_slist:
 *
 * Call g_slist_free() on a variable location when it goes out
 * of scope.
 */
#define gs_free_slist __attribute__ ((cleanup(gs_local_free_slist)))
NM_AUTO_DEFINE_FCN (GSList *, gs_local_free_slist, g_slist_free)

/**
 * gs_unref_bytes:
 *
 * Call g_bytes_unref() on a variable location when it goes out
 * of scope.  Note that unlike g_bytes_unref(), the variable may
 * be %NULL.
 */
#define gs_unref_bytes __attribute__ ((cleanup(gs_local_bytes_unref)))
NM_AUTO_DEFINE_FCN0 (GBytes *, gs_local_bytes_unref, g_bytes_unref)

/**
 * gs_strfreev:
 *
 * Call g_strfreev() on a variable location when it goes out of scope.
 */
#define gs_strfreev __attribute__ ((cleanup(gs_local_strfreev)))
NM_AUTO_DEFINE_FCN (char **, gs_local_strfreev, g_strfreev)

/**
 * gs_free_error:
 *
 * Call g_error_free() on a variable location when it goes out of scope.
 */
#define gs_free_error __attribute__ ((cleanup(gs_local_free_error)))
NM_AUTO_DEFINE_FCN0 (GError *, gs_local_free_error, g_error_free)

/**
 * gs_unref_keyfile:
 *
 * Call g_key_file_unref() on a variable location when it goes out of scope.
 */
#define gs_unref_keyfile __attribute__ ((cleanup(gs_local_keyfile_unref)))
NM_AUTO_DEFINE_FCN0 (GKeyFile *, gs_local_keyfile_unref, g_key_file_unref)

#endif
