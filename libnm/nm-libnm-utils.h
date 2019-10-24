// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2017, 2018 Red Hat, Inc.
 */

#ifndef __NM_LIBNM_UTILS_H__
#define __NM_LIBNM_UTILS_H__

#include "nm-types.h"
#include "nm-glib-aux/nm-ref-string.h"

/*****************************************************************************/

/* Markers for deprecated sync code in internal API. */
#define _NM_DEPRECATED_SYNC_METHOD_INTERNAL            NM_DEPRECATED_IN_1_22
#define _NM_DEPRECATED_SYNC_WRITABLE_PROPERTY_INTERNAL NM_DEPRECATED_IN_1_22

/*****************************************************************************/

typedef enum {
	_NML_DBUS_LOG_LEVEL_INITIALIZED = 0x01,

	_NML_DBUS_LOG_LEVEL_TRACE       = 0x02,

	_NML_DBUS_LOG_LEVEL_DEBUG       = 0x04,

	/* the difference between a warning and a critical is that it results in
	 * g_warning() vs. g_critical() messages. Note that we want to use "warnings"
	 * for unknown D-Bus API that could just result because we run against a
	 * newer NetworkManager version (such warnings are more graceful, because
	 * we want that libnm can be forward compatible against newer servers).
	 * Critial warnings should be emitted when NetworkManager exposes something
	 * on D-Bus that breaks the current expectations. Usually NetworkManager
	 * should not break API, hence such issues are more severe. */
	_NML_DBUS_LOG_LEVEL_WARN        = 0x08,
	_NML_DBUS_LOG_LEVEL_ERROR       = 0x10,

	/* ANY is only relevant for nml_dbus_log_enabled() to check whether any of the
	 * options is on. */
	NML_DBUS_LOG_LEVEL_ANY          = _NML_DBUS_LOG_LEVEL_INITIALIZED,

	NML_DBUS_LOG_LEVEL_TRACE        = _NML_DBUS_LOG_LEVEL_TRACE,
	NML_DBUS_LOG_LEVEL_DEBUG        =   _NML_DBUS_LOG_LEVEL_DEBUG
	                                  | NML_DBUS_LOG_LEVEL_TRACE,
	NML_DBUS_LOG_LEVEL_WARN         =   _NML_DBUS_LOG_LEVEL_WARN
	                                  | NML_DBUS_LOG_LEVEL_DEBUG,
	NML_DBUS_LOG_LEVEL_ERROR        =   _NML_DBUS_LOG_LEVEL_ERROR
	                                  | NML_DBUS_LOG_LEVEL_WARN,
} NMLDBusLogLevel;

extern volatile int _nml_dbus_log_level;

int _nml_dbus_log_level_init (void);

static inline gboolean
nml_dbus_log_enabled (NMLDBusLogLevel level)
{
	int l;

	nm_assert (NM_IN_SET (level, NML_DBUS_LOG_LEVEL_ANY,
	                             NML_DBUS_LOG_LEVEL_TRACE,
	                             NML_DBUS_LOG_LEVEL_DEBUG,
	                             NML_DBUS_LOG_LEVEL_WARN,
	                             NML_DBUS_LOG_LEVEL_ERROR));

	l = g_atomic_int_get (&_nml_dbus_log_level);
	if (G_UNLIKELY (l == 0))
		l = _nml_dbus_log_level_init ();

	nm_assert (l & _NML_DBUS_LOG_LEVEL_INITIALIZED);
	if (level == NML_DBUS_LOG_LEVEL_ANY)
		return l != _NML_DBUS_LOG_LEVEL_INITIALIZED;
	return !!(((NMLDBusLogLevel) l) & level);
}

void _nml_dbus_log (NMLDBusLogLevel level,
                    const char *fmt,
                    ...) _nm_printf (2, 3);

#define NML_DBUS_LOG(level, ...) \
	G_STMT_START { \
		G_STATIC_ASSERT (   (level) == NML_DBUS_LOG_LEVEL_TRACE \
		                 || (level) == NML_DBUS_LOG_LEVEL_DEBUG \
		                 || (level) == NML_DBUS_LOG_LEVEL_WARN \
		                 || (level) == NML_DBUS_LOG_LEVEL_ERROR); \
		\
		if (nml_dbus_log_enabled (level)) { \
			_nml_dbus_log ((level), __VA_ARGS__); \
		} \
	} G_STMT_END

#define NML_DBUS_LOG_T(...) NML_DBUS_LOG (NML_DBUS_LOG_LEVEL_TRACE, __VA_ARGS__)
#define NML_DBUS_LOG_D(...) NML_DBUS_LOG (NML_DBUS_LOG_LEVEL_DEBUG, __VA_ARGS__)
#define NML_DBUS_LOG_W(...) NML_DBUS_LOG (NML_DBUS_LOG_LEVEL_WARN,  __VA_ARGS__)
#define NML_DBUS_LOG_E(...) NML_DBUS_LOG (NML_DBUS_LOG_LEVEL_ERROR, __VA_ARGS__)

#define NML_NMCLIENT_LOG(level, self, ...) \
	NML_DBUS_LOG ((level), \
	              "nmclient["NM_HASH_OBFUSCATE_PTR_FMT"]: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
	              NM_HASH_OBFUSCATE_PTR (self) \
	              _NM_UTILS_MACRO_REST (__VA_ARGS__))

#define NML_NMCLIENT_LOG_T(self, ...) NML_NMCLIENT_LOG (NML_DBUS_LOG_LEVEL_TRACE, self, __VA_ARGS__)
#define NML_NMCLIENT_LOG_D(self, ...) NML_NMCLIENT_LOG (NML_DBUS_LOG_LEVEL_DEBUG, self, __VA_ARGS__)
#define NML_NMCLIENT_LOG_W(self, ...) NML_NMCLIENT_LOG (NML_DBUS_LOG_LEVEL_WARN,  self, __VA_ARGS__)
#define NML_NMCLIENT_LOG_E(self, ...) NML_NMCLIENT_LOG (NML_DBUS_LOG_LEVEL_ERROR, self, __VA_ARGS__)

/*****************************************************************************/

static inline const char *
_nml_coerce_property_str_not_null (const char *str)
{
	return str ?: "";
}

static inline const char *
_nml_coerce_property_str_not_empty (const char *str)
{
	return str && str[0] ? str : NULL;
}

static inline const char *
_nml_coerce_property_object_path (NMRefString *path)
{
	if (!path)
		return NULL;
	return nm_dbus_path_not_empty (path->str);
}

static inline const char *const*
_nml_coerce_property_strv_not_null (char **strv)
{
	return ((const char *const*) strv) ?: NM_PTRARRAY_EMPTY (const char *);
}

/*****************************************************************************/

char *nm_utils_wincaps_to_dash (const char *caps);

/*****************************************************************************/

char *nm_utils_fixup_vendor_string (const char *desc);
char *nm_utils_fixup_product_string (const char *desc);

/*****************************************************************************/

struct _NMObjectPrivate;

struct _NMObject {
	GObject parent;
	struct _NMObjectPrivate *_priv;
};

struct _NMObjectClass {
	GObjectClass parent;

	void (*init_dbus) (struct _NMObject *object);

	/* The "object-creation-failed" method is PRIVATE for libnm and
	 * is not meant for any external usage.  It indicates that an error
	 * occurred during creation of an object.
	 */
	void (*object_creation_failed) (struct _NMObject *master_object,
	                                const char *failed_path);
};

/*****************************************************************************/

struct _NMDevicePrivate;

struct _NMDevice {
	NMObject parent;
	struct _NMDevicePrivate *_priv;
};

struct _NMDeviceClass {
	struct _NMObjectClass parent;

	/* Signals */
	void (*state_changed) (NMDevice *device,
	                       NMDeviceState new_state,
	                       NMDeviceState old_state,
	                       NMDeviceStateReason reason);

	/* Methods */
	gboolean (*connection_compatible) (NMDevice *device,
	                                   NMConnection *connection,
	                                   GError **error);

	const char * (*get_type_description) (NMDevice *device);
	const char * (*get_hw_address) (NMDevice *device);

	GType (*get_setting_type) (NMDevice *device);
};

/*****************************************************************************/

struct _NMActiveConnectionPrivate;

struct _NMActiveConnection {
	NMObject parent;
	struct _NMActiveConnectionPrivate *_priv;
};

struct _NMActiveConnectionClass {
	struct _NMObjectClass parent;
};

/*****************************************************************************/

struct _NMDhcpConfigPrivate;

struct _NMDhcpConfig {
	NMObject parent;
	struct _NMDhcpConfigPrivate *_priv;
};

struct _NMDhcpConfigClass {
	struct _NMObjectClass parent;
};

/*****************************************************************************/

struct _NMIPConfigPrivate;

struct _NMIPConfig {
	NMObject parent;
	struct _NMIPConfigPrivate *_priv;
};

struct _NMIPConfigClass {
	struct _NMObjectClass parent;
};

/*****************************************************************************/

#endif /* __NM_LIBNM_UTILS_H__ */
