/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
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
 * Copyright 2004 - 2014 Red Hat, Inc.
 */

#ifndef __NM_ERRORS_H__
#define __NM_ERRORS_H__

/**
 * NMAgentManagerError:
 * @NM_AGENT_MANAGER_ERROR_FAILED: unknown or unspecified error
 * @NM_AGENT_MANAGER_ERROR_PERMISSION_DENIED: The caller does not have permission
 *   to register a secret agent, or is trying to register the same secret agent
 *   twice.
 * @NM_AGENT_MANAGER_ERROR_INVALID_IDENTIFIER: The identifier is not a valid
 *   secret agent identifier.
 * @NM_AGENT_MANAGER_ERROR_NOT_REGISTERED: The caller tried to unregister an agent
 *   that was not registered.
 * @NM_AGENT_MANAGER_ERROR_NO_SECRETS: No secret agent returned secrets for this
 *   request
 * @NM_AGENT_MANAGER_ERROR_USER_CANCELED: The user canceled the secrets request.
 *
 * Errors returned from the secret-agent manager.
 *
 * These errors may be returned from operations that could cause secrets to be
 * requested (such as nm_client_activate_connection()), and correspond to D-Bus
 * errors in the "org.freedesktop.NetworkManager.AgentManager" namespace.
 */
typedef enum {
	NM_AGENT_MANAGER_ERROR_FAILED = 0,         /*< nick=Failed >*/
	NM_AGENT_MANAGER_ERROR_PERMISSION_DENIED,  /*< nick=PermissionDenied >*/
	NM_AGENT_MANAGER_ERROR_INVALID_IDENTIFIER, /*< nick=InvalidIdentifier >*/
	NM_AGENT_MANAGER_ERROR_NOT_REGISTERED,     /*< nick=NotRegistered >*/
	NM_AGENT_MANAGER_ERROR_NO_SECRETS,         /*< nick=NoSecrets >*/
	NM_AGENT_MANAGER_ERROR_USER_CANCELED,      /*< nick=UserCanceled >*/
} NMAgentManagerError;

GQuark nm_agent_manager_error_quark (void);
#define NM_AGENT_MANAGER_ERROR (nm_agent_manager_error_quark ())

/**
 * NMConnectionError:
 * @NM_CONNECTION_ERROR_FAILED: unknown or unclassified error
 * @NM_CONNECTION_ERROR_SETTING_NOT_FOUND: the #NMConnection object
 *   did not contain the specified #NMSetting object
 * @NM_CONNECTION_ERROR_PROPERTY_NOT_FOUND: the #NMConnection did not contain the
 *   requested #NMSetting property
 * @NM_CONNECTION_ERROR_PROPERTY_NOT_SECRET: an operation which requires a secret
 *   was attempted on a non-secret property
 * @NM_CONNECTION_ERROR_MISSING_SETTING: the #NMConnection object is missing an
 *   #NMSetting which is required for its configuration. The error message will
 *   always be prefixed with "&lt;setting-name>: ", where "&lt;setting-name>" is the
 *   name of the setting that is missing.
 * @NM_CONNECTION_ERROR_INVALID_SETTING: the #NMConnection object contains an
 *   invalid or inappropriate #NMSetting. The error message will always be
 *   prefixed with "&lt;setting-name>: ", where "&lt;setting-name>" is the name of the
 *   setting that is invalid.
 * @NM_CONNECTION_ERROR_MISSING_PROPERTY: the #NMConnection object is invalid
 *   because it is missing a required property. The error message will always be
 *   prefixed with "&lt;setting-name>.&lt;property-name>: ", where "&lt;setting-name>" is
 *   the name of the setting with the missing property, and "&lt;property-name>" is
 *   the property that is missing.
 * @NM_CONNECTION_ERROR_INVALID_PROPERTY: the #NMConnection object is invalid
 *   because a property has an invalid value. The error message will always be
 *   prefixed with "&lt;setting-name>.&lt;property-name>: ", where "&lt;setting-name>" is
 *   the name of the setting with the invalid property, and "&lt;property-name>" is
 *   the property that is invalid.
 *
 * Describes errors that may result from operations involving a #NMConnection
 * or its #NMSettings.
 *
 * These errors may be returned directly from #NMConnection and #NMSetting
 * methods, or may be returned from D-Bus operations (eg on #NMClient or
 * #NMDevice), where they correspond to errors in the
 * "org.freedesktop.NetworkManager.Settings.Connection" namespace.
 */
typedef enum {
	NM_CONNECTION_ERROR_FAILED = 0,                   /*< nick=Failed >*/
	NM_CONNECTION_ERROR_SETTING_NOT_FOUND,            /*< nick=SettingNotFound >*/
	NM_CONNECTION_ERROR_PROPERTY_NOT_FOUND,           /*< nick=PropertyNotFound >*/
	NM_CONNECTION_ERROR_PROPERTY_NOT_SECRET,          /*< nick=PropertyNotSecret >*/
	NM_CONNECTION_ERROR_MISSING_SETTING,              /*< nick=MissingSetting >*/
	NM_CONNECTION_ERROR_INVALID_SETTING,              /*< nick=InvalidSetting >*/
	NM_CONNECTION_ERROR_MISSING_PROPERTY,             /*< nick=MissingProperty >*/
	NM_CONNECTION_ERROR_INVALID_PROPERTY,             /*< nick=InvalidProperty >*/
} NMConnectionError;

#define NM_CONNECTION_ERROR nm_connection_error_quark ()
GQuark nm_connection_error_quark (void);

/**
 * NMCryptoError:
 * @NM_CRYPTO_ERROR_FAILED: generic failure
 * @NM_CRYPTO_ERROR_INVALID_DATA: the certificate or key data provided
 *   was invalid
 * @NM_CRYPTO_ERROR_INVALID_PASSWORD: the password was invalid
 * @NM_CRYPTO_ERROR_UNKNOWN_CIPHER: the data uses an unknown cipher
 * @NM_CRYPTO_ERROR_DECRYPTION_FAILED: decryption failed
 * @NM_CRYPTO_ERROR_ENCRYPTION_FAILED: encryption failed
 *
 * Cryptography-related errors that can be returned from some nm-utils methods,
 * and some #NMSetting8021x operations.
 */
typedef enum {
	NM_CRYPTO_ERROR_FAILED = 0,
	NM_CRYPTO_ERROR_INVALID_DATA,
	NM_CRYPTO_ERROR_INVALID_PASSWORD,
	NM_CRYPTO_ERROR_UNKNOWN_CIPHER,
	NM_CRYPTO_ERROR_DECRYPTION_FAILED,
	NM_CRYPTO_ERROR_ENCRYPTION_FAILED,
} NMCryptoError;

#define NM_CRYPTO_ERROR nm_crypto_error_quark ()
GQuark nm_crypto_error_quark (void);

/**
 * NMDeviceError:
 * @NM_DEVICE_ERROR_FAILED: unknown or unclassified error
 * @NM_DEVICE_ERROR_CREATION_FAILED: NetworkManager failed to create the device
 * @NM_DEVICE_ERROR_INVALID_CONNECTION: the specified connection is not valid
 * @NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION: the specified connection is not
 *   compatible with this device.
 * @NM_DEVICE_ERROR_NOT_ACTIVE: the device does not have an active connection
 * @NM_DEVICE_ERROR_NOT_SOFTWARE: the requested operation is only valid on
 *   software devices.
 * @NM_DEVICE_ERROR_NOT_ALLOWED: the requested operation is not allowed at
 *   this time.
 * @NM_DEVICE_ERROR_SPECIFIC_OBJECT_NOT_FOUND: the "specific object" in the
 *   activation request (eg, the #NMAccessPoint or #NMWimaxNsp) was not
 *   found.
 * @NM_DEVICE_ERROR_VERSION_ID_MISMATCH: the version id did not match.
 * @NM_DEVICE_ERROR_MISSING_DEPENDENCIES: the requested operation could not
 *   be completed due to missing dependencies.
 *
 * Device-related errors.
 *
 * These errors may be returned directly from #NMDevice methods, or may be
 * returned from D-Bus operations (where they correspond to errors in the
 * "org.freedesktop.NetworkManager.Device" namespace).
 */
typedef enum {
	NM_DEVICE_ERROR_FAILED = 0,                /*< nick=Failed >*/
	NM_DEVICE_ERROR_CREATION_FAILED,           /*< nick=CreationFailed >*/
	NM_DEVICE_ERROR_INVALID_CONNECTION,        /*< nick=InvalidConnection >*/
	NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,   /*< nick=IncompatibleConnection >*/
	NM_DEVICE_ERROR_NOT_ACTIVE,                /*< nick=NotActive >*/
	NM_DEVICE_ERROR_NOT_SOFTWARE,              /*< nick=NotSoftware >*/
	NM_DEVICE_ERROR_NOT_ALLOWED,               /*< nick=NotAllowed >*/
	NM_DEVICE_ERROR_SPECIFIC_OBJECT_NOT_FOUND, /*< nick=SpecificObjectNotFound >*/
	NM_DEVICE_ERROR_VERSION_ID_MISMATCH,       /*< nick=VersionIdMismatch >*/
	NM_DEVICE_ERROR_MISSING_DEPENDENCIES,      /*< nick=MissingDependencies >*/
} NMDeviceError;

#define NM_DEVICE_ERROR nm_device_error_quark ()
GQuark nm_device_error_quark (void);

/**
 * NMManagerError:
 * @NM_MANAGER_ERROR_FAILED: unknown or unclassified error
 * @NM_MANAGER_ERROR_PERMISSION_DENIED: Permission denied.
 * @NM_MANAGER_ERROR_UNKNOWN_CONNECTION: The requested connection is not known.
 * @NM_MANAGER_ERROR_UNKNOWN_DEVICE: The requested device is not known.
 * @NM_MANAGER_ERROR_CONNECTION_NOT_AVAILABLE: The requested connection cannot be
 *   activated at this time.
 * @NM_MANAGER_ERROR_CONNECTION_NOT_ACTIVE: The request could not be completed
 *   because a required connection is not active.
 * @NM_MANAGER_ERROR_CONNECTION_ALREADY_ACTIVE: The connection to be activated was
 *   already active on another device.
 * @NM_MANAGER_ERROR_DEPENDENCY_FAILED: An activation request failed due to a
 *   dependency being unavailable.
 * @NM_MANAGER_ERROR_ALREADY_ASLEEP_OR_AWAKE: The manager is already in the requested
 *   sleep/wake state.
 * @NM_MANAGER_ERROR_ALREADY_ENABLED_OR_DISABLED: The network is already
 *   enabled/disabled.
 * @NM_MANAGER_ERROR_UNKNOWN_LOG_LEVEL: Unknown log level in SetLogging
 * @NM_MANAGER_ERROR_UNKNOWN_LOG_DOMAIN: Unknown log domain in SetLogging
 * @NM_MANAGER_ERROR_INVALID_ARGUMENTS: Invalid arguments for D-Bus request
 * @NM_MANAGER_ERROR_MISSING_PLUGIN: A plug-in was needed to complete the
 *   activation but is not available.
 *
 * Errors related to the main "network management" interface of NetworkManager.
 * These may be returned from #NMClient methods that invoke D-Bus operations on
 * the "org.freedesktop.NetworkManager" interface, and correspond to D-Bus
 * errors in that namespace.
 */
typedef enum {
	NM_MANAGER_ERROR_FAILED = 0,                  /*< nick=Failed >*/
	NM_MANAGER_ERROR_PERMISSION_DENIED,           /*< nick=PermissionDenied >*/
	NM_MANAGER_ERROR_UNKNOWN_CONNECTION,          /*< nick=UnknownConnection >*/
	NM_MANAGER_ERROR_UNKNOWN_DEVICE,              /*< nick=UnknownDevice >*/
	NM_MANAGER_ERROR_CONNECTION_NOT_AVAILABLE,    /*< nick=ConnectionNotAvailable >*/
	NM_MANAGER_ERROR_CONNECTION_NOT_ACTIVE,       /*< nick=ConnectionNotActive >*/
	NM_MANAGER_ERROR_CONNECTION_ALREADY_ACTIVE,   /*< nick=ConnectionAlreadyActive >*/
	NM_MANAGER_ERROR_DEPENDENCY_FAILED,           /*< nick=DependencyFailed >*/
	NM_MANAGER_ERROR_ALREADY_ASLEEP_OR_AWAKE,     /*< nick=AlreadyAsleepOrAwake >*/
	NM_MANAGER_ERROR_ALREADY_ENABLED_OR_DISABLED, /*< nick=AlreadyEnabledOrDisabled >*/
	NM_MANAGER_ERROR_UNKNOWN_LOG_LEVEL,           /*< nick=UnknownLogLevel >*/
	NM_MANAGER_ERROR_UNKNOWN_LOG_DOMAIN,          /*< nick=UnknownLogDomain >*/
	NM_MANAGER_ERROR_INVALID_ARGUMENTS,           /*< nick=InvalidArguments >*/
	NM_MANAGER_ERROR_MISSING_PLUGIN,              /*< nick=MissingPlugin >*/
} NMManagerError;

GQuark nm_manager_error_quark (void);
#define NM_MANAGER_ERROR (nm_manager_error_quark ())

/**
 * NMSecretAgentError:
 * @NM_SECRET_AGENT_ERROR_FAILED: unknown or unclassified error
 * @NM_SECRET_AGENT_ERROR_PERMISSION_DENIED: the caller (ie, NetworkManager) is
 *   not authorized to make this request
 * @NM_SECRET_AGENT_ERROR_INVALID_CONNECTION: the connection for which secrets
 *   were requested is invalid
 * @NM_SECRET_AGENT_ERROR_USER_CANCELED: the request was canceled by the user
 * @NM_SECRET_AGENT_ERROR_AGENT_CANCELED: the agent canceled the request
 *   because it was requested to do so by NetworkManager
 * @NM_SECRET_AGENT_ERROR_NO_SECRETS: the agent cannot find any secrets for this
 *   connection
 *
 * #NMSecretAgentError values are passed by secret agents back to NetworkManager
 * when they encounter problems retrieving secrets on behalf of NM. They
 * correspond to errors in the "org.freedesktop.NetworkManager.SecretManager"
 * namespace.
 *
 * Client APIs such as nm_client_activate_connection() will not see these error
 * codes; instead, the secret agent manager will translate them to the
 * corresponding #NMAgentManagerError codes.
 */
typedef enum {
	NM_SECRET_AGENT_ERROR_FAILED = 0,         /*< nick=Failed >*/
	NM_SECRET_AGENT_ERROR_PERMISSION_DENIED,  /*< nick=PermissionDenied >*/
	NM_SECRET_AGENT_ERROR_INVALID_CONNECTION, /*< nick=InvalidConnection >*/
	NM_SECRET_AGENT_ERROR_USER_CANCELED,      /*< nick=UserCanceled >*/
	NM_SECRET_AGENT_ERROR_AGENT_CANCELED,     /*< nick=AgentCanceled >*/
	NM_SECRET_AGENT_ERROR_NO_SECRETS,         /*< nick=NoSecrets >*/
} NMSecretAgentError;

GQuark nm_secret_agent_error_quark (void);
#define NM_SECRET_AGENT_ERROR         (nm_secret_agent_error_quark ())

/**
 * NMSettingsError:
 * @NM_SETTINGS_ERROR_FAILED: unknown or unclassified error
 * @NM_SETTINGS_ERROR_PERMISSION_DENIED: permission denied
 * @NM_SETTINGS_ERROR_NOT_SUPPORTED: the requested operation is not supported by any
 *   active settings backend
 * @NM_SETTINGS_ERROR_INVALID_CONNECTION: the connection was invalid
 * @NM_SETTINGS_ERROR_READ_ONLY_CONNECTION: attempted to modify a read-only connection
 * @NM_SETTINGS_ERROR_UUID_EXISTS: a connection with that UUID already exists
 * @NM_SETTINGS_ERROR_INVALID_HOSTNAME: attempted to set an invalid hostname
 * @NM_SETTINGS_ERROR_INVALID_ARGUMENTS: invalid arguments
 *
 * Errors related to the settings/persistent configuration interface of
 * NetworkManager.
 *
 * These may be returned from #NMClient methods that invoke D-Bus operations on
 * the "org.freedesktop.NetworkManager.Settings" interface, and correspond to
 * D-Bus errors in that namespace.
 */
typedef enum {
	NM_SETTINGS_ERROR_FAILED = 0,           /*< nick=Failed >*/
	NM_SETTINGS_ERROR_PERMISSION_DENIED,    /*< nick=PermissionDenied >*/
	NM_SETTINGS_ERROR_NOT_SUPPORTED,        /*< nick=NotSupported >*/
	NM_SETTINGS_ERROR_INVALID_CONNECTION,   /*< nick=InvalidConnection >*/
	NM_SETTINGS_ERROR_READ_ONLY_CONNECTION, /*< nick=ReadOnlyConnection >*/
	NM_SETTINGS_ERROR_UUID_EXISTS,          /*< nick=UuidExists >*/
	NM_SETTINGS_ERROR_INVALID_HOSTNAME,     /*< nick=InvalidHostname >*/
	NM_SETTINGS_ERROR_INVALID_ARGUMENTS,    /*< nick=InvalidArguments >*/
} NMSettingsError;

GQuark nm_settings_error_quark (void);
#define NM_SETTINGS_ERROR (nm_settings_error_quark ())

/**
 * NMVpnPluginError:
 * @NM_VPN_PLUGIN_ERROR_FAILED: unknown or unclassified error
 * @NM_VPN_PLUGIN_ERROR_STARTING_IN_PROGRESS: the plugin is already starting,
 *   and another connect request was received
 * @NM_VPN_PLUGIN_ERROR_ALREADY_STARTED: the plugin is already connected, and
 *   another connect request was received
 * @NM_VPN_PLUGIN_ERROR_STOPPING_IN_PROGRESS: the plugin is already stopping,
 *   and another stop request was received
 * @NM_VPN_PLUGIN_ERROR_ALREADY_STOPPED: the plugin is already stopped, and
 *   another disconnect request was received
 * @NM_VPN_PLUGIN_ERROR_WRONG_STATE: the operation could not be performed in
 *   this state
 * @NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS: the operation could not be performed as
 *   the request contained malformed arguments, or arguments of unexpected type.
 *   Usually means that one of the VPN setting data items or secrets was not of
 *   the expected type (ie int, string, bool, etc).
 * @NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED: a child process failed to launch
 * @NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION: the operation could not be performed
 *   because the connection was invalid.  Usually means that the connection's
 *   VPN setting was missing some required data item or secret.
 * @NM_VPN_PLUGIN_ERROR_INTERACTIVE_NOT_SUPPORTED: the operation could not be
 *   performed as the plugin does not support interactive operations, such as
 *   ConnectInteractive() or NewSecrets()
 *
 * Returned by the VPN service plugin to indicate errors. These codes correspond
 * to errors in the "org.freedesktop.NetworkManager.VPN.Error" namespace.
 **/
typedef enum {
	NM_VPN_PLUGIN_ERROR_FAILED,                    /*< nick=Failed >*/
	NM_VPN_PLUGIN_ERROR_STARTING_IN_PROGRESS,      /*< nick=StartingInProgress >*/
	NM_VPN_PLUGIN_ERROR_ALREADY_STARTED,           /*< nick=AlreadyStarted >*/
	NM_VPN_PLUGIN_ERROR_STOPPING_IN_PROGRESS,      /*< nick=StoppingInProgress >*/
	NM_VPN_PLUGIN_ERROR_ALREADY_STOPPED,           /*< nick=AlreadyStopped >*/
	NM_VPN_PLUGIN_ERROR_WRONG_STATE,               /*< nick=WrongState >*/
	NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,             /*< nick=BadArguments >*/
	NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,             /*< nick=LaunchFailed >*/
	NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,        /*< nick=InvalidConnection >*/
	NM_VPN_PLUGIN_ERROR_INTERACTIVE_NOT_SUPPORTED, /*< nick=InteractiveNotSupported >*/
} NMVpnPluginError;

#define NM_VPN_PLUGIN_ERROR      (nm_vpn_plugin_error_quark ())
GQuark nm_vpn_plugin_error_quark    (void);

#endif /* __NM_ERRORS_H__ */
