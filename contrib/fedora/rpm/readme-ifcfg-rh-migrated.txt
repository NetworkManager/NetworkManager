NetworkManager was built to automatically migrate connection profiles in
this directory to equivalent ones in keyfile format in directory
/etc/NetworkManager/system-connections.

You can check whether the migration is enabled via:

 $ NetworkManager --print-config | grep migrate-ifcfg-rh

In case it is enabled, all files in this directory are migrated at startup.

To inspect where your connection files are currently stored use:

 $ nmcli -f name,uuid,filename connection

Background
==========

The ifcfg format is deprecated and will be removed in future releases. For
more information see:

https://lists.freedesktop.org/archives/networkmanager/2023-May/000103.html

Connection profiles in keyfile format have many benefits. For example, this
format is INI file-based and can easily be parsed and generated.

Each section in NetworkManager keyfiles corresponds to a NetworkManager
setting name as described in the nm-settings(5) and nm-settings-keyfile(5)
man pages. Each key-value pair in a section is one of the properties listed
in the settings specification of the man page.

How to keep using ifcfg
=======================

If you want to keep using connection profiles in ifcfg format, you need to:

 - disable the automatic migration to keyfile by setting
   "migrate-ifcfg-rh=false" in the [main] section of NetworkManager
   configuration;

 - optionally, set "plugins=ifcfg-rh" in the [main] section of
   NetworkManager configuration so that new profiles are created in ifcfg
   format.

At this point, you can migrate all your files back via

  nmcli connection migrate --plugin ifcfg-rh

Or, if you prefer to migrate only specific connections:

  nmcli connection migrate --plugin ifcfg-rh <profile_name|UUID>

Note that some connection types are not supported by the ifcfg plugin.
