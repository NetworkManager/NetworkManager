# SPDX-License-Identifier: LGPL-2.1-or-later

libnm_platform = static_library(
  'nm-platform',
  sources: [
    'nm-linux-platform.c',
    'nm-netlink.c',
    'nm-platform-utils.c',
    'nm-platform.c',
    'nmp-base.c',
    'nmp-global-tracker.c',
    'nmp-netns.c',
    'nmp-object.c',
    'nmp-plobj.c',
    'wifi/nm-wifi-utils-nl80211.c',
    'wifi/nm-wifi-utils.c',
    'wpan/nm-wpan-utils.c',
  ] + (enable_wext ? [ 'wifi/nm-wifi-utils-wext.c' ] : []),
  include_directories: [
    src_inc,
    top_inc,
  ],
  dependencies: [
    glib_dep,
    libudev_dep,
  ],
)
