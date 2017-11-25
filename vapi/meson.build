gnome.generate_vapi(
  'libnm',
  sources: libnm_gir[0],
  packages: 'gio-2.0',
  install: true
)

if enable_libnm_glib
  packages = [
    'dbus-glib-1',
    'gio-2.0'
  ]

  libnm_util_vapi = gnome.generate_vapi(
    'libnm-util',
    sources: libnm_util_gir[0],
    packages: packages,
    install: true
  )

  packages += libnm_util_vapi

  gnome.generate_vapi(
    'libnm-glib',
    sources: libnm_glib_gir[0],
    packages: packages,
    install: true
  )
endif
