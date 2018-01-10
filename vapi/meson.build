gnome.generate_vapi(
  libnm_name,
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
    libnm_util_name,
    sources: libnm_util_gir[0],
    packages: packages,
    install: true
  )

  packages += libnm_util_vapi

  gnome.generate_vapi(
    libnm_glib_name,
    sources: libnm_glib_gir[0],
    packages: packages,
    install: true
  )
endif
