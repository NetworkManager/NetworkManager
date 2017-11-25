version_conf = configuration_data()
version_conf.set('VERSION', nm_version)

version_xml = 'version.xml'

subdir('libnm')
subdir('api')

if enable_libnm_glib
  subdir('libnm-util')
  subdir('libnm-glib')
endif
