# test-cert.p12 created with:
#
# openssl pkcs12 -export \
# -in test_key_and_cert.pem \
# -inkey test_key_and_cert.pem \
# -certfile test_ca_cert.pem \
# -name "test-pkcs12" \
# -out test-cert.p12

enum_types = 'nm-core-tests-enum-types'

enum = gnome.mkenums(
  enum_types,
  sources: 'test-general-enums.h',
  identifier_prefix: nm_id_prefix,
  c_template: enum_types + '.c.template',
  h_template: enum_types + '.h.template'
)

test_units = [
  'test-compare',
  'test-crypto',
  'test-general',
  'test-keyfile',
  'test-secrets',
  'test-setting',
  'test-settings-defaults'
]

incs = [
  top_inc,
  shared_inc,
  libnm_core_inc
]

test_cert_dir = join_paths(meson.current_source_dir(), 'certs')

cflags = '-DTEST_CERT_DIR="@0@"'.format(test_cert_dir)

foreach test_unit: test_units
  exe = executable(
    'libnm-core-' + test_unit,
    [test_unit + '.c'] + enum,
    include_directories: incs,
    dependencies: glib_dep,
    c_args: cflags,
    link_with: libnm_core
  )

  test(test_unit, exe)
endforeach
