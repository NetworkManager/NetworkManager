g_ir_compiler = find_program('g-ir-compiler')

girs = [
  'NetworkManager',
  'NMClient',
]

resource_data = []

foreach gir: girs
  gir_typelib = gir + '.typelib'

  resource_data += custom_target(
    gir_typelib,
    input: gir + '.gir',
    output: gir_typelib,
    command: [g_ir_compiler, '@INPUT@', '-o', '@OUTPUT@'],
  )
endforeach

resource = 'typelibs'

libnm_utils_sources += gnome.compile_resources(
  resource,
  resource + '.gresource.xml',
  source_dir: '.',
  dependencies: resource_data,
  extra_args: '--manual-register',
  export: true,
)
