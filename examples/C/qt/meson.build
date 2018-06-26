examples = [
  ['add-connection-wired', []],
  ['list-connections', []],
  ['change-ipv4-addresses', []]
]

incs = [
  top_inc,
  libnm_core_inc
]

qt_core_dep = dependency('QtCore', version: '>= 4')

deps = [
  dbus_dep,
  qt_core_dep,
  dependency('QtDBus'),
  dependency('QtNetwork')
]

moc = find_program('moc-qt4', required: false)
if not moc.found()
  moc = qt_core_dep.get_pkgconfig_variable('moc_location')
endif

example = 'monitor-nm-running'
output = example + '.moc'

example_moc = custom_target(
  output,
  input: example + '.cpp',
  output: output,
  command: [moc, '-i', '@INPUT@', '-o', '@OUTPUT@']
)

examples += [[example, [example_moc]]]

foreach example: examples
  executable(
    example[0],
    example[0] + '.cpp',
    include_directories: incs,
    dependencies: deps,
    link_depends: example[1]
  )
endforeach
