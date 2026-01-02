# SPDX-License-Identifier: LGPL-2.1+

# Ripped from systemd: https://github.com/systemd/systemd/pull/20429

if not enable_clat
  subdir_done()
endif

bpf_compiler = get_option('bpf-compiler')
clang_found = false
clang_supports_bpf = false
bpf_gcc_found = false
bpftool_strip = false

if bpf_compiler == 'clang' or bpf_compiler == 'auto'
  # Support 'versioned' clang/llvm-strip binaries, as seen on Debian/Ubuntu
  # (like clang-10/llvm-strip-10)
  if meson.is_cross_build() or cc.get_id() != 'clang' or cc.cmd_array()[0].contains('afl-clang') or cc.cmd_array()[0].contains('hfuzz-clang')
    r = find_program('clang',
                     version : '>= 10.0.0')
    clang_found = r.found()
    if clang_found
      if meson.version().version_compare('>= 0.55')
        clang = r.full_path()
      else
        clang = r.path()
      endif
    endif
  else
    clang_found = true
    clang = cc.cmd_array()
  endif

  if clang_found
    # Check if 'clang -target bpf' is supported.
    clang_supports_bpf = run_command(clang, '-target', 'bpf', '--print-supported-cpus', check : false).returncode() == 0
  endif
elif bpf_compiler == 'gcc' or bpf_compiler == 'auto'
  bpf_gcc = find_program('bpf-gcc',
                         'bpf-none-gcc',
                         'bpf-unknown-none-gcc',
                         version : '>= 13.1.0')
  bpf_gcc_found = bpf_gcc.found()
endif

if bpf_compiler == 'auto'
  if clang_supports_bpf and bpf_gcc_found
    # Both supported, prefer the one matching our compiler:
    if cc.get_id() == 'gcc'
      bpf_compiler = 'gcc'
    else
      # Default to clang if we don't know this compiler
      bpf_compiler = 'clang'
    endif
  elif clang_supports_bpf
    bpf_compiler = 'clang'
  elif bpf_gcc_found
    bpf_compiler = 'clang'
  endif
endif

if clang_supports_bpf or bpf_gcc_found
  # Debian installs this in /usr/sbin/ which is not in $PATH.
  # We check for 'bpftool' first, honouring $PATH, and in /usr/sbin/ for Debian.
  # We use 'bpftool gen object' subcommand for bpftool strip, it was added by d80b2fcbe0a023619e0fc73112f2a02c2662f6ab (v5.13).
  bpftool = find_program('bpftool',
                         '/usr/sbin/bpftool',
                         required : bpf_compiler == 'gcc',
                         version : bpf_compiler == 'gcc' ? '>= 7.0.0' : '>= 5.13.0')

  if bpftool.found()
    bpftool_strip = true
  elif bpf_compiler == 'clang'
    # We require the 'bpftool gen skeleton' subcommand, it was added by 985ead416df39d6fe8e89580cc1db6aa273e0175 (v5.6).
    bpftool = find_program('bpftool',
                           '/usr/sbin/bpftool',
                           required : true,
                           version : '>= 5.6.0')
  endif

  # We use `llvm-strip` as a fallback if `bpftool gen object` strip support is not available.
  if not bpftool_strip and bpftool.found() and clang_supports_bpf
    if not meson.is_cross_build()
      llvm_strip_bin = run_command(clang, '--print-prog-name', 'llvm-strip',
                                   check : true).stdout().strip()
    else
      llvm_strip_bin = 'llvm-strip'
    endif
    llvm_strip = find_program(llvm_strip_bin,
                              required : true,
                              version : '>= 10.0.0')
  endif
else
  error('clat support was enabled but couldn\'t find a suitable BPF compiler!')
endif

bpf_clang_flags = [
  '-std=gnu17',
  '-Wunused',
  '-Wimplicit-fallthrough',
  '-Wno-compare-distinct-pointer-types',
  '-fno-stack-protector',
  '-O2',
  '-target',
  'bpf',
  '-g',
  '-c',
]

bpf_gcc_flags = [
  '-std=gnu17',
  '-Wunused',
  '-Wimplicit-fallthrough',
  '-fno-stack-protector',
  '-fno-ssa-phiopt',
  '-O2',
  '-mcpu=v3',
  '-mco-re',
  '-gbtf',
  '-c',
]

clang_arch_flag = '-D__@0@__'.format(host_machine.cpu_family())

libbpf_include_dir = dependency('libbpf').get_variable(pkgconfig : 'includedir')

# Generate defines that are appropriate to tell the compiler what architecture
# we're compiling for. By default we just map meson's cpu_family to __<cpu_family>__.
# This dictionary contains the exceptions where this doesn't work.
#
# C.f. https://mesonbuild.com/Reference-tables.html#cpu-families
# and src/basic/missing_syscall_def.h.
cpu_arch_defines = {
  'ppc'         : ['-D__powerpc__', '-D__TARGET_ARCH_powerpc'],
  'ppc64'       : ['-D__powerpc64__', '-D__TARGET_ARCH_powerpc', '-D_CALL_ELF=2'],
  'riscv32'     : ['-D__riscv', '-D__riscv_xlen=32', '-D__TARGET_ARCH_riscv'],
  'riscv64'     : ['-D__riscv', '-D__riscv_xlen=64', '-D__TARGET_ARCH_riscv'],
  'x86'         : ['-D__i386__', '-D__TARGET_ARCH_x86'],
  's390x'       : ['-D__s390__', '-D__s390x__', '-D__TARGET_ARCH_s390'],

  # For arm, assume hardware fp is available.
  'arm'         : ['-D__arm__', '-D__ARM_PCS_VFP', '-D__TARGET_ARCH_arm'],
  'loongarch64' : ['-D__loongarch__', '-D__loongarch_grlen=64', '-D__TARGET_ARCH_loongarch']
}

bpf_arch_flags = cpu_arch_defines.get(host_machine.cpu_family(),
                                      ['-D__@0@__'.format(host_machine.cpu_family())])
if bpf_compiler == 'gcc'
  bpf_arch_flags += ['-m' + host_machine.endian() + '-endian']
endif

bpf_o_unstripped_cmd = []
if bpf_compiler == 'clang'
  bpf_o_unstripped_cmd += [
    clang,
    bpf_clang_flags,
    bpf_arch_flags,
  ]
elif bpf_compiler == 'gcc'
  bpf_o_unstripped_cmd += [
    bpf_gcc,
    bpf_gcc_flags,
    bpf_arch_flags,
  ]
endif

bpf_o_unstripped_cmd += ['-I.']

if cc.get_id() == 'gcc' or meson.is_cross_build()
  if cc.get_id() != 'gcc'
    warning('Cross compiler is not gcc. Guessing the target triplet for bpf likely fails.')
  endif
  target_triplet_cmd = run_command(cc.cmd_array(), '-print-multiarch', check: false)
else
  # clang does not support -print-multiarch (D133170) and its -dump-machine
  # does not match multiarch. Query gcc instead.
  target_triplet_cmd = run_command('gcc', '-print-multiarch', check: false)
endif

if target_triplet_cmd.returncode() == 0
  target_triplet = target_triplet_cmd.stdout().strip()
  bpf_o_unstripped_cmd += [
    '-isystem',
    '/usr/include/@0@'.format(target_triplet)
  ]
endif

bpf_o_unstripped_cmd += [
  '-idirafter',
  libbpf_include_dir,
  '@INPUT@',
  '-o',
  '@OUTPUT@'
]

if bpftool_strip
  bpf_o_cmd = [
    bpftool,
    'gen',
    'object',
    '@OUTPUT@',
    '@INPUT@'
  ]
elif bpf_compiler == 'clang'
  bpf_o_cmd = [
    llvm_strip,
    '-g',
    '@INPUT@',
    '-o',
    '@OUTPUT@'
  ]
endif

skel_h_cmd = [
  bpftool,
  'g',
  's',
  '@INPUT@'
]

clat_bpf_o_unstripped = custom_target(
  'clat.bpf.unstripped.o',
  input : 'clat.bpf.c',
  output : 'clat.bpf.unstripped.o',
  command : bpf_o_unstripped_cmd)

clat_bpf_o = custom_target(
  'clat.bpf.o',
  input : clat_bpf_o_unstripped,
  output : 'clat.bpf.o',
  command : bpf_o_cmd)

clat_skel_h = custom_target(
  'clat.skel.h',
  input : clat_bpf_o,
  output : 'clat.skel.h',
  command : skel_h_cmd,
  capture : true)

