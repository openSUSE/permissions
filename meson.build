project('permissions', 'cpp',
  license: 'gpl2',
  default_options: ['buildtype=debugoptimized', 'cpp_std=c++17', 'warning_level=3', 'werror=true'])


foreach warning: [ 'duplicated-cond', 'duplicated-branches',
    'logical-op', 'null-dereference', 'double-promotion', 'shadow',  'format=2',
    'sign-conversion']
  add_global_arguments('-W' + warning, language: 'cpp')
endforeach

foreach define: ['_GNU_SOURCE', '_LARGEFILE_SOURCE', '_FILE_OFFSET_BITS=64']
  add_global_arguments('-D' + define, language: 'cpp')
endforeach

if get_option('testbuild')
  # NOTE: meson complains that we should consider the built-in 'sanitizers'
  # option which would need to be passed to the project() declaration. But
  # then we cannot make this dependent on the 'testbuild' option.
  # The only other way would be explicitly passing `-Db_sanitize=address,...
  # on the command line.
  foreach sanitize: ['address', 'pointer-compare', 'pointer-subtract', 'undefined']
    add_global_arguments('-fsanitize=' + sanitize, language: 'cpp')
    add_global_link_arguments('-fsanitize=' + sanitize, language: 'cpp')
  endforeach
endif

executable('chkstat', [
    'src/chkstat.cpp',
    'src/cmdline.cpp',
    'src/entryproc.cpp',
    'src/formatting.cpp',
    'src/profparser.cpp',
    'src/utility.cpp',
    'src/varexp.cpp'
  ],
  dependencies: [dependency('libcap'), dependency('tclap')],
  # link statically against libstdc++. since some people are afraid of ABI
  # changes in this area and since permissions is a base package in SUSE this
  # protects us from such potential breakage at the expense of some increased
  # binary size
  link_args: ['-static-libstdc++'],
  install: true
)

install_man('man/chkstat.8')
install_man('man/permissions.5')
install_data(sources: 'etc/sysconfig.security', install_dir: 'share/fillup-templates')
install_data(sources: 'zypper-plugin/permissions.py', install_dir: 'lib/zypp/plugins/commit')
install_data(sources: ['etc/variables.conf', 'etc/permissions', 'profiles/permissions.easy', 'profiles/permissions.secure', 'profiles/permissions.paranoid'], install_dir: 'share/permissions')
install_data(sources: 'etc/permissions.local', install_dir: '/etc')
install_subdir('permissions.d', install_dir: 'share/permissions')
