#
# Global Project Setup
#

project(
        'c-stdaux',
        'c',
        default_options: [
                'c_std=c11'
        ],
        license: 'Apache',
        meson_version: '>=0.60.0',
        version: '1.4.0',
)
major = meson.project_version().split('.')[0]
project_description = 'Auxiliary macros and functions for the C standard library'

mod_pkgconfig = import('pkgconfig')

#
# CFLAGS
#
# We have a set of compiler flags for GCC and CLANG which adjust their warnings
# and behavior to our coding-style.
#
# This variable is exported to dependent projects via meson for them to use as
# well. Since these exports are limited to strings, we need to be careful that
# the individual entries do not contain spaces (see the assertion below).
#

cflags = meson.get_compiler('c').get_supported_arguments(
        # Enable GNU features of our dependencies. See feature_test_macros(7).
        '-D_GNU_SOURCE',

        # Prevent CLANG from complaining that alignof-expressions are GNU-only.
        '-Wno-gnu-alignof-expression',
        # Never complain about *MAYBE* uninit variables. This is very flaky and
        # produces bogus results with LTO.
        '-Wno-maybe-uninitialized',
        # Do not complain about unknown GCC/CLANG warnings.
        '-Wno-unknown-warning-option',
        # There is no standardized way to mark unused arguments, so never
        # complain about them.
        '-Wno-unused-parameter',

        # Preprocessor evaluations often lead to warnings about comparisons
        # that are always true/false. Make sure they do not break a build but
        # keep them on for diagnostics.
        '-Wno-error=type-limits',
        # As we use designated field-initializers, this warning should never
        # trigger, but still does on GCC in combination with some other
        # preprocessor checks. Lets just make sure it does not break builds.
        '-Wno-error=missing-field-initializers',

        # Warn if we ever use `__DATE__` and similar in our build. We want
        # reproducible builds.
        '-Wdate-time',
        # We strictly follow decl-before-statements, so check it.
        '-Wdeclaration-after-statement',
        # More strict logical-op sanity checks.
        '-Wlogical-op',
        # Loudly complain about missing include-directories.
        '-Wmissing-include-dirs',
        # We want hints about noreturn functions, so warn about them.
        '-Wmissing-noreturn',
        # Warn if an extern-decl is inside a function. We want imports as
        # global attributes, never as local ones.
        '-Wnested-externs',
        # Warn about redundant declarations. We want declarations in headers
        # and want them to be unique.
        '-Wredundant-decls',
        # Warn about shadowed variables so we do not accidentally override
        # variables of parent scopes and thus confuse macros.
        '-Wshadow',
        # Warn about aliasing violations. Level-3 produces the least false
        # positives, but is the slowest. Force it to avoid breaking -Werror
        # builds.
        '-Wstrict-aliasing=3',
        # Suggest 'noreturn' attributes. They are useful, we want them!
        '-Wsuggest-attribute=noreturn',
        # Warn about undefined identifiers in preprocessor conditionals.
        '-Wundef',
        # Make sure literal strings are considered 'const'.
        '-Wwrite-strings',
)
assert(not ''.join(cflags).contains(' '), 'Malformed compiler flags.')
add_project_arguments(cflags, language: 'c')

#
# Version Scripts
#

use_version_scripts = get_option('version-scripts')
if use_version_scripts == 'auto'
        use_version_scripts = meson.get_compiler('c').has_link_argument(
                '-Wl,--version-script=' + (meson.current_source_dir() / 'src/libcstdaux.sym')
        ) ? 'yes' : 'no'
endif

#
# Subdir Delegation
#

subdir('src')

#
# Meson Subproject Configuration
#

meson.override_dependency('libcstdaux-'+major, libcstdaux_dep, static: true)
