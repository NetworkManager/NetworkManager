# c-stdaux - Auxiliary macros and functions for the C standard library

## CHANGES WITH 1.1.0:

        * Add c_memcpy() as a safe wrapper around memcpy(3) that supports
          empty arenas as NULL pointers.

        * Support building on MacOS-X.

        * Rework the apidoc comments and properly document the entire API.

        * Export 'version-scripts' configuration variable alongside the
          existing 'cflags' variable. It defines whether c-stdaux was built
          with GNU-linker version-scripts, or not. Dependent projects can
          use this to decide whether to use version-scripts or not.
          Additionally, the new 'version-scripts' meson-option allows
          specifying whether to use version-scripts, auto-detect whether to
          enable it, or disable it.

        * Fix the export of `cflags` to also be exported in pkg-config, not
          just meson subprojects.

        * Avoid NULL-pointers in compile-time macros. This silences possible
          false-positives from code sanitizers that otherwise trip over the
          NULL pointer dereferences.

        Contributions from: David Rheinsberg, Evgeny Vereshchagin

        - Brno, 2022-06-22

## CHANGES WITH 1.0.0:

        * Initial release of c-stdaux.

        Contributions from: David Rheinsberg, Lorenzo Arena, Michele Dionisio,
                            Yuri Chornoivan

        - Dußlingen, 2022-05-12
