# c-stdaux - Auxiliary macros and functions for the C standard library

## CHANGES WITH 1.4.0:

        * New compiler-builtin c_assume_aligned() allows hinting alignment
          to the compiler and thus improving code generation. For targets
          without such builtins, the function will be a no-op.

        * A new set of memory-load operations is added: c_load_*()
          This includes support for reading unaligned & aligned memory,
          big-endian & little-endian data, and various standard sizes.
          The helpers are basically a pointer cast to `uintX_t*` and a
          dereference operation, but they guarantee that strict aliasing
          rules, as well as alignment requirements are followed.

        Contributions from: David Rheinsberg, Jan Engelhardt, Tom Gundersen

        - Dußlingen, 2023-01-12

## CHANGES WITH 1.3.0:

        * Microsoft Windows is now supported as a target platform.

        * The `C_COMPILER_*` and `C_OS_*` pre-processor constants now
          allow identifying the used compiler as well as the target OS.

        * The new `_c_always_inline_` annotation allows telling compilers
          to inline a function unless technically not possible.

        * Split c-stdaux.h into modules and include them from the root
          header for backwards compatibility. Inclusion of the new modules
          is guarded by the `C_COMPILER_*` and `C_OS_*` macros to prevent
          them from being used on unspported platforms. A direct include
          of the respective modules allows overriding that behavior.

          The new modules provide the same functionality as before on the
          previously supported linux platforms. With the support of other
          platforms, individual modules might not be available, or generic
          functions might provide a stub that provides the same runtime
          behavior, but possibly with fewer diagnostics.

        * Rework `c_assert()` to avoid context-expressions and instead use
          the ternary-operator to check for the assertion.

        * Improve `c_{un,}likely()` to support constant-folding as well as
          -Wparantheses diagnostics if supported by the compiler. This adds
          `_c_boolean_expr_()` as a helper to achieve this.

        Contributions from: David Rheinsberg, Thomas Haller

        - Dußlingen, 2022-12-15

## CHANGES WITH 1.2.0:

        * Add c_memcmp() as a safe wrapper around memcmp(3) that supports
          empty arenas as NULL pointers.

        * Add an API documentation renderer based on the sphinx docutils
          suite. The documentation is available on readthedocs.org.

        * Drop stdatomic.h from the public includes. This was not used by
          any of the dependent projects, but breaks builds on older GCC
          compilers. While this is technically an API break, no breakage
          has been discovered in our tests, and thus we deemed it reasonable
          to proceed without version bump.

        Contributions from: David Rheinsberg, Thomas Haller

        - Dußlingen, 2022-07-22

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
