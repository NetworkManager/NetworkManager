# n-acd - IPv4 Address Conflict Detection

## CHANGES WITH 2:

        * All public destructors now include a variant that returns `void`.
          This was requested for easier integration with `glib` and friends.
          Similar to the `cleanup` variants, these variants are denoted by a
          single-character function-name suffix. E.g., `n_acd_freev()`

        * A fallback to `CLOCK_MONOTONIC` is now provided in case
          `CLOCK_BOOTTIME` is not supported by the kernel. Note that this is in
          no way signalled through the API, so if timers should follow the
          `BOOTTIME` rather than monotonic clock, a kernel with this clock is
          required.

        * The `c-sundry` dependency is no longer needed.

        * The `transport` configuration property is now mandatory for
          `n_acd_new()`. It defaulted to `ETHERNET` before, by mistake.

        * In-source documentation for the public API is now provided.

        Contributions from: Beniamino Galvani, David Herrmann, David
                            Rheinsberg, Thomas Haller, Tom Gundersen

        - Tübingen, 2019-03-20

## CHANGES WITH 1:

        * Initial release of n-acd. This project implements the IPv4 Address
          Conflict Detection standard as defined in RFC-5227. The state machine
          is implemented in a shared library and provides a stable ISO-C11 API.
          The implementation is linux-only and relies heavily on the API
          behavior of recent linux kernel releases.

        * Compared to the pre-releases, this release supports many parallel
          probes on a single n-acd context. This reduces the number of
          allocated network resources to O(1), based on the number of running
          parallel probes.

        * The n-acd project is now dual-licensed: ASL-2.0 and LGPL-2.1+

        Contributions from: Beniamino Galvani, David Herrmann, Thomas Haller,
                            Tom Gundersen

        - Tübingen, 2018-08-08
