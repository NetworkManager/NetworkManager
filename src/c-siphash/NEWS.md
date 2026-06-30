# c-siphash - Streaming-capable SipHash Implementation

## CHANGES WITH 1.1.0:

        * Support MacOS and Windows builds.

        * Support SipHash variants other than SipHash24 by parameterizing
          the N and M variables of SipHash.

        * Update the c-stdaux dependency to provide the new build variables
          and thus allow linking through pkg-config.

        Contributions from: Daniele Nicolodi, David Rheinsberg

        - Dußlingen, 2023-12-12

## CHANGES WITH 1.0.0:

        * Initial release of c-siphash.

        Contributions from: David Rheinsberg, Tom Gundersen

        - Brno, 2022-06-22
