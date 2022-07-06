# c-rbtree - Intrusive Red-Black Tree Collection

## CHANGES WITH 3.1.0:

        * Add 'ptrace' build option to enable running tests using 'ptrace'
          to verify extended execution properties. This option should not
          be used in setups where 'ptrace' cannot be employed (like running
          under gdb or valgrind). This option only affects the test-suite.

        * meson-0.60.0 is now the minimum required meson version.

        Contributions from: David Rheinsberg, Evgeny Vereshchagin

        - Brno, 2022-06-22

## CHANGES WITH 3:

        * Add more helpers. Add both a collection of iteratiors and helpers
          for initializing a tree and checking if a tree is empty, without
          explicitly accessing the data structure.

        Contributions from: David Herrmann

        - Berlin, 2017-08-13

## CHANGES WITH 2:

        * Relicense as ASL-2.0 to make c-rbtree useful for more projects. All
          code is now fully available under the ASL-2.0. Nothing is covered by
          the LGPL, anymore.

        * Switch build-system from Autotools to Meson. This simplifies the code
          base significantly. The Meson Build System is now used by many other
          projects, including GStreamer, Weston, and several Gnome packages.
          See http://mesonbuild.com/ for more information.

        Contributions from: David Herrmann

        - Berlin, 2016-12-14

## CHANGES WITH 1:

        * Initial release of c-rbtree.

        * This projects provides an RB-Tree API, that is fully implemented in
          ISO-C11 and has no external dependencies. Furthermore, tree
          traversal, memory allocations, and key comparisons are completely
          controlled by the API user. The implementation only provides the
          RB-Tree specific rebalancing and coloring.

        Contributions from: David Herrmann, Kay Sievers, Tom Gundersen

        - Berlin, 2016-08-31
