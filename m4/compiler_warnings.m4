AC_DEFUN([NM_COMPILER_WARNINGS],
[AC_ARG_ENABLE(more-warnings,
	AS_HELP_STRING([--enable-more-warnings], [Possible values: no/yes/error]),
	set_more_warnings="$enableval",set_more_warnings=error)
AC_MSG_CHECKING(for more warnings)
if test "$GCC" = "yes" -a "$set_more_warnings" != "no"; then
	AC_MSG_RESULT(yes)
	CFLAGS_SAVED="$CFLAGS"
	CFLAGS_MORE_WARNINGS="-Wall -std=gnu89"

	dnl clang only warns about unknown warnings, unless
	dnl called with "-Werror=unknown-warning-option"
	dnl Test if the compiler supports that, and if it does
	dnl attach it to the CFLAGS.
	CFLAGS_EXTRA="-Werror=unknown-warning-option"
	CFLAGS="$CFLAGS_MORE_WARNINGS $CFLAGS_EXTRA $CFLAGS_SAVED"
	AC_TRY_COMPILE([], [],
		has_option=yes,
		has_option=no,)
	if test $has_option = no; then
		CFLAGS_EXTRA=
	fi
	unset has_option

	for option in -Wshadow -Wmissing-declarations -Wmissing-prototypes \
		      -Wdeclaration-after-statement -Wformat-security \
		      -Wfloat-equal -Wno-unused-parameter -Wno-sign-compare \
		      -Wstrict-prototypes \
		      -fno-strict-aliasing -Wno-unused-but-set-variable \
		      -Wundef -Wimplicit-function-declaration \
		      -Wpointer-arith -Winit-self \
		      -Wmissing-include-dirs -Wno-pragmas; do
		dnl GCC 4.4 does not warn when checking for -Wno-* flags (https://gcc.gnu.org/wiki/FAQ#wnowarning)
		CFLAGS="$CFLAGS_MORE_WARNINGS $CFLAGS_EXTRA $(printf '%s' "$option" | sed 's/^-Wno-/-W/')  $CFLAGS_SAVED"
		AC_MSG_CHECKING([whether gcc understands $option])
		AC_TRY_COMPILE([], [],
			has_option=yes,
			has_option=no,)
		if test $has_option != no; then
			CFLAGS_MORE_WARNINGS="$CFLAGS_MORE_WARNINGS $option"
		fi
		AC_MSG_RESULT($has_option)
		unset has_option
	done
	unset option
	unset CFLAGS_EXTRA
	if test "x$set_more_warnings" = xerror; then
		CFLAGS_MORE_WARNINGS="$CFLAGS_MORE_WARNINGS -Werror"
	fi
	CFLAGS="$CFLAGS_MORE_WARNINGS $CFLAGS_SAVED"
	unset CFLAGS_SAVED
else
	AC_MSG_RESULT(no)
fi
])
