AC_DEFUN([_NM_COMPILER_FLAG], [
	CFLAGS_SAVED="$CFLAGS"
	CFLAGS="$CFLAGS $GLIB_CFLAGS -Werror $1"
	AC_MSG_CHECKING([whether $1 works as expected])

	AC_COMPILE_IFELSE([AC_LANG_SOURCE([[]])], [
		AC_COMPILE_IFELSE([AC_LANG_SOURCE([[$2]])], [
			AC_MSG_RESULT(yes)
			CFLAGS="$CFLAGS_SAVED"
			$3
		],[
			AC_MSG_RESULT(no)
			CFLAGS="$CFLAGS_SAVED"
			$4
		])
	],[
		AC_MSG_RESULT(not supported)
		CFLAGS="$CFLAGS_SAVED"
	])
])

dnl Check whether a particular compiler flag is supported,
dnl append it to the specified variable if the check succeeds.
dnl NM_COMPILER_FLAG([ENV-VAR], [FLAG], [ACTION-IF-SUPPORTED], [ACTION-IF-NOT-SUPPORTED])
AC_DEFUN([NM_COMPILER_FLAG], [
        _NM_COMPILER_FLAG([$2], [], [
		eval "AS_TR_SH([$1])='$$1 $2'"
		$3
	], [$4])
])

dnl Check whether a particular warning is not emitted with code provided,
dnl append an option to disable the warning to a specified variable if the check fails.
dnl NM_COMPILER_WARNING([ENV-VAR], [WARNING], [C-SNIPPET])
AC_DEFUN([NM_COMPILER_WARNING], [
        _NM_COMPILER_FLAG([-W$2], [$3], [eval "AS_TR_SH([$1])='$$1 -W$2'"], [eval "AS_TR_SH([$1])='$$1 -Wno-$2'"])
])

dnl NM_COMPILER_WARNINGS([ENV-VAR], [MORE-WARNINGS])
AC_DEFUN([NM_COMPILER_WARNINGS],
[AC_ARG_ENABLE(more-warnings,
	AS_HELP_STRING([--enable-more-warnings], [Possible values: no/yes/error]),
	set_more_warnings="$enableval",set_more_warnings=$2)
AC_MSG_CHECKING(for more warnings)
if test "$GCC" = "yes" -a "$set_more_warnings" != "no"; then
	AC_MSG_RESULT(yes)

	dnl This is enabled in clang by default, makes little sense,
	dnl and causes the build to abort with -Werror.
	CFLAGS_SAVED="$CFLAGS"
	CFLAGS="$CFLAGS -Qunused-arguments"
	AC_COMPILE_IFELSE([AC_LANG_SOURCE([])], eval "AS_TR_SH([$1])='$$1 -Qunused-arguments'", [])
	CFLAGS="$CFLAGS_SAVED"

	dnl clang only warns about unknown warnings, unless
	dnl called with "-Werror=unknown-warning-option"
	dnl Test if the compiler supports that, and if it does
	dnl attach it to the CFLAGS.
	NM_COMPILER_WARNING([$1], [unknown-warning-option], [])

	CFLAGS_MORE_WARNINGS="-Wall"

	if test "x$set_more_warnings" = xerror; then
		CFLAGS_MORE_WARNINGS="$CFLAGS_MORE_WARNINGS -Werror"
	fi

	for option in \
		      -Wextra \
		      -Wdeclaration-after-statement \
		      -Wfloat-equal \
		      -Wformat-nonliteral \
		      -Wformat-security \
		      -Wimplicit-fallthrough \
		      -Wimplicit-function-declaration \
		      -Winit-self \
		      -Wlogical-op \
		      -Wmissing-declarations \
		      -Wmissing-include-dirs \
		      -Wmissing-prototypes \
		      -Wpointer-arith \
		      -Wshadow \
		      -Wshift-negative-value \
		      -Wstrict-prototypes \
		      -Wundef \
		      -Wvla \
		      -Wno-duplicate-decl-specifier \
		      -Wno-format-truncation \
		      -Wno-format-y2k \
		      -Wno-missing-field-initializers \
		      -Wno-pragmas \
		      -Wno-sign-compare \
		      -Wno-unused-parameter \
		      ; do
		dnl GCC 4.4 does not warn when checking for -Wno-* flags (https://gcc.gnu.org/wiki/FAQ#wnowarning)
		_NM_COMPILER_FLAG([-Wall $(printf '%s' "$option" | sed 's/^-Wno-/-W/')], [],
		                  [CFLAGS_MORE_WARNINGS="$CFLAGS_MORE_WARNINGS $option"], [])
	done
	unset option

	dnl Disable warnings triggered by known compiler problems

	dnl https://bugzilla.gnome.org/show_bug.cgi?id=745821
	NM_COMPILER_WARNING([$1], [unknown-attributes], [#include <glib.h>])

	dnl https://bugzilla.gnome.org/show_bug.cgi?id=744473
	NM_COMPILER_WARNING([$1], [typedef-redefinition], [#include <gio/gio.h>])

	dnl https://llvm.org/bugs/show_bug.cgi?id=21614
	NM_COMPILER_WARNING([$1], [array-bounds],
		[#include <string.h>]
		[void f () { strcmp ("something", "0"); }]
	)

	dnl https://llvm.org/bugs/show_bug.cgi?id=22949
	NM_COMPILER_WARNING([$1], [parentheses-equality],
		[#include <sys/wait.h>]
		[void f () { if (WIFCONTINUED(0)) return; }]
	)

	dnl systemd-dhcp's log_internal macro and our handle_warn are sometimes
	dnl used in void context,u sometimes in int. Makes clang unhappy.
	NM_COMPILER_WARNING([$1], [unused-value],
		[#define yolo ({ (666 + 666); })]
		[int f () { int i = yolo; yolo; return i; }]
	)

	dnl a new warning in gcc 8, glib 2.55 doesn't play nice yet
	dnl https://bugzilla.gnome.org/show_bug.cgi?id=793272
	NM_COMPILER_WARNING([$1], [cast-function-type],
		[#include <glib-object.h>]
		[typedef struct { GObject parent; } NMObject;]
		[typedef struct { GObjectClass parent; } NMObjectClass;]
		[static void nm_object_init (NMObject *object) { } ]
		[static void nm_object_class_init (NMObjectClass *object) { }]
		[G_DEFINE_TYPE (NMObject, nm_object, G_TYPE_OBJECT)]
	)

	eval "AS_TR_SH([$1])='$CFLAGS_MORE_WARNINGS $$1'"
else
	AC_MSG_RESULT(no)
fi
])

AC_DEFUN([NM_LTO],
[AC_ARG_ENABLE(lto, AS_HELP_STRING([--enable-lto], [Enable Link Time Optimization for smaller size (default: no)]))
if (test "${enable_lto}" = "yes"); then
	CC_CHECK_FLAG_APPEND([lto_flags], [CFLAGS], [-flto -flto-partition=none])
	if (test -n "${lto_flags}"); then
		CFLAGS="-flto -flto-partition=none $CFLAGS"
	else
		AC_MSG_ERROR([Link Time Optimization -flto is not supported.])
	fi
else
	enable_lto='no'
fi
])

AC_DEFUN([NM_LD_GC],
[AC_ARG_ENABLE(ld-gc, AS_HELP_STRING([--enable-ld-gc], [Enable garbage collection of unused symbols on linking (default: auto)]))
if (test "${enable_ld_gc}" != "no"); then
	CC_CHECK_FLAG_APPEND([ld_gc_flags], [CFLAGS], [-fdata-sections -ffunction-sections -Wl,--gc-sections])
	if (test -n "${ld_gc_flags}"); then
		enable_ld_gc="yes"
		CFLAGS="$ld_gc_flags $CFLAGS"
	else
		if (test "${enable_ld_gc}" = "yes"); then
			AC_MSG_ERROR([Unused symbol eviction requested but not supported.])
		else
			enable_ld_gc="no"
		fi
	fi
fi
])

