AC_INIT([libpam-freerdp], [2.0.0])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])

AM_INIT_AUTOMAKE([-Wno-portability subdir-objects])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_PROG_CC
# the Google Test targets are cpp
AC_PROG_CXX
AC_PROG_LIBTOOL

LT_INIT([disable-static])

###########################
# PAM
###########################

have_pam=no
AC_CHECK_LIB(pam, pam_getenv, have_pam=yes)
if test "x$have_pam" = "xno"; then
  AC_MSG_ERROR([Required library PAM was not found])
fi

###########################
# FreeRDP
###########################

dnl GTK version selection.
AC_MSG_CHECKING([whether to build against FreeRDPv3])
AC_ARG_ENABLE([freerdp3],
              [AS_HELP_STRING([--enable-freerdp3],
                              [Build against FreeRDPv3])],
              [enable_freerdp3=$enableval],
              [enable_freerdp3=no])
AC_MSG_RESULT([$enable_freerdp3])
with_freerdp3=$enable_freerdp3

AS_IF([test "x$enable_freerdp3" != 'xno'],
      [PKG_CHECK_MODULES([FREERDP],
                         [freerdp3],
                         [freerdp3_modules=yes],
                         [freerdp3_modules=no])
       PKG_CHECK_MODULES([WINPR],
                         [winpr3])
       AC_MSG_CHECKING([for FreeRDPv3 libraries])
       AC_MSG_RESULT([$freerdp3_modules])
       AS_IF([test "x$freerdp3_modules" = 'xno'],
             [AC_MSG_ERROR([requested FreeRDPv3, but not found])],
             [with_freerdp3=yes])])
AS_IF([test "x$with_freerdp3" = 'xno'],
      [PKG_CHECK_MODULES([FREERDP],
                         [freerdp2],
                         [freerdp2_modules=yes],
                         [freerdp2_modules=no])
       PKG_CHECK_MODULES([WINPR],
                         [winpr2])
       AC_MSG_CHECKING([for FreeRDPv2 libraries])
       AC_MSG_RESULT([$freerdp2_modules])
       AS_IF([test "x$freerdp2_modules" = 'xno'],
             [AC_MSG_ERROR([requested FreeRDPv2, but not found])])])
AC_SUBST([FREERDP_CFLAGS])
AC_SUBST([FREERDP_LIBS])
AC_SUBST([WINPR_CFLAGS])
AC_SUBST([WINPR_LIBS])
AM_CONDITIONAL([HAVE_FREERDP3], [test "x$with_freerdp3" != 'xno'])

###########################
# PAM Module dir
###########################

PAMMODULEDIR="/lib/security"
AC_SUBST(PAMMODULEDIR)

###########################
# Google Test Dependencies
###########################

m4_include([m4/gtest.m4])
CHECK_GTEST
if test "x$have_gtest" != "xyes"; then
   AC_MSG_WARN([tests were requested but gtest is not installed.])
fi
AM_CONDITIONAL([HAVE_GTEST], [test "$have_gtest" != "no"])

###########################
# gcov coverage reporting
###########################

m4_include([m4/gcov.m4])
AC_TDD_GCOV
AM_CONDITIONAL([HAVE_GCOV], [test "x$ac_cv_check_gcov" = xyes])
AM_CONDITIONAL([HAVE_LCOV], [test "x$ac_cv_check_lcov" = xyes])
AM_CONDITIONAL([HAVE_GCOVR], [test "x$ac_cv_check_gcovr" = xyes])
AC_SUBST(COVERAGE_CFLAGS)
AC_SUBST(COVERAGE_CXXFLAGS)
AC_SUBST(COVERAGE_LDFLAGS)



AC_CONFIG_FILES([
  Makefile
  src/Makefile
  tests/Makefile
])
AC_OUTPUT
