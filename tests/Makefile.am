NULL =

CLEANFILES =
DISTCLEANFILES =
EXTRA_DIST =

TESTS =								\
        test-freerdp2-wrapper					\
        $(NULL)

check_PROGRAMS =						\
        test-freerdp2-auth					\
        $(TESTS)						\
        $(NULL)

CLEANFILES +=							\
        test-freerdp2-auth					\
        $(TESTS)						\
        $(NULL)

AM_CPPFLAGS = $(GTEST_CPPFLAGS)					\
        $(REMOTE_APPS_MANAGER_CFLAGS)				\
        -I${top_srcdir}/src -Wall -Werror			\
        $(NULL)

AM_CXXFLAGS = $(GTEST_CXXFLAGS)					\
        $(REMOTE_APPS_MANAGER_CFLAGS)				\
        $(NULL)

AM_CFLAGS =							\
        -Wall							\
        -g							\
        $(NULL)

##########################
# Google Test Test Suite #
##########################

check_LIBRARIES = libgtest.a libgtest_main.a

gtest-all.cc:
	cp $(GTEST_SOURCE)/src/gtest-all.cc .

gtest_main.cc:
	cp $(GTEST_SOURCE)/src/gtest_main.cc .

CLEANFILES +=							\
        gtest-all.cc						\
        gtest_main.cc						\
        $(NULL)

nodist_libgtest_a_SOURCES =					\
        gtest-all.cc						\
        $(NULL)
nodist_libgtest_main_a_SOURCES =				\
        gtest_main.cc						\
        $(NULL)

libgtest_a_CPPFLAGS =						\
        $(GTEST_CPPFLAGS) -w					\
        $(AM_CPPFLAGS)						\
        $(NULL)
libgtest_main_a_CPPFLAGS =					\
        $(GTEST_CPPFLAGS) -w					\
        $(AM_CPPFLAGS)						\
        $(NULL)

libgtest_a_CXXFLAGS =						\
        $(AM_CXXFLAGS)						\
        $(NULL)
libgtest_main_a_CXXFLAGS =					\
        $(AM_CXXFLAGS)						\
        $(NULL)

##########################
# Wrapper
##########################

test_freerdp2_wrapper: test-freerdp2-auth

test_freerdp2_wrapper_SOURCES =					\
        mock_pam.c mock_pam.h					\
        mock_guest.c mock_guest.h				\
        test-freerdp2-wrapper.cc				\
        $(NULL)

test_freerdp2_wrapper_LDADD =					\
        libgtest.a libgtest_main.a				\
        ${top_srcdir}/src/pam_freerdp2.la			\
        $(FREERDP2_LIBS)					\
        $(WINPR2_LIBS)						\
        $(NULL)

test_freerdp2_wrapper_CPPFLAGS =				\
        $(AM_CPPFLAGS)						\
        -I${top_srcdir}/include					\
        -I${top_srcdir}/src					\
        $(GTEST_CPPFLAGS)					\
        $(FREERDP2_CPPFLAGS)					\
        $(WINPR2_CPPFLAGS)					\
        $(NULL)

test_freerdp2_wrapper_CXXFLAGS =				\
        $(AM_CXXFLAGS)						\
        -DAUTH_CHECK="\"$(abs_builddir)/test-freerdp2-auth\""	\
        $(GTEST_CXXFLAGS)					\
        $(FREERDP2_CXXFLAGS)					\
        $(WINPR2_CXXFLAGS)					\
        $(NULL)

test_freerdp2_wrapper_LDFLAGS =					\
        $(GTEST_LDFLAGS)					\
        $(FREERDP2_LDFLAGS)					\
        $(WINPR2_LDFLAGS)					\
        -pthread						\
        $(NULL)

##########################
# Auth tool
##########################

test_freerdp2_auth_SOURCES =					\
        test-freerdp2-auth.c					\
        $(NULL)
