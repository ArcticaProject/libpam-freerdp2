pamlibdir = $(PAMMODULEDIR)
pamlib_LTLIBRARIES = pam_freerdp2.la

pam_freerdp2_la_SOURCES = \
	auth-check-path.c auth-check-path.h

pam_freerdp2_la_LDFLAGS = \
	-no-undefined \
	-module \
	-avoid-version \
	$(COVERAGE_LDFLAGS)

pam_freerdp2_la_CFLAGS = \
	-Wall -Werror \
	-DAUTH_CHECK="\"$(pkglibexecdir)/freerdp2-auth-check\"" \
	$(COVERAGE_CFLAGS)

pam_freerdp2_la_LIBADD = \
	$(builddir)/libfreerdp2core.la

noinst_LTLIBRARIES = \
	libfreerdp2core.la

libfreerdp2core_la_SOURCES = \
	pam-freerdp.c \
	pam-freerdp-children.c
libfreerdp2core_la_CFLAGS = \
	-Wall -Werror \
	$(COVERAGE_CFLAGS)
libfreerdp2core_la_LIBADD = \
	-lpam
libfreerdp2core_la_LDFLAGS = \
	$(COVERAGE_LDFLAGS)

pkglibexec_PROGRAMS = \
	freerdp2-auth-check

freerdp2_auth_check_SOURCES = \
	freerdp-auth-check.c
freerdp2_auth_check_CFLAGS = \
	$(FREERDP2_CFLAGS) \
	$(WINPR2_CFLAGS) \
	$(COVERAGE_CFLAGS)
freerdp2_auth_check_LDADD = \
	$(FREERDP2_LIBS) \
	$(WINPR2_LIBS)
freerdp2_auth_check_LDFLAGS = \
	$(FREERDP2_LDFLAGS) \
	$(WINPR2_LDFLAGS) \
	$(COVERAGE_LDFLAGS)
