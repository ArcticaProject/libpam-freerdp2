SUBDIRS = src

if HAVE_GTEST
SUBDIRS += tests
endif

DISTCHECK_CONFIGURE_FLAGS = --enable-localinstall

include $(top_srcdir)/Makefile.am.coverage
