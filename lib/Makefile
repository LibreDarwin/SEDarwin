#
# libkern-bsd: BSD-style kernel support library (sbuf + _MALLOC/_FREE) for
# the SEDarwin policy kext.
#
# The sources are vendored into lib/libkern-bsd/ (they originally lived in
# mSL/XNU's compat/libkern-bsd). Building is delegated to that directory.
#
# Usage:
#   make            # build libkern-bsd.a (arm64e)
#   make clean      # remove build artifacts
#

MAKE=make

all: debug

debug:
	$(MAKE) -C libkern-bsd

release: TARGET=release
release: debug

clean:
	$(MAKE) -C libkern-bsd clean

.PHONY: all debug release clean
