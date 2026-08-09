include ../Makefile.inc

SDKROOT?=       $(shell xcrun --sdk macosx --show-sdk-path)
KERNEL_FW=      $(SDKROOT)/System/Library/Frameworks/Kernel.framework
KERNEL_HEADERS= $(KERNEL_FW)/Headers
KERNEL_LIBDIR=  $(SDKROOT)/usr/lib

# The KPI version of the running system, taken from the BSDKernel symbol set
# in System.kext. The MAC framework entry points (mac_policy_register/
# unregister) are exported by the com.apple.kpi.dsep symbol set - also
# versioned with the same number - not by com.apple.kpi.bsd, which is why the
# plist declares both.
KPIVERSION?=     $(shell defaults read /System/Library/Extensions/System.kext/PlugIns/BSDKernel.kext/Info CFBundleVersion 2>/dev/null || echo 25.0.0)

BUNDLEID?=           $(BUNDLEDOMAIN).$(KEXTNAME)
KEXTBUNDLE?=         $(KEXTNAME).kext
KEXTMACHO?=          $(KEXTNAME).out

ARCHFLAGS?=          -arch arm64e
TARGET_TRIPLE?=      arm64e-apple-macos12.0

PREFIX?=             /Library/Extensions
DEVELOPER_DIR?=      /Applications/Xcode.app/Contents/Developer
MACOSX_VERSION_MIN?= 12.0

CC=       $(shell xcrun -find -sdk $(SDKROOT) cc)
CODESIGN= $(shell xcrun -find -sdk $(SDKROOT) codesign)

CSRCS:=   $(wildcard *.c)
OBJS:=    $(CSRCS:.c=.o)

CFLAGS+= -DKEXTNAME_S=\"$(KEXTNAME)\" \
         -DKEXTVERSION_S=\"$(KEXTVERSION)\" \
         -DKEXTBUILD_S=\"$(KEXTBUILD)\" \
         -DBUNDLEID_S=\"$(BUNDLEID)\" \
         -DBUNDLEID=$(BUNDLEID)

TIME_STAMP:= $(shell date +'%Y/%m/%d\ %H:%M:%S%z')
CFLAGS+=     -D__TS__=\"$(TIME_STAMP)\"

# Compile the vendored XNU headers (xnu-12377.1.9) in their kernel-private
# configuration. These must be defined on the command line (not just in
# kernel.h) so they are visible to every header from the very first include in
# each translation unit.
CFLAGS+= -DKERNEL \
         -DPRIVATE \
         -DKERNEL_PRIVATE \
         -DXNU_KERNEL_PRIVATE \
         -DBSD_KERNEL_PRIVATE \
         -DMACH_KERNEL_PRIVATE \
         -D__APPLE_API_PRIVATE \
         -D_DARWIN_C_SOURCE \
         -DMACH_BSD \
         -DXNU_TARGET_OS_OSX \
         -DXNU_PLATFORM_MacOSX

# Match the struct layout of the RELEASE macOS kernel (see mSL-ProcFS
# kext/Makefile for the full rationale). CONFIG_PERSONAS/AUDIT/DTRACE are on in
# the shipping macOS config; CONFIG_PROC_RESOURCE_LIMITS is DEV/DEBUG-only and
# deliberately left off.
CFLAGS+= -DCONFIG_PERSONAS \
         -DCONFIG_AUDIT \
         -DCONFIG_DTRACE

# arm64/proc_reg.h picks its constants from a CPU-family macro and #errors if
# none is set; XNU supplies it via board config. APPLEFIRESTORM (M1) satisfies
# the header's #if chain; every Apple ARM64 family selects identical constants
# here.
CFLAGS += -DAPPLEFIRESTORM

# No vendored xnu include paths. Everything the policy needs comes from the
# public kernel SDK; the only hand-declared ABI is include/sedarwin/sebsd_mac.h.
#
# The kernel-private headers this used to vendor came from a different xnu build
# than the running kernel, so any struct laid out from them was a guess - and
# including one dragged in most of the osfmk lock/zalloc/waitq chain. Where a
# definition really is private, the policy uses the public accessor
# (proc_find_ident() rather than struct proc_ident) or forward-declares the type
# because it only ever holds a pointer. See include/sedarwin/sebsd_mac.h.
XNU_INCLUDES :=

ARCH_SYS_INCLUDES := -isystem $(KERNEL_HEADERS)/arm64 -isystem $(KERNEL_HEADERS)/arm

CFLAGS+= -target $(TARGET_TRIPLE) \
         -isysroot $(SDKROOT) \
         $(ARCHFLAGS) \
         -x c \
         -std=gnu99 \
         -nostdinc \
         -fno-builtin \
         -fno-common \
         -mkernel \
         -fno-stack-check \
         -fno-stack-protector \
         -I../include \
         $(XNU_INCLUDES) \
         -isystem $(KERNEL_HEADERS) \
         $(ARCH_SYS_INCLUDES)

CFLAGS+= -Werror -Wall -Wextra \
         -Wno-unused-parameter \
         -Wno-unused-variable \
         -Wno-unused-value \
         -Wno-vla \
         -Wno-gnu-folding-constant \
         -Wno-visibility \
         -Wno-unused-function \
         -Wno-deprecated-declarations \
         -Wno-sign-conversion

LDFLAGS+= -target $(TARGET_TRIPLE) \
          -isysroot $(SDKROOT) \
          $(ARCHFLAGS) \
          -nostdlib \
          -Xlinker -kext \
          -Xlinker -object_path_lto main.o \
          -Xlinker -object_path_lto vnode.o \
          -Xlinker -object_path_lto spawn.o \
          -Xlinker -object_path_lto proc.o \
          -Xlinker -object_path_lto file.o \
          -Xlinker -object_path_lto net.o \
          -Xlinker -object_path_lto tty.o \
          -Xlinker -object_path_lto MachO.o \
          -Xlinker -export_dynamic

LIBS+= -L$(KERNEL_LIBDIR)

# -lkmod provides kmod_start/kmod_stop (the kext entry points for a C-style
# kext). libkext.a no longer ships in the macOS 26 SDK and is not needed for a
# pure-C kext.
#
# libkern-bsd is deliberately NOT linked: the policy references nothing from it
# (no _MALLOC, no sbuf - check with `nm -u`). It still builds, for the userland
# side to use later.
LIBS+= -lkmod

all: debug

%.o: %.c kernel.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(KEXTMACHO): $(OBJS)
	$(CC) $(LDFLAGS) $(LIBS) -o $@ $^
	otool -h $@
	otool -l $@ | grep uuid

Info.plist~: Info.plist.in
	sed \
		-e 's/__KEXTNAME__/$(KEXTNAME)/g' \
		-e 's/__KEXTMACHO__/$(KEXTNAME)/g' \
		-e 's/__KEXTVERSION__/$(KEXTVERSION)/g' \
		-e 's/__KEXTBUILD__/$(KEXTBUILD)/g' \
		-e 's/__BUNDLEID__/$(BUNDLEID)/g' \
		-e 's/__OSBUILD__/$(shell /usr/bin/sw_vers -buildVersion)/g' \
		-e 's/__KPIVERSION__/$(KPIVERSION)/g' \
		-e 's/__CLANGVER__/$(shell $(CC) -v 2>&1 | grep version)/g' \
	$^ > $@

$(KEXTBUNDLE): $(KEXTMACHO) Info.plist~
	mkdir -p $@/Contents/MacOS
	mv $< $@/Contents/MacOS/$(KEXTNAME)
	cp Info.plist~ $@/Contents/Info.plist
ifdef COMPATIBLE_VERSION
	/usr/libexec/PlistBuddy -c 'Add :OSBundleCompatibleVersion string "$(COMPATIBLE_VERSION)"' $@/Contents/Info.plist
endif
ifdef COPYRIGHT
	/usr/libexec/PlistBuddy -c 'Add :NSHumanReadableCopyright string "$(COPYRIGHT)"' $@/Contents/Info.plist
endif
ifdef SIGNCERT
	$(CODESIGN) --force --timestamp=none --sign $(SIGNCERT) $@
	/usr/libexec/PlistBuddy -c 'Add :CFBundleSignature string ????' $@/Contents/Info.plist
endif
ifdef MACOSX_VERSION_MIN
	/usr/libexec/PlistBuddy -c 'Add :LSMinimumSystemVersion string "$(MACOSX_VERSION_MIN)"' $@/Contents/Info.plist
endif
	/usr/libexec/PlistBuddy -c 'Print OSBundleLibraries' $@/Contents/Info.plist &> /dev/null || \
		/usr/libexec/PlistBuddy -c 'Add :OSBundleLibraries:com.apple.kpi.bsd string "$(KPIVERSION)"' $@/Contents/Info.plist
	touch $@
	dsymutil $(ARCHFLAGS) -o $(KEXTNAME).kext.dSYM $@/Contents/MacOS/$(KEXTNAME)

debug: CFLAGS += -O0 -g
debug: $(KEXTBUNDLE)

release: CFLAGS += -O2
release: $(KEXTBUNDLE)

load: $(KEXTBUNDLE)
	sudo chown -R root:wheel $<
	sudo sync
	sudo kextutil $<
	sudo chown -R '$(USER):$(shell id -gn)' $<
	sudo dmesg | grep $(KEXTNAME) | tail -1

stat:
	kextstat | grep $(KEXTNAME)

unload:
	sudo kextunload $(KEXTBUNDLE)
	sudo dmesg | grep $(KEXTNAME) | tail -2

clean:
	rm -f $(OBJS) $(KEXTMACHO) Info.plist~
	rm -rf $(KEXTBUNDLE) $(KEXTNAME).kext.dSYM

.PHONY: all debug release load stat unload clean
