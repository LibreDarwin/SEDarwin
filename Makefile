#
# All-in-one Makefile
#
# Usage:
#   make                    # build lib + kext into $(OUT)
#   sudo make install       # install kext + boot loader (leaves it DISARMED)
#   make status             # installed / armed / loaded / trace state
#   sudo make load          # load now - only works if already approved+staged
#   sudo make unload        # unload from the running kernel
#   sudo make uninstall     # remove everything
#   make clean              # remove build artifacts (no sudo needed)
#
# Typical flow. A REBUILT kext has a new cdhash, so it needs re-approval and a
# reboot every time - the auxiliary kernel collection is only rebuilt at boot,
# and `make load` cannot shortcut that:
#
#   make && sudo make install
#   # System Settings > Privacy & Security -> allow the developer
#   sudo touch /var/db/sedarwin.enabled     # arm the boot loader
#   sudo reboot
#   make status                             # expect loaded: yes, trace: 0
#
# NOTE: never run the build as root. `make install` only COPIES the already-built
# artifacts from $(OUT) into place; it does not compile. This keeps every build
# artifact owned by the invoking user, so `make clean` never needs sudo.
#

MAKE=make
OUT=out

# Install locations / identifiers.
EXT_DIR    := /Library/Extensions
BUNDLE_ID  := com.beako.security.sedarwin

# Boot-time loader. Being installed in $(EXT_DIR) - and even being prelinked
# into the auxKC - does not START a kext; something has to ask kernelmanagement
# to load it. That is this daemon's whole job (same pattern as the procfs/sysfs
# siblings). It stays inert until armed with $(ARM_FLAG).
SBIN_DIR     := /usr/local/sbin
DAEMON_DIR   := /Library/LaunchDaemons
LOAD_SCRIPT  := sedarwin-load
DAEMON_PLIST := com.beako.sedarwin.plist
DAEMON_LABEL := com.beako.sedarwin
ARM_FLAG     := /var/db/sedarwin.enabled

# Version (single source of truth: the repo VERSION file).
VERSION    := $(strip $(shell cat VERSION 2>/dev/null || echo 1.0.0))

# Default target: everything needed to install (lib + kext). Nothing else yet.
all: clean kext

# ---------------------------------------------------------------------------
# Build  ->  $(OUT)
# ---------------------------------------------------------------------------

kext:
	rm -rf $(OUT)
	mkdir $(OUT)
	$(MAKE) -C lib
	$(MAKE) debug -C kext
	mv kext/sedarwin.kext kext/sedarwin.kext.dSYM $(OUT)

debug: kext
release: TARGET=release
release: kext

# ---------------------------------------------------------------------------
# Install  (run as root, AFTER `make`; copies only, never compiles)
# ---------------------------------------------------------------------------

install: require-root require-built
	rm -rf $(EXT_DIR)/sedarwin.kext
	cp -R $(OUT)/sedarwin.kext $(EXT_DIR)/sedarwin.kext
	chown -R root:wheel $(EXT_DIR)/sedarwin.kext
	chmod -R 755 $(EXT_DIR)/sedarwin.kext
	install -d -m 755 -o root -g wheel $(SBIN_DIR)
	install -m 755 -o root -g wheel tools/$(LOAD_SCRIPT) $(SBIN_DIR)/$(LOAD_SCRIPT)
	install -m 644 -o root -g wheel tools/$(DAEMON_PLIST) $(DAEMON_DIR)/$(DAEMON_PLIST)
	@# A prior `launchctl disable` persists across boots in launchd's override
	@# database, and would silently defeat RunAtLoad on the next install.
	-@launchctl enable system/$(DAEMON_LABEL) 2>/dev/null || true
	-@launchctl bootout system/$(DAEMON_LABEL) 2>/dev/null || true
	launchctl bootstrap system $(DAEMON_DIR)/$(DAEMON_PLIST)
	@echo ""
	@echo "sedarwin: installed $(EXT_DIR)/sedarwin.kext + boot loader ($(DAEMON_LABEL))."
	@echo "sedarwin: the loader is DISARMED - the kext will not load until you run:"
	@echo "              sudo touch $(ARM_FLAG)"
	@echo "          then either 'sudo make load' (now) or reboot."

require-root:
	@[ "$$(id -u)" -eq 0 ] || { echo "error: this target must be run as root (use: sudo make $(MAKECMDGOALS))"; exit 1; }

require-built:
	@[ -d "$(OUT)/sedarwin.kext" ] || { echo "error: build artifacts missing in $(OUT)/. Run 'make' first."; exit 1; }

# ---------------------------------------------------------------------------
# Uninstall  (run as root)
# ---------------------------------------------------------------------------

uninstall: require-root
	-@launchctl bootout system/$(DAEMON_LABEL) 2>/dev/null || true
	rm -f $(DAEMON_DIR)/$(DAEMON_PLIST) $(SBIN_DIR)/$(LOAD_SCRIPT) $(ARM_FLAG)
	-@kmutil unload -b $(BUNDLE_ID) 2>/dev/null || true
	-@kmutil clear-staging 2>/dev/null || true
	rm -rf $(EXT_DIR)/sedarwin.kext
	$(MAKE) clean
	@echo "sedarwin: uninstalled."

# ---------------------------------------------------------------------------
# Load / unload the installed kext in the RUNNING kernel (no reboot)
# ---------------------------------------------------------------------------
#
# `load` goes through the same script the boot daemon runs, so what you test
# interactively is exactly what happens at boot - including the arm-flag gate.

load: require-root
	@[ -e "$(ARM_FLAG)" ] || { echo "error: loader is disarmed. Arm it first: sudo touch $(ARM_FLAG)"; exit 1; }
	$(SBIN_DIR)/$(LOAD_SCRIPT)

unload: require-root
	kmutil unload -b $(BUNDLE_ID)
	@echo "sedarwin: unloaded."

# Show whether the kext is loaded and what the policy is doing.
status:
	@echo "installed:  $$([ -d $(EXT_DIR)/sedarwin.kext ] && echo yes || echo no)"
	@echo "armed:      $$([ -e $(ARM_FLAG) ] && echo yes || echo "no ($(ARM_FLAG) absent)")"
	@echo "daemon:     $$(launchctl print system/$(DAEMON_LABEL) >/dev/null 2>&1 && echo bootstrapped || echo "not bootstrapped")"
	@echo "loaded:     $$(kmutil showloaded 2>/dev/null | grep -q $(BUNDLE_ID) && echo yes || echo no)"
	@echo "trace:      $$(sysctl -n sedarwin.trace 2>/dev/null || echo "n/a (policy not registered)")"

# ---------------------------------------------------------------------------
# Clean  (never needs sudo)
# ---------------------------------------------------------------------------

clean:
	rm -rf $(OUT)
	$(MAKE) -C lib clean
	$(MAKE) -C kext clean

.PHONY: all kext debug release install require-root require-built uninstall \
        load unload status clean
