# gfrguard top-level Makefile.
#
# Honors externally provided CC, CFLAGS, LDFLAGS for Yocto cross-compilation.
# Three targets:
#   build/gfrguard.so  - Samba VFS module (shared, -fPIC)
#   build/gfrguardd        - policy daemon
#   build/gfrguard-recover - CLI restore tool

CC      ?= gcc
AR      ?= ar

# Common (re)overridable flags.
CFLAGS   ?= -O2 -g
LDFLAGS  ?=

# Internal warning/std flags. Append at the end so external CFLAGS may override.
# -MMD -MP: header edits MUST rebuild dependents — without dep files a
# struct change (e.g. rguard_config.h) links objects with MIXED layouts
# (this actually happened: daemon read space.max_usage_percent as 0).
COMMON_CFLAGS := -std=c17 -D_GNU_SOURCE -Wall -Wextra -Wno-unused-parameter \
                -Isrc/common -MMD -MP $(CFLAGS)

# Samba 4.19.6 source tree (override on command line for Yocto: SAMBA_SRC=...).
SAMBA_SRC ?= /opt/yocto/gf_saxa_poky/build/tmp/work/corei7-64-poky-linux/samba/4.19.6/samba-4.19.6

# Includes used only by the VFS module to find Samba headers.
# bin/default is the waf build output dir containing config.h and gen_ndr.
SAMBA_SYSROOT ?= /opt/yocto/gf_saxa_poky/build/tmp/work/corei7-64-poky-linux/samba/4.19.6/recipe-sysroot
SAMBA_INC := -I$(SAMBA_SYSROOT)/usr/include \
             -I$(SAMBA_SRC)/bin/default/include \
             -I$(SAMBA_SRC)/bin/default \
             -I$(SAMBA_SRC)/bin/default/source3 \
             -I$(SAMBA_SRC) \
             -I$(SAMBA_SRC)/source3/include \
             -I$(SAMBA_SRC)/source3 \
             -I$(SAMBA_SRC)/lib/replace \
             -I$(SAMBA_SRC)/lib/talloc \
             -I$(SAMBA_SRC)/include

BUILD := build

COMMON_SRCS := \
    src/common/rguard_errors.c \
    src/common/rguard_log.c    \
    src/common/rguard_config.c \
    src/common/rguard_db.c     \
    src/common/cJSON.c

COMMON_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(COMMON_SRCS))

DAEMON_SRCS := $(wildcard src/daemon/*.c)
DAEMON_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(DAEMON_SRCS))

RECOVER_SRCS := $(wildcard src/recover/*.c) src/daemon/gfrguardd_blocker.c
RECOVER_OBJS := $(patsubst %.c,$(BUILD)/%.o,$(RECOVER_SRCS))

VFS_SRCS := $(wildcard src/vfs/*.c)
VFS_OBJS := $(patsubst %.c,$(BUILD)/%.pic.o,$(VFS_SRCS))

VFS_TARGET     := $(BUILD)/gfrguard.so
DAEMON_TARGET  := $(BUILD)/gfrguardd
RECOVER_TARGET := $(BUILD)/gfrguard-recover

.PHONY: all clean vfs daemon recover

all: $(if $(strip $(VFS_SRCS)),vfs) daemon recover

vfs:     $(VFS_TARGET)
daemon:  $(DAEMON_TARGET)
recover: $(RECOVER_TARGET)

# Generic compile rules.
$(BUILD)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(COMMON_CFLAGS) -c $< -o $@

$(BUILD)/%.pic.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(COMMON_CFLAGS) -fPIC $(SAMBA_INC) -c $< -o $@

# Targets.
$(VFS_TARGET): $(VFS_OBJS)
	@mkdir -p $(dir $@)
	$(CC) -shared -fPIC $(LDFLAGS) -o $@ $(VFS_OBJS)

$(DAEMON_TARGET): $(DAEMON_OBJS) $(COMMON_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) -o $@ $(DAEMON_OBJS) $(COMMON_OBJS) -lsqlite3 -lpthread -lyara -lm

$(RECOVER_TARGET): $(RECOVER_OBJS) $(COMMON_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) -o $@ $(RECOVER_OBJS) $(COMMON_OBJS) -lsqlite3 -lpthread

clean:
	rm -rf $(BUILD)

-include $(shell find $(BUILD) -name '*.d' 2>/dev/null)
