# RASP portable (LD_PRELOAD) channel — builds librasp_preload.so
#
# This is the buildable, demo-ready channel of the RASP. The seccomp-unotify and
# BPF-LSM enforcement cores (see the design document) are Linux-version and
# privilege dependent and are built separately.

CC      ?= cc
CFLAGS  ?= -std=c11 -Wall -Wextra -O2 -fPIC -Iinclude
LDFLAGS ?= -shared
LDLIBS  ?= -ldl -lpthread

# Channel A (exec / open / connect interposition) is always built. Channel B
# (libpq PQexec/PQexecParams interposition) is OPT-IN: it is only safe against a
# backend dynamically linked to a reachable libpq. With a statically-bundled
# libpq (e.g. the psycopg2 *binary* wheel) RTLD_NEXT cannot find the real symbol,
# so the hook would have to fail every query. Enable it with `make RASP_DB_HOOK=1`
# on a source-libpq deployment.
RASP_DB_HOOK ?= 0
SRC := src/context.c src/emitter.c src/engine.c src/preload_a.c
ifeq ($(RASP_DB_HOOK),1)
SRC += src/pg_hook.c
endif
OBJ := $(SRC:.c=.o)
LIB := librasp_preload.so

.PHONY: all clean
all: $(LIB)

$(LIB): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $(OBJ) $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(LIB)
