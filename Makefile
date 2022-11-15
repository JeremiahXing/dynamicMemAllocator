CC       = gcc
# https://developers.redhat.com/blog/2018/03/21/compiler-and-linker-flags-gcc
CFLAGS   = -fPIC -Wall -Wextra -Werror=format-security -Werror=implicit-function-declaration -std=gnu17 -pedantic
LIBFLAGS = -shared
MALLOC   = mymalloc
ODIR	 = ./out
LIBTESTFLAGS = -L./out

ifdef RELEASE
CFLAGS += -O3
else
CFLAGS += -g -ggdb3
endif

ifdef LOG
CFLAGS += -DENABLE_LOG
endif

ifeq ($(shell uname -s),Darwin)
# Treat 32-bit tests as 64-bit.
M32_FLAG =
DYLIB_EXT = dylib
else
M32_FLAG = -m32
DYLIB_EXT = so
endif

ALL_TESTS_SRC = $(wildcard tests/*.c)
ALL_TESTS = $(ALL_TESTS_SRC:%.c=%)

all: mymalloc

mymalloc: $(MALLOC).c | $(ODIR)/
	@$(CC) $(CFLAGS) $(LIBFLAGS) -o $(ODIR)/lib$(MALLOC).$(DYLIB_EXT) $<

ifneq ($(shell uname -s),Darwin)
mymalloc32: $(MALLOC).c | $(ODIR)/
	@$(CC) $(CFLAGS) $(LIBFLAGS) -m32 -o $(ODIR)/lib$(MALLOC)32.$(DYLIB_EXT) $<
endif

tests/%: _force *.h tests/*.h tests/%.c | mymalloc
	@$(CC) $(CFLAGS) $(LIBTESTFLAGS) $@.c -l$(MALLOC) -o $@ -Wl,-rpath,`pwd`/$(ODIR)

ifneq ($(shell uname -s),Darwin)
tests/m32: _force *.h tests/m32.c | mymalloc32
	@$(CC) $(CFLAGS) $(LIBTESTFLAGS) -m32 $@.c -l$(MALLOC)32 -o $@ -Wl,-rpath,`pwd`/$(ODIR)
endif

tests/%_: tests/%
	$^

test: $(ALL_TESTS)

bench/%: _force *.h tests/*.h bench/%.c | mymalloc
	@$(CC) $(CFLAGS) $(LIBTESTFLAGS) $@.c -l$(MALLOC) -o $@ -Wl,-rpath,`pwd`/$(ODIR)

$(ODIR)/:
	mkdir -p $(ODIR)

clean:
	rm -rf ./out
	rm -rf ./tests/*.dSYM
	rm -f *.o $(ODIR)/*.o
	rm -f *.$(DYLIB_EXT) $(ODIR)/*.$(DYLIB_EXT)
	@for test in $(ALL_TESTS); do        \
		echo "rm $$test";            \
		rm -f $$test;      	     \
	done

_force:

.PHONY: clean _force all mymalloc mymalloc32

