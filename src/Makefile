PROGRAMS = enforcer pledge
LIBRARIES = libenforcer.so

TARGETS = $(LIBRARIES) $(PROGRAMS)

SOURCES = pledge.c list.c list_util.c enforcer.c
COMMON_SRCS = list.c list_util.c

OBJECTS = list.o list_util.o pledge.o enforcer.o
OBJECTS_PLEDGE = list.o list_util.o pledge.o

CCFLAGS= -Wall -Wextra -g -O2 -std=c99 -D_GNU_SOURCE -fPIC
#CCFLAGS== -Wall -Wextra -Werror -g -O2 -std=gnu11

#EXTERNAL_LINKAGE_NO_OPENSSL = -L--prefix/lib -lresolv -L--prefix/lib -lrt -ldl -L--prefix/lib

all: $(TARGETS)

enforcer: $(OBJECTS_PLEDGE)

libenforcer.so: enforcer.o $(COMMON_SRCS)
	gcc $(CCFLAGS) $(EXTERNAL_LINKAGE_NO_OPENSSL) -shared -o $@ $^

libenforcer.h: libenforcer.so
	xxd -i $< > $@

pledge.o: pledge.c libenforcer.h

enforcer.o: enforcer.c
	 gcc -o $@ -c $(CCFLAGS) enforcer.c

pledge: pledge_tracer.py
	echo '#!/bin/sh' > $@
	echo 'case "$$1" in' >> $@
	echo '  --trace)' >> $@
	echo '    shift' >> $@
	echo '    python3 $(PWD)/pledge_tracer.py "$$@"' >> $@
	echo '    ;;' >> $@
	echo '  --enforce)' >> $@
	echo '    shift' >> $@
	echo '    $(PWD)/pledge "$$@"' >> $@
	echo '    ;;' >> $@
	echo '  *)' >> $@
	echo '    echo "Usage: $$0 [--trace|--enforce] args..."' >> $@
	echo '    exit 1' >> $@
	echo '    ;;' >> $@
	echo 'esac' >> $@
	chmod +x $@

format:
	clang-format -i $(SOURCES)

clean:
	rm $(OBJECTS) $(TARGETS) libenforcer.h

.PHONY: all clean install test lint format bindings
