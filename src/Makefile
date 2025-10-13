PROGRAMS = pledge
LIBRARIES = libenforcer.so

TARGETS = $(LIBRARIES) $(PROGRAMS)

SOURCES = pledge.c list.c list_util.c enforcer.c
COMMON_SRCS = list.c list_util.c

OBJECTS = list.o list_util.o pledge.o enforcer.o
OBJECTS_PLEDGE = list.o list_util.o pledge.o

CCFLAGS= -Wall -Wextra -g -O2 -std=c99 -D_GNU_SOURCE -fPIC
#CCFLAGS== -Wall -Wextra -Werror -g -O2 -std=gnu11

EXTERNAL_LINKAGE_NO_OPENSSL = -L--prefix/lib -lresolv -L--prefix/lib -lnsl -lrt -ldl -L--prefix/lib -lz -lstdc++ -lpthread -lz -lc -lm

all: $(TARGETS)

pledge: $(OBJECTS_PLEDGE)

libenforcer.so: enforcer.o $(COMMON_SRCS)
	gcc $(CCFLAGS) $(EXTERNAL_LINKAGE_NO_OPENSSL) -shared -o $@ $^

libenforcer.h: libenforcer.so
	xxd -i $< > $@

pledge.o: pledge.c libenforcer.h

enforcer.o: enforcer.c
	 gcc -o $@ -c $(CCFLAGS) enforcer.c

format:
	clang-format -i $(SOURCES)

clean:
	rm $(OBJECTS) $(TARGETS) libenforcer.h

.PHONY: all clean install test lint format bindings
