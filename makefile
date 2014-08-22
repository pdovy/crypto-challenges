CC       = g++
MKDIR    = mkdir -p
CFLAGS   = -Wall -g
LIB_SRC  = $(wildcard lib/*.cxx)
TEST_SRC = $(wildcard challenges/*.cxx)
LIB_NAME = libcrypto.a
LIB_OBJS = $(patsubst %.cxx,%.o,$(LIB_SRC))
TESTS    = $(patsubst %.cxx,%,$(TEST_SRC))

%.o : %.cxx
	$(CC) $(CFLAGS) -I lib/ -c -o $@ $<

lib: $(LIB_OBJS)
	$(MKDIR) bin
	$(AR) rcs bin/$(LIB_NAME) $^

tests:
	for test in $(TESTS); do \
		$(MAKE) BIN=$$test test; \
	done

all: lib tests
clean:
	$(RM) lib/*.o
	$(RM) -f bin/*

ifdef BIN
OBJ = $(addsuffix .o,$(BIN))
test : $(OBJ)
	$(MKDIR) bin
	$(CC) $^ bin/$(LIB_NAME) -lcrypto -lssl -o bin/$(notdir $(BIN))
endif

.DEFAULT_GOAL := all
