CC      = gcc
CFLAGS  = -Wall -Wextra -O2

SO      = libnss_forward.so
SO_SRC  = src/nss_forward.c

TEST_C_BIN = test/nss_forward_test
TEST_C_SRC = test/nss_forward_test.c

.PHONY: all build test clean

all: build

build: $(SO)

$(SO): $(SO_SRC)
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $<

$(TEST_C_BIN): $(TEST_C_SRC) $(SO_SRC)
	$(CC) $(CFLAGS) -DNSS_FORWARD_TESTING -o $@ $<

test: $(TEST_C_BIN)
	./$(TEST_C_BIN)

clean:
	rm -f $(SO) $(TEST_C_BIN)
