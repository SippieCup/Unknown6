CC ?= cc
CFLAGS ?= -g -fPIC
LDFLAGS ?=

LIBENCRYPT_OBJS = encrypt.o
TEST_OBJS = main.o
OBJS = $(LIBENCRYPT_OBJS) $(TEST_OBJS)
TARGETS = libencrypt.so test

all: $(TARGETS)

libencrypt.so: $(LIBENCRYPT_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $(LIBENCRYPT_OBJS) -lm

test: libencrypt.so $(TEST_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,-rpath='$$ORIGIN' -o $@ $(TEST_OBJS) -L$(CURDIR) -lencrypt 

lib: libencrypt.so

clean:
	$(RM) $(OBJS) $(TARGETS)
