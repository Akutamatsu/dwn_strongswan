CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Wpedantic
LDLIBS ?= -lcrypto

SOURCES = \
	src/cbd.c \
	src/fips202.c \
	src/indcpa.c \
	src/kem_cpaf.c \
	src/ntt.c \
	src/poly.c \
	src/polyvec.c \
	src/randombytes.c \
	src/reduce.c \
	src/symmetric-shake.c \
	src/verify.c

.PHONY: smoke clean

smoke: e768-smoke

e768-smoke: smoke_test.c $(SOURCES)
	$(CC) $(CFLAGS) -DKYBER_K=3 -Isrc -o $@ smoke_test.c $(SOURCES) $(LDLIBS)

clean:
	$(RM) e768-smoke
