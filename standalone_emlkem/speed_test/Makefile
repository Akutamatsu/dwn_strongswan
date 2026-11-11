CC=/usr/bin/gcc
VPATH = ../src/:../src/test
CFLAGS += -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls \
  -Wshadow -Wpointer-arith -O3 -fomit-frame-pointer -z noexecstack
LDFLAGS = -lcrypto
RM = /bin/rm

# replace 'test_speed_api.c' with 'test_speed.c' for a more detailed speed test (inner functions)
SRC= cpucycles.c speed_print.c cbd.c fips202.c indcpa.c kem_cpaf.c ntt.c poly.c polyvec.c reduce.c verify.c symmetric-shake.c test_speed_api.c
HEADERS = params.h kem.h indcpa.h polyvec.h poly.h ntt.h cbd.h reduce.c verify.h symmetric.h
HEADERSKECCAK = $(HEADERS) fips202.h

BIN1= e512-speed
BIN2= e768-speed
BIN3= e1024-speed
BIN= $(BIN1) $(BIN2) $(BIN3)

.PHONY: all speed shared clean

all:$(BIN) 

$(BIN1):$(SRC)
	$(CC) $(CFLAGS) -DKYBER_K=2 -o $@ $^ ../src/randombytes.c $(LDFLAGS) -I../src -I../src/test

$(BIN2):$(SRC)
	$(CC) $(CFLAGS) -DKYBER_K=3 -o $@ $^ ../src/randombytes.c $(LDFLAGS) -I../src -I../src/test

$(BIN3):$(SRC)
	$(CC) $(CFLAGS) -DKYBER_K=4 -o $@ $^ ../src/randombytes.c $(LDFLAGS) -I../src -I../src/test


clean:
	-$(RM) -f $(BIN)


