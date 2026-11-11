CC=/usr/bin/gcc
VPATH = ../src/:.
NISTFLAGS += -Wno-unused-result -O3 -fomit-frame-pointer
# if need output PQCkemKAT files, add flag: -DLOG_FOR_DEBUG
LDFLAGS=-lcrypto
RM = /bin/rm

SRC= fips202.c symmetric-shake.c kem_cpaf.c indcpa.c polyvec.c poly.c ntt.c cbd.c reduce.c verify.c correct_test.c
HEADERS = params.h kem.h indcpa.h polyvec.h poly.h ntt.h cbd.h reduce.c verify.h symmetric.h
HEADERSKECCAK = $(HEADERS) fips202.h

.PHONY: all speed shared clean

BIN1= e512-failure
BIN2= e768-failure
BIN3= e1024-failure
BIN= $(BIN1) $(BIN2) $(BIN3)

all:$(BIN)

$(BIN1):$(SRC)
	$(CC) $(NISTFLAGS) -DKYBER_K=2 -o $@ $^ ../src/nistkat/rng.c $(LDFLAGS) -I../src

$(BIN2):$(SRC)
	$(CC) $(NISTFLAGS) -DKYBER_K=3 -o $@ $^ ../src/nistkat/rng.c $(LDFLAGS) -I../src

$(BIN3):$(SRC)
	$(CC) $(NISTFLAGS) -DKYBER_K=4 -o $@ $^ ../src/nistkat/rng.c $(LDFLAGS) -I../src


clean:
	-$(RM) -f $(BIN)

