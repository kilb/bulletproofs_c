TARGET := riscv64-unknown-elf
CC := $(TARGET)-gcc
CFLAGS := -O3 -Ideps/molecule -I deps/secp256k1/src -I deps/secp256k1 -I c -I build -Wall -Werror -Wno-nonnull-compare -Wno-unused-function
LDFLAGS := -Wl,-static -fdata-sections -ffunction-sections -Wl,--gc-sections -Wl,-s
LIBCRYPTO_LIB := openssl/libcrypto.a

default: src/inner_product.c src/range_proof.c src/test.c $(LIBCRYPTO_LIB)
	$(CC) $^ -I openssl/include $(CFLAGS) $(LDFLAGS) -o test

$(LIBCRYPTO_LIB):
	cd openssl && \
		CFLAGS="-DNO_SYSLOG" ./Configure linux-generic64 no-threads no-sock no-shared no-dso no-stdio no-ui-console no-afalgeng && \
		make include/openssl/opensslconf.h include/crypto/bn_conf.h include/crypto/dso_conf.h && \
		make CC=riscv64-unknown-elf-gcc CFLAGS="-DNO_SYSLOG -O3" libcrypto.a

clean:
	rm test
	cd openssl && make clean

.PHONY: default clean
