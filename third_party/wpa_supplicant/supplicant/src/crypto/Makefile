all: libcrypto.a

clean:
	rm -f *~ *.o *.d *.gcno *.gcda *.gcov libcrypto.a

install:
	@echo Nothing to be made.


include ../lib.rules

CFLAGS += -DCONFIG_CRYPTO_INTERNAL
CFLAGS += -DCONFIG_TLS_INTERNAL_CLIENT
CFLAGS += -DCONFIG_TLS_INTERNAL_SERVER
#CFLAGS += -DALL_DH_GROUPS
#CFLAGS += -DCONFIG_SHA256
#CFLAGS += -DCONFIG_SHA384
#CFLAGS += -DCONFIG_HMAC_SHA384_KDF
#CFLAGS += -DCONFIG_INTERNAL_SHA384

LIB_OBJS= \
	aes-cbc.o \
	
	aes-ctr.o \
	aes-eax.o \
	aes-encblock.o \

	aes-internal.o \
	aes-internal-dec.o \
	aes-internal-enc.o \
	aes-omac1.o \
	aes-siv.o \
	aes-unwrap.o \
	aes-wrap.o \
	des-internal.o \
	dh_group5.o \
	dh_groups.o \
	md4-internal.o \
	md5.o \
	md5-internal.o \
	md5-non-fips.o \
	milenage.o \
	ms_funcs.o \
	rc4.o \
	sha1.o \
	sha1-internal.o \
	sha1-pbkdf2.o \

	sha1-tlsprf.o \
	sha1-tprf.o \
	sha256.o \


	sha256-internal.o \
	sha384.o \
	sha384-prf.o \
	sha384-internal.o \
	sha512-internal.o

LIB_OBJS += crypto_internal.o
LIB_OBJS += crypto_internal-cipher.o
LIB_OBJS += crypto_internal-modexp.o
LIB_OBJS += crypto_internal-rsa.o
LIB_OBJS += tls_internal.o
LIB_OBJS += fips_prf_internal.o
ifndef TEST_FUZZ
LIB_OBJS += random.o
endif


libcrypto.a: $(LIB_OBJS)
	$(AR) crT $@ $?

-include $(OBJS:%.o=%.d)
