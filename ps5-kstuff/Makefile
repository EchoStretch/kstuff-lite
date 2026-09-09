PROSPER0GDB_OPT ?= -O0
PAYLOAD_OPT ?= -O0
UELF_OPT ?= -O3
UELF_ARCH ?= -march=znver2 -mtune=znver2
KSTUFF_OBS ?= 0
KSTUFF_SELF_ELEVATION ?= 1

ALL_TARGETS := payload.bin
BUILD_CONFIG := .build-config

ifeq ($(KSTUFF_OBS),1)
ifndef PS5_PAYLOAD_SDK
$(error PS5_PAYLOAD_SDK is undefined)
endif
ALL_TARGETS += debug-reader.bin
endif

all: $(ALL_TARGETS)

clean:
	rm -f payload.elf payload.bin debug-reader.elf debug-reader.bin freebsd-loader kelf kelf.o structs.h structs.inc uelf/uelf uelf/uelf.bin uelf/crt.o $(BUILD_CONFIG)

.PHONY: FORCE
FORCE:

$(BUILD_CONFIG): FORCE
	@tmp="$@.tmp"; \
	printf 'KSTUFF_OBS=%s\n' "$(KSTUFF_OBS)" > "$$tmp"; \
	printf 'KSTUFF_SELF_ELEVATION=%s\n' "$(KSTUFF_SELF_ELEVATION)" >> "$$tmp"; \
	printf 'EXTRA_CFLAGS=%s\n' "$(EXTRA_CFLAGS)" >> "$$tmp"; \
	printf 'PAYLOAD_OPT=%s\n' "$(PAYLOAD_OPT)" >> "$$tmp"; \
	printf 'UELF_OPT=%s\n' "$(UELF_OPT)" >> "$$tmp"; \
	printf 'UELF_ARCH=%s\n' "$(UELF_ARCH)" >> "$$tmp"; \
	if test -f "$@" && cmp -s "$$tmp" "$@"; then rm -f "$$tmp"; else mv "$$tmp" "$@"; fi

../lib/lib-elf-ps5.a: FORCE
	cd ../lib; $(MAKE)

../prosper0gdb/prosper0gdb.o: FORCE
	cd ../prosper0gdb; $(MAKE) PROSPER0GDB_OPT="$(PROSPER0GDB_OPT)"

structs.inc: structs-ps5.inc
	cp structs-ps5.inc structs.inc

payload.elf: ../lib/lib-elf-ps5.a ../prosper0gdb/prosper0gdb.o main.c kelf uelf/uelf.bin $(BUILD_CONFIG) shellcore_patches/*
	gcc $(PAYLOAD_OPT) -isystem ../freebsd-headers -nostdinc -nostdlib -fno-stack-protector -static ../lib/lib-elf-ps5.a ../prosper0gdb/prosper0gdb.o $(EXTRA_CFLAGS) -DKSTUFF_OBS=$(KSTUFF_OBS) main.c -DPS5KEK ../prosper0gdb/dbg.c -Wl,-gc-sections -o payload.elf -fPIE -ffreestanding -no-pie -Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384

payloa%.bin: payloa%.elf
	objcopy $< --only-section .text --only-section .data --only-section .bss --only-section .rodata -O binary $@
	python3 ../lib/frankenelf.py $@

kelf.o: kelf.asm structs.inc
	yasm -f elf64 -g dwarf2 kelf.asm -o kelf.o

kelf: kelf.o
	gcc -nostdlib -shared kelf.o -o kelf

structs.h: structs.inc
	sed 's/^%/#/' structs.inc > structs.h

uelf/crt.o: uelf/crt.asm
	yasm uelf/crt.asm -f elf64 -o uelf/crt.o

uelf/uelf: uelf/*.c uelf/*.h structs.h uelf/crt.o BearSSL/build/libbearssl.a isa-l_crypto/bin/isa-l_crypto.a $(BUILD_CONFIG)
	gcc -Wl,-Bsymbolic -Wl,-gc-sections -ffunction-sections -fdata-sections $(UELF_OPT) $(UELF_ARCH) -g -isystem ../freebsd-headers -isystem isa-l_crypto/include -nostdinc -nostdlib -mgeneral-regs-only -fno-stack-protector -fPIE -fPIC -shared -fvisibility=hidden -ffreestanding uelf/crt.o $(EXTRA_CFLAGS) -DKSTUFF_OBS=$(KSTUFF_OBS) -DKSTUFF_SELF_ELEVATION=$(KSTUFF_SELF_ELEVATION) uelf/*.c BearSSL/build/libbearssl.a isa-l_crypto/bin/isa-l_crypto.a -o uelf/uelf -Wl,-z,max-page-size=4096

uelf/uelf.bin: uelf/uelf
	objcopy --strip-all $< $@

ifeq ($(KSTUFF_OBS),1)
debug-reader.elf: debug-reader.c uelf/shared_area.h debug-reader.mk
	$(MAKE) -f debug-reader.mk $@ PS5_PAYLOAD_SDK="$(PS5_PAYLOAD_SDK)"

debug-reader.bin: debug-reader.elf debug-reader.mk
	$(MAKE) -f debug-reader.mk $@ PS5_PAYLOAD_SDK="$(PS5_PAYLOAD_SDK)"
endif

BearSSL/build/libbearssl.a: build_bearssl.sh overrides.h
	bash build_bearssl.sh

isa-l_crypto/bin/isa-l_crypto.a: build_isal_crypto.sh isa_l_crypto_ps5_minimal.c isa_l_crypto_ps5_sha256_zen2.asm
	bash build_isal_crypto.sh
