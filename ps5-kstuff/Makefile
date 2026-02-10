all: payload.bin

clean:
	rm -f payload.elf payload.bin  freebsd-loader kelf kelf.o structs.h structs.inc uelf/uelf uelf/uelf.bin uelf/crt.o

../lib/lib-elf-ps5.a:
	cd ../lib; make

../prosper0gdb/prosper0gdb.o:
	cd ../prosper0gdb; make

structs.inc: structs-ps5.inc
	cp structs-ps5.inc structs.inc

payload.elf: ../lib/lib-elf-ps5.a ../prosper0gdb/prosper0gdb.o main.c kelf uelf/uelf.bin
	gcc -O0 -isystem ../freebsd-headers -nostdinc -nostdlib -fno-stack-protector -static ../lib/lib-elf-ps5.a ../prosper0gdb/prosper0gdb.o $(EXTRA_CFLAGS) main.c -DPS5KEK ../prosper0gdb/dbg.c -Wl,-gc-sections -o payload.elf -fPIE -ffreestanding -no-pie -Wl,-z,max-page-size=16384 -Wl,-zcommon-page-size=16384

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

uelf/uelf: uelf/*.c uelf/*.h structs.h uelf/crt.o BearSSL/build/libbearssl.a libtomcrypt/libtomcrypt.a
	gcc -Wl,-Bsymbolic -Wl,-gc-sections -ffunction-sections -fdata-sections -O3 -g -isystem ../freebsd-headers -nostdinc -nostdlib -mgeneral-regs-only -fno-stack-protector -fPIE -fPIC -shared -fvisibility=hidden -ffreestanding uelf/crt.o $(EXTRA_CFLAGS) uelf/*.c -L BearSSL/build -lbearssl -L libtomcrypt -ltomcrypt -o uelf/uelf -Wl,-z,max-page-size=4096

uelf/uelf.bin: uelf/uelf
	objcopy --strip-all $< $@

BearSSL/build/libbearssl.a: build_bearssl.sh overrides.h
	bash build_bearssl.sh

libtomcrypt/libtomcrypt.a: build_libtomcrypt.sh overrides.h
	bash build_libtomcrypt.sh
