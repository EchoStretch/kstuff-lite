all: lib.a lib-ps5.a lib-elf.a lib-elf-ps5.a

clean:
	rm -f lib.a lib-*.a *.o syscalls.asm syscalls-ps5.asm

dl.o: dl.c
	gcc -c -isystem ../freebsd-headers -nostdinc -fno-stack-protector dl.c -o dl.o -fPIE -ffreestanding

crt-elf-c.o: crt-elf-c.c r0gdb-bootstrap.h shellcore-imports.h
	gcc -c -isystem ../freebsd-headers -nostdinc -fno-stack-protector -O3 crt-elf-c.c -o crt-elf-c.o -fPIE -ffreestanding

crt.o: crt.asm
	yasm -f elf64 crt.asm

crt-elf.o: crt-elf.asm
	yasm -f elf64 crt-elf.asm

rfork.o: rfork.asm
	yasm -f elf64 rfork.asm

syscalls.o: syscalls.asm
	yasm -f elf64 syscalls.asm

syscalls.asm: syscalls.py syscalls.txt
	python3 syscalls.py > syscalls.asm

syscalls-ps5.o: syscalls-ps5.asm
	yasm -f elf64 syscalls-ps5.asm

syscalls-ps5.asm: syscalls-ps5.py
	python3 syscalls-ps5.py > syscalls-ps5.asm

lib.a: crt.o rfork.o dl.o syscalls.o
	ld -r crt.o rfork.o dl.o syscalls.o -o lib.a

lib-ps5.a: crt.o dl.o syscalls-ps5.o
	ld -r crt.o dl.o syscalls-ps5.o -o lib-ps5.a

lib-elf.a: crt-elf.o crt-elf-c.o dl.o syscalls.o
	ld -r crt-elf.o crt-elf-c.o dl.o syscalls.o -o lib-elf.a

lib-elf-ps5.a: crt-elf.o crt-elf-c.o dl.o syscalls-ps5.o
	ld -r crt-elf.o crt-elf-c.o dl.o syscalls-ps5.o -o lib-elf-ps5.a
