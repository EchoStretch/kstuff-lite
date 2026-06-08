LOADER_OPT ?= -O2

#   Copyright (C) 2025 John Törnblom
#
# This file is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING. If not see
# <http://www.gnu.org/licenses/>.

PS5_HOST ?= ps5
PS5_PORT ?= 9021

ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK is undefined)
endif

CFLAGS += -Wall -Werror
CPPFLAGS += -Iinclude

LDFLAGS += -lz \
           -lSceSystemService \
           -lSceUserService \
           -lSceAppInstUtil \
           -lSceFsInternalForVsh \
           -lsqlite3

# Automatically grab all .c files in src/
SRC := $(filter-out src/payload_bin.c,$(shell find src -name '*.c'))

all: kstuff.elf

../ps5-kstuff/payload.bin:
	$(MAKE) -C ../ps5-kstuff/

src/payload_bin.c: ../ps5-kstuff/payload.bin
	xxd -i $< > $@

kstuff.elf: src/payload_bin.c $(SRC)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LOADER_OPT) $(SRC) -o $@ $(LDFLAGS)
	strip $@

clean:
	rm -f src/payload_bin.c *.o *.elf

test: kstuff.elf
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $^

