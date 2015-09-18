#
# IP*Works! SSH V9 C++ Edition - Demo Application
#
# Copyright (c) 2014 /n software inc. - All rights reserved. - www.nsoftware.com
#

ifeq ($(shell uname -m), x86_64)
  OS_CFLAGS = -D UNIX64
else
  OS_CFLAGS =
endif
ifeq ($(shell uname -m), amd64)
  OS_CFLAGS = -D UNIX64
endif

FRAMEWORK =
LD_FLAGS = -lz -lresolv -lssl -lcrypto
MACOS = "darwin Darwin macos"
FREEBSD = "FreeBSD"

ifeq ($(origin OSTYPE), undefined)
  OSTYPE = $(shell uname -s)
endif

ifneq (,$(findstring $(OSTYPE),$(MACOS)))
  OS_CFLAGS = -D UNIX64 -arch i386
  FRAMEWORK = -framework Carbon -framework Security
endif

ifneq (,$(findstring $(OSTYPE),$(FREEBSD)))
  LD_FLAGS = -lz -lssl -lcrypto
endif


all: ../../../src/ipworksssh.o
	g++ $(OS_CFLAGS) -o psclientgetprocess ../../../src/ipworksssh.o psclientgetprocess.cpp $(LD_FLAGS) $(FRAMEWORK)

../../../src/ipworksssh.o:
	cd ../../../src;make ipworksssh.o

clean:
	cd ../../../src;make clean
	rm -f psclientgetprocess *.o
