LIBDIR = /usr/lib

CFLAGS_GCC_4 = -c -fno-exceptions -fno-rtti -fno-const-strings
CFLAGS = -c -fno-exceptions -fno-rtti -w
BUILD_LIB = g++ -v -shared -lz -lresolv -lssl -lcrypto -Wl,-soname,libipworksssh.so.9,-version-script=ipworksssh.ver -o libipworksssh.so.9.0 ipworksssh.o
STRIP = strip -g -x --strip-unneeded libipworksssh.so.9.0

ifeq ($(origin OSTYPE), undefined)
OSTYPE = $(shell uname -s)
endif

MACOS = "darwin Darwin macos"
SOLARIS = "solaris SunOS sco SCO SCO_SV solaris2.9"
LINUX = "linux linux-gnu Linux"
AIX = "aix AIX"
FREEBSD = "FreeBSD"
MACOSTYPE = ""
MACOSPPC = "powerpc"
MACOSFLAGS = ""

#note: if building a universal build library in Mac OS X 10.4 on a PPC machine, you must have installed MacOSX10.4u.sdk
ifneq (,$(findstring $(OSTYPE),$(MACOS)))
MACOSTYPE = $(shell uname -p)
MACOSUSER = $(shell whoami)
ifneq (,$(findstring $(MACOSTYPE),$(MACOSPPC)))
OS_CFLAGS = -fpascal-strings -fPIC -D MACOS -arch ppc -arch i386 -lsysroot /Developer/SDKs/MacOSX10.4u.sdk 
MACOSFLAGS = -Wl,-syslibroot,/Developer/SDKs/MacOSX10.4u.sdk -arch ppc -arch i386
else
OS_CFLAGS = -fpascal-strings -fPIC -D MACOS -arch i386 -arch x86_64
MACOSFLAGS = -Wl -arch i386 -arch x86_64
endif
BUILD_LIB = g++ -v -dynamiclib -prebind -current_version 9.0 -o libipworksssh.so.9.0 $(MACOSFLAGS) -lc -shared-libgcc -lstdc++ -lz -lresolv -lssl -lcrypto ipworksssh.o -framework Carbon -framework Security
STRIP = strip -x -S libipworksssh.so.9.0
endif

ifneq (,$(findstring $(OSTYPE),$(SOLARIS)))
OS_CFLAGS = -fPIC -D SOLARIS
BUILD_LIB = g++ -shared -static-libgcc -Wl,-Mipworksssh.ver -o libipworksssh.so.9.0 -lsocket -lz -lresolv -lssl -lcrypto ipworksssh.o
STRIP = strip -x libipworksssh.so.9.0
endif

ifneq (,$(findstring $(OSTYPE),$(LINUX)))
OS_CFLAGS = -fPIC -D LINUX
endif

ifneq (,$(findstring $(OSTYPE),$(FREEBSD)))
OS_CFLAGS = -fPIC -D FreeBSD
BUILD_LIB = g++ -v -shared -lz -lssl -lcrypto -Wl,-soname,libipworksssh.so.9,-version-script=ipworksssh.ver -o libipworksssh.so.9.0 ipworksssh.o
endif

all: lib

lib: ipworksssh.o
	mkdir -p ../lib
	$(BUILD_LIB)
	$(STRIP)
	mv libipworksssh.so.9.0 ../lib
	ln -s libipworksssh.so.9.0 ../lib/libipworksssh.so.9
	ln -s libipworksssh.so.9 ../lib/libipworksssh.so

install:
	ln -f -s libipworksssh.so.9.0 $(LIBDIR)/libipworksssh.so.9
	ln -f -s libipworksssh.so.9 $(LIBDIR)/libipworksssh.so
	cp -f ../lib/libipworksssh.so.9.0 $(LIBDIR)

uninstall:
	rm -rf $(LIBDIR)/libipworksssh.so
	rm -rf $(LIBDIR)/libipworksssh.so.9
	rm -rf $(LIBDIR)/libipworksssh.so.9.0

# the following creates a framework for MacOS X (IPWorksSSH.framework)
macos_framework: ipworksssh.o
	mkdir -p ../IPWorksSSH.framework/Versions/9.0/
	g++ -v -dynamiclib -prebind  -seg1addr 0x14000000 -current_version 9  -install_name @executable_path/../Frameworks/IPWorksSSH.framework/Versions/9.0/IPWorksSSH -o ../IPWorksSSH.framework/Versions/9.0/IPWorksSSH $(MACOSFLAGS) -lc -shared-libgcc -lstdc++ -lz -lresolv -lssl -lcrypto ipworksssh.o -framework Carbon -framework Security

clean: 
	rm -rf *.o ../lib
	rm -rf /Users/$(MACOSUSER)/Library/Frameworks/IPWorksSSH.framework

%.o:%.cpp
	g++ $(CFLAGS) $(OS_CFLAGS) -o $*.o $*.cpp
