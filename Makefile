CC=g++49
CFLAGS=-g -lz  -lssl -lcrypto -w -fpermissive -lssh2 -I/usr/local/include -L/usr/local/lib   -lpthread
all: clean scanner ddos

ddos:
	$(CC) ddos.cpp ddos.h /data/projects/scanner/ipworksssh/src/ipworksssh.o -o ddos $(CFLAGS) 
scanner:
	$(CC) scanner.cpp /data/projects/scanner/ipworksssh/src/ipworksssh.o -o scanner $(CFLAGS) 

scanner.o:
	$(CC)  -c scanner.cpp $(CFLAGS)

clean:
	rm -f *.o scanner ddos
	
