# build helloworld executable when user executes "make"
CCFLAGS = -O3 -Wall -static -g0
LDFLAGS = -Wl,--strip-all

objects = main.c relay.c nat.c log.c utils.c ping.c dns.c info.c checksum.c

nat: $(objects)
	$(CC) $(CCFLAGS) -o nat $(objects) $(LDFLAGS) 

all: nat
        
# remove object files and executable when user executes "make clean"
clean:
	rm -rf *.o nat
