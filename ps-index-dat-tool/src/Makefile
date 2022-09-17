CC=gcc
CFLAGS=-Wall
LDFLAGS=-lz
SOURCES=mingw_mmap.c sha1.c tools.c aes.c sha2.c main.c
EXECUTABLE=ps-index-dat-tool
all:
	$(CC) $(CFLAGS) $(SOURCES) $(LDFLAGS) -o $(EXECUTABLE)
clean:
	rm -rf $(EXECUTABLE)