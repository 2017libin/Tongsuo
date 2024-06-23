CC=gcc
CFLAGS=-I/home/chase511/code_2023/Tongsuo/include
LDFLAGS=-L/home/chase511/code_2023/Tongsuo

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

perf: sm.o
	$(CC) -o sm sm.o -lcrypto $(LDFLAGS) -Wl,-rpath=..

clean:
	rm -rf *.o sm
