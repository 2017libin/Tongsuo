CC=gcc
CFLAGS=-I/home/chase511/code_2023/Tongsuo/include
LDFLAGS=-L/home/chase511/code_2023/Tongsuo/

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS) -O2

threshold: threshold.o
	$(CC) -o threshold threshold.o -lcrypto $(LDFLAGS)  -Wl,-rpath=/home/chase511/code_2023/Tongsuo


clean:
	rm -rf *.o threshold
