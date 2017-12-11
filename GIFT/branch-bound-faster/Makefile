CC=g++
CFLAGS=-std=c++11

search.out: *.cpp Makefile
	$(CC) $(CFLAGS) -D NDEBUG -O3 main.cpp -o search.out

search-dbg.out: *.cpp Makefile
	$(CC) $(CFLAGS) main.cpp -o search-dbg.out
