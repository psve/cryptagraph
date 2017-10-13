CC=g++
SFLAGS=-lz -ldl -static-libgcc
CFLAGS=-O3 -static -std=c++11 -D NDEBUG
DFLAGS=-std=c++11 -ggdb -fsanitize=address
AR=ar

iter-elp.out:
	$(CC) $(CFLAGS) bin_iter_elp.cpp -o iter-elp.out

iter-cnt.out:
	$(CC) $(CFLAGS) bin_iter_cnt.cpp -o iter-cnt.out

push: iter-elp.out
	strip iter-elp.out
	scp iter-elp.out array.job hpc:~/gift-hull/
