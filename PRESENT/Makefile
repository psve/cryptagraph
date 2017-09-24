FLAGS=-std=c++17 -fopenmp

mask-search: mask-search.cpp
	g++ $(FLAGS) -static mask-search.cpp -D NDEBUG -o mask-search
	strip mask-search

mask-search-dbg: mask-search.cpp
	g++ $(FLAGS) mask-search.cpp -o mask-search

push: mask-search mask-search.job
	scp mask-search mask-search.job hpc:~/paper

clean:
	rm -f mask-search
