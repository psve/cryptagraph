FLAGS=-std=c++11
CPPC=mpic++

mask-search-dbg: *.cpp *.hpp
	$(CPPC) $(FLAGS) -ggdb main.cpp -o mask-search

mask-search: *.cpp *.hpp
	$(CPPC) $(FLAGS) -fopenmp main.cpp -D NDEBUG -o mask-search
	strip mask-search

push: *.cpp *.hpp
	scp *.cpp *.hpp Makefile mask-search.job hpc:~/paper

clean:
	rm -f mask-search
