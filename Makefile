CXXFLAGS=-std=c++14 -Wall -Wextra -g

all: tests.o example

example: sha256.o example.cpp

sha256.o: sha256.cpp
tests.o: tests.cpp

clean:
	rm -f tests.o sha256.o example
