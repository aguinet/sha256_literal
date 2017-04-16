CXXFLAGS=-std=c++14

all: tests.o example

example: sha256.o example.cpp

sha256.o: sha256.cpp
tests.o: tests.cpp

clean:
	rm tests.o example
