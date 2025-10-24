CXX=g++
CXXFLAGS=-O2 -Wall -std=c++17

all: tsamgroup21 client

tsamgroup21: tsamgroup21.cpp helper.cpp helper.hpp
	$(CXX) $(CXXFLAGS) -o $@ tsamgroup21.cpp helper.cpp

client: client.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

clean:
	rm -f tsamgroup21 client

	
