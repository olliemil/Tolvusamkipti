CXX=g++
CXXFLAGS=-O2 -Wall -std=c++17

all: tsamgroup21 client

tsamgroup21: tsamgroup21.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

client: client.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

clean:
	rm -f tsamgroup21 client

	
