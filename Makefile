CXX = g++
CXXFLAGS = -std=c++11 -Wall -g -pthread $(shell pkg-config --cflags spead2) -O3
LDFLAGS = -L$(SPEAD2_DIR)/src $(shell pkg-config --libs --static spead2) -lpcap -lboost_program_options -lboost_system -pthread -ltbb

all: digitiser_decode

digitiser_decode: digitiser_decode.o
	$(CXX) -o $@ $< $(LDFLAGS)

%.o: %.cpp Makefile
	$(CXX) -c $< $(CXXFLAGS)

clean:
	rm -f digitiser_decode digitiser_decode.o
