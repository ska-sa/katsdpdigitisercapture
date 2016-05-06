CXX = g++
SPEAD2_DIR = ../../spead2
CXXFLAGS = -std=c++11 -Wall -g -pthread -I$(SPEAD2_DIR)/src -O3
LDFLAGS = -L$(SPEAD2_DIR)/src -lspead2 -lpcap -lboost_program_options -lboost_system -pthread -ltbb

all: digitiser_decode

digitiser_decode: digitiser_decode.o $(SPEAD2_DIR)/src/libspead2.a
	$(CXX) -o $@ $< $(LDFLAGS)

%.o: %.cpp Makefile
	$(CXX) -c $< $(CXXFLAGS)

clean:
	rm -f digitiser_decode digitiser_decode.o
