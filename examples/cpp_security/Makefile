# This Makefile was tested with GNU Make
CXX=g++ --std=c++17

# Use pkg-config to lookup the proper compiler and linker flags for LCM
CFLAGS=`pkg-config --cflags lcm` -g
LDFLAGS=`pkg-config --libs lcm`

msg_types=../lcm/*.lcm

all: exlcm/example_t.hpp exlcm/example_list_t.hpp \
	demo_instance

demo_instance: demo_instance.o
	$(CXX) -o $@ $^ $(LDFLAGS)

%.o: %.cpp exlcm/example_t.hpp
	$(CXX) $(CFLAGS) -I. -o $@ -c $< 

exlcm/%.hpp:
	lcm-gen -x ../types/*.lcm

clean:
	rm -f demo_instance
	rm -f *.o exlcm/*.o
	rm -f exlcm/*.hpp
