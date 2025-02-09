CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++11 -Iinclude
LDFLAGS = -lpcap

TARGET = csa-attack

SRCS = main.cpp csa_attack.cpp pcap_handler.cpp
OBJS = $(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
