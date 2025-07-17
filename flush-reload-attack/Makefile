# Compiler and flags
CXX = g++
CXXFLAGS = -I/usr/local/include/ssl
LDFLAGS = -L/usr/local/lib -lcrypto

# Targets
TARGETS = victim attacker

# Rules
all: $(TARGETS)

victim: victim.cpp
	$(CXX) victim.cpp -o victim $(CXXFLAGS) $(LDFLAGS)

attacker: attacker.cpp
	$(CXX) attacker.cpp -o attacker $(CXXFLAGS) $(LDFLAGS)

calibration: calibration.c
	$(CXX) calibration.c -o calibration

clean:
	rm -f $(TARGETS)
	rm -f calibration
	rm -f guess_key_*.txt

.PHONY: all clean
