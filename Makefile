# Makefile — duet-httpfs
# Tested on Arch Linux (pacman) and Debian/Ubuntu (apt)

CXX      ?= g++
CXXFLAGS  = -O2 -std=c++17 -Wall -Wextra \
            $(shell pkg-config --cflags fuse3 libcurl)
LDFLAGS   = $(shell pkg-config --libs   fuse3 libcurl) -lpthread
TARGET    = duet-httpfs
SRC       = duet-httpfs.cpp

.PHONY: all clean deps

all: json.hpp $(TARGET)

# Single-header JSON library — no build step needed
json.hpp:
	@echo "Downloading nlohmann/json..."
	wget -q -O json.hpp \
	  https://github.com/nlohmann/json/releases/download/v3.11.3/json.hpp
	@echo "  json.hpp downloaded."

$(TARGET): $(SRC) json.hpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)
	@echo "  Built $@"

# Install build dependencies
deps:
	@if command -v pacman >/dev/null 2>&1; then \
	    sudo pacman -S --needed fuse3 libcurl-gnutls; \
	elif command -v apt-get >/dev/null 2>&1; then \
	    sudo apt-get install -y libfuse3-dev libcurl4-openssl-dev; \
	else \
	    echo "Install fuse3 and libcurl dev packages for your distro."; \
	fi

clean:
	rm -f $(TARGET)