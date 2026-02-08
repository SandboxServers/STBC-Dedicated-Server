# STBC Dedicated Server - Top-level Makefile
# Cross-compiles DDraw proxy DLL from Linux/WSL2 for 32-bit Windows
# and deploys to game directory.

# Game installation path (override with: make GAME_DIR="C:\path\to\game")
GAME_DIR ?= /mnt/c/GOG Games/Star Trek Bridge Commander

# Compiler settings
CC       = i686-w64-mingw32-gcc
CFLAGS   = -Wall -O2 -std=c99 -DWIN32 -D_WIN32
LDFLAGS  = -shared -static-libgcc -Wl,--enable-stdcall-fixup
LIBS     = -lgdi32 -lws2_32

# Source layout
SRC_DIR  = src/proxy
SRCS     = $(SRC_DIR)/ddraw_main.c $(SRC_DIR)/ddraw_ddraw7.c \
           $(SRC_DIR)/ddraw_surface7.c $(SRC_DIR)/ddraw_d3d7.c
OBJS     = $(SRCS:.c=.o)
DEF      = $(SRC_DIR)/ddraw.def
HEADER   = $(SRC_DIR)/ddraw_proxy.h
TARGET   = ddraw.dll

.PHONY: all build deploy run clean logs kill

all: build

build: $(TARGET)

$(TARGET): $(OBJS) $(DEF)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(DEF) $(LIBS)
	@echo "Built $(TARGET)"

$(SRC_DIR)/%.o: $(SRC_DIR)/%.c $(HEADER)
	$(CC) $(CFLAGS) -c $< -o $@

deploy: $(TARGET)
	/mnt/c/Windows/System32/taskkill.exe /f /im stbc.exe 2>/dev/null || true
	mkdir -p "$(GAME_DIR)/scripts/Custom"
	cp $(TARGET) "$(GAME_DIR)/"
	cp src/scripts/Custom/DedicatedServer.py "$(GAME_DIR)/scripts/Custom/"
	cp src/scripts/Custom/__init__.py "$(GAME_DIR)/scripts/Custom/"
	rm -f "$(GAME_DIR)/scripts/Custom/"*.pyc
	cp src/scripts/Local.py "$(GAME_DIR)/scripts/"
	rm -f "$(GAME_DIR)/scripts/Local.pyc"
	cp config/dedicated.cfg "$(GAME_DIR)/"
	@echo "Deployed to $(GAME_DIR)"

run: deploy
	cd "$(GAME_DIR)" && cmd.exe /c start stbc.exe

kill:
	/mnt/c/Windows/System32/taskkill.exe /f /im stbc.exe 2>/dev/null || true

logs:
	@cat "$(GAME_DIR)/ddraw_proxy.log" 2>/dev/null || echo "No log file found"

clean:
	rm -f $(OBJS) $(TARGET)
