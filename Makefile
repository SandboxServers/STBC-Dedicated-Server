# STBC Dedicated Server - Top-level Makefile
# Cross-compiles DDraw proxy DLL from Linux/WSL2 for 32-bit Windows
# and deploys to game directory.

# Game installation paths (in-repo copies)
SERVER_DIR    ?= game/server
CLIENT_DIR    ?= game/client
STOCKDEDI_DIR ?= game/stock-dedi

# Compiler settings
CC       = i686-w64-mingw32-gcc
CFLAGS   = -Wall -O2 -fno-omit-frame-pointer -std=c99 -DWIN32 -D_WIN32
LDFLAGS  = -shared -static-libgcc -Wl,--enable-stdcall-fixup
LIBS     = -lgdi32 -lws2_32

# Source layout
SRC_DIR  = src/proxy
SRCS     = $(SRC_DIR)/ddraw_main.c $(SRC_DIR)/ddraw_ddraw7.c \
           $(SRC_DIR)/ddraw_surface7.c $(SRC_DIR)/ddraw_d3d7.c
OBJS     = $(SRCS:.c=.o)
OBS_OBJS = $(SRCS:$(SRC_DIR)/%.c=$(SRC_DIR)/obs_%.o)
# ddraw_main.c is split into include-components under src/proxy/ddraw_main/.
# Keep these as explicit dependencies so incremental builds pick up .inc.c edits
# (otherwise "make build" can incorrectly report "Nothing to be done").
DDRAW_MAIN_PARTS = $(wildcard $(SRC_DIR)/ddraw_main/*.inc.c)
DEF      = $(SRC_DIR)/ddraw.def
HEADER   = $(SRC_DIR)/ddraw_proxy.h
TARGET   = ddraw.dll
OBS_TARGET = ddraw_observe.dll

.PHONY: all build build-observe deploy deploy-server deploy-client deploy-stockdedi \
        run run-server run-client run-stockdedi clean kill \
        logs logs-server logs-client logs-stockdedi

all: build

build: $(TARGET)

$(TARGET): $(OBJS) $(DEF)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(DEF) $(LIBS)
	@echo "Built $(TARGET)"

$(SRC_DIR)/ddraw_main.o: $(SRC_DIR)/ddraw_main.c $(HEADER) $(DDRAW_MAIN_PARTS)
	$(CC) $(CFLAGS) -c $< -o $@

$(SRC_DIR)/%.o: $(SRC_DIR)/%.c $(HEADER)
	$(CC) $(CFLAGS) -c $< -o $@

# Observer build: passive-only proxy (no VEH, no patches, just logging)
build-observe: $(OBS_TARGET)

$(OBS_TARGET): $(OBS_OBJS) $(DEF)
	$(CC) $(LDFLAGS) -o $@ $(OBS_OBJS) $(DEF) $(LIBS)
	@echo "Built $(OBS_TARGET) (observe-only)"

$(SRC_DIR)/obs_ddraw_main.o: $(SRC_DIR)/ddraw_main.c $(HEADER) $(DDRAW_MAIN_PARTS)
	$(CC) $(CFLAGS) -DOBSERVE_ONLY -c $< -o $@

$(SRC_DIR)/obs_%.o: $(SRC_DIR)/%.c $(HEADER)
	$(CC) $(CFLAGS) -DOBSERVE_ONLY -c $< -o $@

# Deploy server: proxy DLL + DedicatedServer scripts + dedicated.cfg
deploy-server: $(TARGET)
	/mnt/c/Windows/System32/taskkill.exe /f /im stbc.exe 2>/dev/null || true
	mkdir -p "$(SERVER_DIR)/scripts/Custom"
	cp $(TARGET) "$(SERVER_DIR)/"
	cp src/scripts/Custom/DedicatedServer.py "$(SERVER_DIR)/scripts/Custom/"
	cp src/scripts/Custom/DSSwig.py "$(SERVER_DIR)/scripts/Custom/"
	cp src/scripts/Custom/DSImportHook.py "$(SERVER_DIR)/scripts/Custom/"
	cp src/scripts/Custom/DSPatches.py "$(SERVER_DIR)/scripts/Custom/"
	cp src/scripts/Custom/DSHandlers.py "$(SERVER_DIR)/scripts/Custom/"
	cp src/scripts/Custom/DSNetHandlers.py "$(SERVER_DIR)/scripts/Custom/"
	cp src/scripts/Custom/StateDumper.py "$(SERVER_DIR)/scripts/Custom/"
	cp src/scripts/Custom/__init__.py "$(SERVER_DIR)/scripts/Custom/"
	rm -f "$(SERVER_DIR)/scripts/Custom/"*.pyc
	rm -f "$(SERVER_DIR)/scripts/Custom/_proxy_log.py"
	cp src/scripts/Local.py "$(SERVER_DIR)/scripts/"
	rm -f "$(SERVER_DIR)/scripts/Local.pyc"
	cp config/dedicated.cfg "$(SERVER_DIR)/"
	rm -f "$(SERVER_DIR)/"*.log
	@echo "Deployed SERVER to $(SERVER_DIR)"

# Deploy client: observe-only proxy DLL + ClientLogger + Observer scripts (no dedicated.cfg)
deploy-client: $(OBS_TARGET)
	mkdir -p "$(CLIENT_DIR)/scripts/Custom"
	cp $(OBS_TARGET) "$(CLIENT_DIR)/ddraw.dll"
	cp src/scripts/Custom/ClientLogger.py "$(CLIENT_DIR)/scripts/Custom/"
	cp src/scripts/Custom/Observer.py "$(CLIENT_DIR)/scripts/Custom/"
	cp src/scripts/Custom/StateDumper.py "$(CLIENT_DIR)/scripts/Custom/"
	cp src/scripts/Custom/__init__.py "$(CLIENT_DIR)/scripts/Custom/"
	rm -f "$(CLIENT_DIR)/scripts/Custom/"*.pyc
	rm -f "$(CLIENT_DIR)/scripts/Custom/_proxy_log.py"
	cp src/scripts/ClientLocal.py "$(CLIENT_DIR)/scripts/Local.py"
	rm -f "$(CLIENT_DIR)/scripts/Local.pyc"
	rm -f "$(CLIENT_DIR)/"*.log
	@echo "Deployed CLIENT to $(CLIENT_DIR)"

# Deploy stock-dedi: observe-only proxy DLL + Observer Python scripts (NO dedicated.cfg)
deploy-stockdedi: $(OBS_TARGET)
	/mnt/c/Windows/System32/taskkill.exe /f /im stbc.exe 2>/dev/null || true
	mkdir -p "$(STOCKDEDI_DIR)/scripts/Custom"
	cp $(OBS_TARGET) "$(STOCKDEDI_DIR)/ddraw.dll"
	cp src/scripts/Custom/Observer.py "$(STOCKDEDI_DIR)/scripts/Custom/"
	cp src/scripts/Custom/StateDumper.py "$(STOCKDEDI_DIR)/scripts/Custom/"
	cp src/scripts/Custom/__init__.py "$(STOCKDEDI_DIR)/scripts/Custom/"
	rm -f "$(STOCKDEDI_DIR)/scripts/Custom/"*.pyc
	rm -f "$(STOCKDEDI_DIR)/scripts/Custom/_proxy_log.py"
	cp src/scripts/ObserverLocal.py "$(STOCKDEDI_DIR)/scripts/Local.py"
	rm -f "$(STOCKDEDI_DIR)/scripts/Local.pyc"
	rm -f "$(STOCKDEDI_DIR)/"*.log
	@echo "Deployed STOCK-DEDI (observer) to $(STOCKDEDI_DIR)"

# Deploy both server + client
deploy: deploy-server deploy-client

# Run targets
run-server: deploy-server
	/mnt/c/Windows/System32/cmd.exe /c start "" "$(shell wslpath -w $(realpath $(SERVER_DIR)))\stbc.exe"

run-client: deploy-client
	/mnt/c/Windows/System32/cmd.exe /c start "" "$(shell wslpath -w $(realpath $(CLIENT_DIR)))\bridgecommander.exe"

run-stockdedi: deploy-stockdedi
	/mnt/c/Windows/System32/cmd.exe /c start "" "$(shell wslpath -w $(realpath $(STOCKDEDI_DIR)))\bridgecommander.exe"

kill:
	/mnt/c/Windows/System32/taskkill.exe /f /im stbc.exe 2>/dev/null || true

# Logs
logs-server:
	@echo "=== ddraw_proxy.log ===" && cat "$(SERVER_DIR)/ddraw_proxy.log" 2>/dev/null || echo "No server proxy log"
	@echo "" && echo "=== pydebug.log ===" && cat "$(SERVER_DIR)/pydebug.log" 2>/dev/null || echo "No pydebug log"
	@echo "" && echo "=== packet_trace.log ===" && cat "$(SERVER_DIR)/packet_trace.log" 2>/dev/null || echo "No packet trace"
	@echo "" && echo "=== tick_trace.log ===" && cat "$(SERVER_DIR)/tick_trace.log" 2>/dev/null || echo "No tick trace"
	@echo "" && echo "=== dedicated_init.log ===" && cat "$(SERVER_DIR)/dedicated_init.log" 2>/dev/null || echo "No dedicated init log"
	@echo "" && echo "=== state_dump.log ===" && cat "$(SERVER_DIR)/state_dump.log" 2>/dev/null || echo "No state dump log"

logs-client:
	@echo "=== ddraw_proxy.log ===" && cat "$(CLIENT_DIR)/ddraw_proxy.log" 2>/dev/null || echo "No client proxy log"
	@echo "" && echo "=== pydebug.log ===" && cat "$(CLIENT_DIR)/pydebug.log" 2>/dev/null || echo "No pydebug log"
	@echo "" && echo "=== packet_trace.log ===" && cat "$(CLIENT_DIR)/packet_trace.log" 2>/dev/null || echo "No client packet trace"
	@echo "" && echo "=== tick_trace.log ===" && cat "$(CLIENT_DIR)/tick_trace.log" 2>/dev/null || echo "No client tick trace"
	@echo "" && echo "=== message_trace.log ===" && cat "$(CLIENT_DIR)/message_trace.log" 2>/dev/null || echo "No client message trace"
	@echo "" && echo "=== client_debug.log ===" && cat "$(CLIENT_DIR)/client_debug.log" 2>/dev/null || echo "No client debug log"
	@echo "" && echo "=== observer.log ===" && cat "$(CLIENT_DIR)/observer.log" 2>/dev/null || echo "No observer log"
	@echo "" && echo "=== state_dump.log ===" && cat "$(CLIENT_DIR)/state_dump.log" 2>/dev/null || echo "No state dump log"

logs-stockdedi:
	@echo "=== ddraw_proxy.log ===" && cat "$(STOCKDEDI_DIR)/ddraw_proxy.log" 2>/dev/null || echo "No proxy log"
	@echo "" && echo "=== pydebug.log ===" && cat "$(STOCKDEDI_DIR)/pydebug.log" 2>/dev/null || echo "No pydebug log"
	@echo "" && echo "=== packet_trace.log ===" && cat "$(STOCKDEDI_DIR)/packet_trace.log" 2>/dev/null || echo "No packet trace"
	@echo "" && echo "=== tick_trace.log ===" && cat "$(STOCKDEDI_DIR)/tick_trace.log" 2>/dev/null || echo "No stock-dedi tick trace"
	@echo "" && echo "=== message_trace.log ===" && cat "$(STOCKDEDI_DIR)/message_trace.log" 2>/dev/null || echo "No message trace"
	@echo "" && echo "=== observer.log ===" && cat "$(STOCKDEDI_DIR)/observer.log" 2>/dev/null || echo "No observer log"
	@echo "" && echo "=== state_dump.log ===" && cat "$(STOCKDEDI_DIR)/state_dump.log" 2>/dev/null || echo "No state dump log"

logs: logs-server

clean:
	rm -f $(OBJS) $(OBS_OBJS) $(TARGET) $(OBS_TARGET)
