# Makefile -- build both PIE and non-PIE versions of test/*.c
# Usage:
#   make          # build both
#   make pie      # build PIE (bin/main-pie)
#   make nopie    # build non-PIE (bin/main-nopie)
#   make run-pie
#   make run-nopie
#   make check
#   make clean

CC ?= gcc
CFLAGS ?= -O2 -g
SRC_DIR := ./
SRCS := $(wildcard $(SRC_DIR)/*.c)

PIE_BUILD_DIR := build/pie
NOPIE_BUILD_DIR := build/nopie
BIN_DIR := bin

PIE_CFLAGS := $(CFLAGS) -fPIE
PIE_LDFLAGS := -pie

NOPIE_CFLAGS := $(CFLAGS) -fno-pie
# -Wl,-no-pie passes -no-pie directly to the linker driver; -no-pie is also supported by some toolchains
NOPIE_LDFLAGS := -Wl,-no-pie

PIE_OBJS := $(patsubst $(SRC_DIR)/%.c,$(PIE_BUILD_DIR)/%.o,$(SRCS))
NOPIE_OBJS := $(patsubst $(SRC_DIR)/%.c,$(NOPIE_BUILD_DIR)/%.o,$(SRCS))

PIE_BIN := $(BIN_DIR)/main-pie
NOPIE_BIN := $(BIN_DIR)/main-nopie

.PHONY: all pie nopie clean check run-pie run-nopie

all: pie nopie

# --- PIE build ---
pie: $(PIE_BIN)

$(PIE_BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(PIE_BUILD_DIR)
	$(CC) $(PIE_CFLAGS) -c $< -o $@

$(PIE_BIN): $(PIE_OBJS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(PIE_OBJS) -o $@ $(PIE_LDFLAGS)
	@echo "Built PIE binary: $@"

# --- non-PIE build ---
nopie: $(NOPIE_BIN)

$(NOPIE_BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(NOPIE_BUILD_DIR)
	$(CC) $(NOPIE_CFLAGS) -c $< -o $@

$(NOPIE_BIN): $(NOPIE_OBJS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(NOPIE_OBJS) -o $@ $(NOPIE_LDFLAGS)
	@echo "Built non-PIE binary: $@"

# run helpers
run-pie: pie
	@echo "Running $(PIE_BIN):"
	@$(PIE_BIN)

run-nopie: nopie
	@echo "Running $(NOPIE_BIN):"
	@$(NOPIE_BIN)

# quick check (ELF Type)
check: pie nopie
	@echo "---- $(PIE_BIN) ELF header ----"
	@readelf -h $(PIE_BIN) | sed -n '1,20p'
	@echo
	@echo "---- $(NOPIE_BIN) ELF header ----"
	@readelf -h $(NOPIE_BIN) | sed -n '1,20p'

clean:
	@rm -rf $(PIE_BUILD_DIR) $(NOPIE_BUILD_DIR) $(BIN_DIR)
	@echo "cleaned."

