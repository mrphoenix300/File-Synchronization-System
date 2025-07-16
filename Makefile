CC = gcc
CFLAGS = -Wall -g -Iinclude
LDFLAGS = 

SRC_DIR = src
OBJ_DIR = build
BIN_DIR = bin

EXECUTABLES = fss_manager fss_console worker

.PRECIOUS: $(OBJ_DIR)/%.o

all: $(EXECUTABLES:%=$(BIN_DIR)/%)

$(BIN_DIR)/%: $(OBJ_DIR)/%.o | $(BIN_DIR)
	$(CC) $^ -o $@ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

.PHONY: all clean 