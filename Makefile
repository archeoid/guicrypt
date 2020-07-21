# Install
BIN = guicrypt

# Flags
CFLAGS += -g -o -std=c99 -Wall

SRC = main.c src/util.c src/gui.c src/crypt.c
OBJ = $(SRC:.c=.o)

LIBS = -lglfw -lGL -lm -lGLU -lGLEW -ltomcrypt -lcrypto -Llib
INCLUDE = -Iinclude -Iinclude/tomcrypt -Iinclude/nuklear
$(BIN):
	@mkdir -p bin
	@rm -f bin/$(BIN) $(OBJS)
	$(CC) $(SRC) $(INCLUDE) $(CFLAGS) -o bin/$(BIN) $(LIBS)

run: $(BIN)
	./bin/$(BIN)

clean: 
	@rm -f bin/$(BIN) $(OBJS)

.PHONY: run clean

