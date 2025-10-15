TARGET = uelf
SRC = uELF.c
OBJDIR = build
OBJ = $(OBJDIR)/$(SRC:.c=.o)
CC = gcc
CFLAGS = -Wall -O2

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: %.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -rf $(OBJDIR) $(TARGET)
