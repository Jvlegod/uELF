TARGET = uelf
SRC = uELF.c
OBJDIR = build
OBJ = $(OBJDIR)/$(SRC:.c=.o)
CC = gcc
CFLAGS = -Wall -O2
LDLIBS = -ldl

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: %.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -rf $(OBJDIR) $(TARGET)
