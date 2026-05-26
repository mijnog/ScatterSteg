CC      = gcc
CFLAGS  = -Wall -Wextra -std=c17 -g
LIBS    = -lsodium -lpng

SRCS    = main.c prng.c embed.c png_io.c
OBJS    = $(SRCS:.c=.o)
TARGET  = scattersteg

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)