CC := gcc
CFLAGS = -Wall -Wextra -g3 -lbfd

main: main.o
	$(CC) $^ -o $@ $(CFLAGS) 

.PHONY: clean
clean:
	rm main main.o

.DEFAULT_GOAL = main




