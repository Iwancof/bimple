CC := gcc
CFLAGS = -Wall -Wextra -O2 -lbfd 

main: main.o
	$(CC) $^ -o $@ $(CFLAGS) 

.PHONY: clean
clean:
	rm main main.o

.DEFAULT_GOAL = main




