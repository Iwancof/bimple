CC := gcc
CFLAGS = -Wall -Wextra -lbfd -g

main: main.o
	$(CC) $^ -o $@ $(CFLAGS) 

.PHONY: clean
clean:
	rm main main.o

.DEFAULT_GOAL = main




