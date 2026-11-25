CC = gcc
CFLAGS = -Wall

all: respawn doublefork hop watchdog

respawn: respawn.c
	$(CC) $(CFLAGS) respawn.c -o respawn

doublefork: doublefork.c
	$(CC) $(CFLAGS) doublefork.c -o doublefork

hop: hop.c
	$(CC) $(CFLAGS) hop.c -o hop

watchdog: watchdog.c
	$(CC) $(CFLAGS) watchdog.c -o watchdog

clean:
	rm -f respawn doublefork hop watchdog
