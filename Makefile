SOURCES_flux = flux_test.c
CFLAG = -w -Wall -O3
CC = gcc

all:  flux_test

%.o: %.c
	$(CC) -c $^ -o $@ 

flux_test: $(SOURCES_flux)
	$(CC) $(CFLAG) $(SOURCES_flux) -o $@

