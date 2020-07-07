CC=gcc
CFLAGS= -lcrypto
DEPS = 
OBJ = password_generator.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

password_generator: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm -f *.o *~ $()