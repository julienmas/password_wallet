CC=gcc
CFLAGS= -lcrypto
DEPS = 
OBJ = password_wallet.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

password_wallet: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm -f *.o *~ $()