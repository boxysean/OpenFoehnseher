CC = gcc -g $(shell pkg-config --cflags --libs gtk+-2.0 glib) -Wall
CFLAGS = $(GTK_INCLUDE)
LDFLAGS = $(GTK_LIB) $(X11_LIB) -lpcap -lpcre -lcurl

# -lX11 -lXext -lm -lgdk -lglib

#gcc -Wall -o sniffex sniffex.c -I/opt/local/include -L/opt/local/lib -lpcap -lpcre -lcurl $(pkg-config --cflags gtk+-2.0) $(pkg-config --libs gtk+-2.0)

OBJS = openfoehnseher.o

openfoehnseher:	$(OBJS)
#	$(CC) (X11_LIB) $(OBJS) -o openfoehnseher $(LDFLAGS)

clean:
	rm -f *.o *~ openfoehnseher
