BIN	= icmp-tunnel
OBJS	= in_cksum.o main.o proxy.o

CFLAGS	+= -Wall
CC	= gcc ${CFLAGS}

.c.o:
	@echo "CC	$@";
	@${CC} -c $<;

${BIN}: ${OBJS}
	@echo "LD	$@";
	@${CC} ${OBJS} -o $@;

all: ${BIN}

clean:
	rm -f ${OBJS} ${BIN}
