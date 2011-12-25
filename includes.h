#include <err.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netpacket/packet.h>

#include <linux/if_ether.h>


#define TEMPO_TIMEOUT 15

struct sock_ctx {
	/* define se vamos atuar como proxy ou cliente */
	int			 proxy;
	int			 seq_atual;

	/* descritor do socket */
	int			 sd;

	/* buffer do socket de entrada */
	u_int8_t		 sbuff[BUFSIZ];
	u_int8_t		*spos;

	/* buffer de pacotes */
	u_int8_t		 pbuff[BUFSIZ];
	/* XXX ponteiro do buffer: manter sempre atualizado */
	u_int8_t		*ppos;
	/* XXX macro para pegar tamanho do pacote a partir do ponteiro do buffer */
#define GET_PACKET_LEN(sock_ctx) (sock_ctx->ppos - sock_ctx->pbuff)
	u_int16_t		*plen;
	u_int16_t		*icmp_cksum;

	/* Struct para se fazer checksum */
	struct ckfields {
		struct in6_addr		 ip6_src;
		struct in6_addr		 ip6_dst;
		u_int32_t		 pkt_len;
		u_int8_t		 dummy[3];
		u_int8_t		 nxthdr;
		struct icmp6_hdr	 icmp6;
		struct tcphdr		 tcp;
		u_char			 msg[512];
	} ckf;

	/* enderecos macs */
	u_int8_t		 mfrom[6], mto[6];
	/* enderecos IP */
	struct sockaddr_in6	 ifrom, ito;
	/* Porta */
	u_int16_t		 tcp_port;

	/* enderecador de destino (escolhe interface, enlace etc...) */
	struct sockaddr_ll	 saddr;

	/* tamanho do endereco */
	socklen_t		 saddr_len;

	/* interface usada para mandar */
	int	 ifindex;
	char	 ifname[IFNAMSIZ];
};

/* Proxy */
void		 run_proxy(struct sock_ctx *);
u_int8_t	*le_mensagem(struct sock_ctx *, u_int8_t *, int);

/* Generico */
void     constroi_mensagem(struct sock_ctx *, u_int8_t *, u_int32_t);
void	 manda_mensagem(struct sock_ctx *);

#define DEBUG 1
#define debug_msg(msg, args...)					\
	do {							\
		if (DEBUG)					\
			fprintf(stderr, "(%s:%d) " msg "\n",	\
			    __FUNCTION__, __LINE__,		\
			    ## args);				\
	} while (0);

unsigned short	 in_cksum(unsigned short *addr, int len);
