#include "includes.h"

////////////////////////////////////////////////////////////////////////
// DEFINICOES

const char		*__progname = NULL;

////////////////////////////////////////////////////////////////////////
// FUNCOES

static void
associa_interface(struct sock_ctx *ctx)
{
	int			 sys_sock;
	struct ifreq		 ifr;
	char			 buf[INET6_ADDRSTRLEN];

	sys_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sys_sock == -1)
		err(1, "%s", __FUNCTION__);

	memset(&ifr, 0, sizeof(struct ifreq));
	strcpy(ifr.ifr_name, ctx->ifname);
	if (ioctl(sys_sock, SIOCGIFINDEX, &ifr) == -1)
		err(1, "%s", __FUNCTION__);

	ctx->ifindex = ifr.ifr_ifindex;

	if (inet_ntop(AF_INET6, &ctx->ifrom.sin6_addr,
	    buf, INET6_ADDRSTRLEN) == NULL)
		err(1, "%s", __FUNCTION__);

	debug_msg("DEBUG: [interface=%s][IP=%s]",
	    ctx->ifname, buf);

	return;
}

void
inicializa_socket(struct sock_ctx *ctx)
{
	memset(ctx, 0, sizeof(struct sock_ctx));

	ctx->sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (ctx->sd == -1)
		err(1, "%s", __FUNCTION__);
}

static int
mac_str2bin(const char *mac, u_int8_t mac_bin[ETH_ALEN])
{
	if (sscanf(mac, "%02x:%02x:%02x:%02x:%02x:%02x",
	    (u_int *) &mac_bin[0], (u_int *) &mac_bin[1],
	    (u_int *) &mac_bin[2], (u_int *) &mac_bin[3],
	    (u_int *) &mac_bin[4], (u_int *) &mac_bin[5])
	    == ETH_ALEN)
		return(0);

	return(-1);
}

static void
constroi_header(struct sock_ctx *ctx)
{
	struct ether_header		*eth;
	struct ip6_hdr			*ip6;
	struct icmp6_hdr		*icmp6;

	/************************************
	 * XXX inicio da montagem da camada *
	 ************************************/
	eth = (struct ether_header *) ctx->pbuff;

	/* XXX ETH_ALEN foi retirado do arquivo: net/ethernet.h */
	memcpy(eth->ether_dhost, ctx->mto, ETH_ALEN);
	memcpy(eth->ether_shost, ctx->mfrom, ETH_ALEN);

	/* XXX IDs dos tipos de ethernet tambem podem ser achados no
	 * arquivo referenciado acima.
	 */
	eth->ether_type = htons(ETHERTYPE_IPV6);

	ctx->ppos = ctx->pbuff + sizeof(struct ether_header);


	/************************************
	 * XXX inicio da montagem da camada *
	 ************************************/
	ip6 = (struct ip6_hdr *) ctx->ppos;
	/* nem vamo usa */
	ip6->ip6_flow = htonl(0);

	/* XXX guarda ponteiro para o tamanho do
	 * pacote de dados para atualizar mais tarde
	 */
	ctx->plen = &ip6->ip6_plen;
	ip6->ip6_plen = htons(64);
	/* next header -> 0x3a == ICMPv6 */
	ip6->ip6_nxt = 0x3a;
	/* XXX hop-limit a.k.a. ttl */
	ip6->ip6_hlim = 64;

	memcpy(&ip6->ip6_src, &ctx->ifrom.sin6_addr, sizeof(struct in6_addr));
	memcpy(&ip6->ip6_dst, &ctx->ito.sin6_addr, sizeof(struct in6_addr));

	ctx->ppos += sizeof(struct ip6_hdr);


	/************************************
	 * XXX inicio da montagem da camada *
	 ************************************/
	icmp6 = (struct icmp6_hdr *) ctx->ppos;

	if (ctx->proxy)
		icmp6->icmp6_type = ICMP6_ECHO_REPLY;
	else
		icmp6->icmp6_type = ICMP6_ECHO_REQUEST;

	/* Sempre zero */
	icmp6->icmp6_code = 0;

	/* XXX ponteiro para a posicao do pacote onde fica o checksum sera
	 * guardada para ser usada mais tarde
	 */
	ctx->icmp_cksum = &icmp6->icmp6_cksum;

	icmp6->icmp6_seq = htons(ctx->seq_atual++);
	/* XXX numero gerado por dados, garantido de ser aleartório */
	icmp6->icmp6_id = htons(42);

	ctx->ppos += sizeof(struct icmp6_hdr);


	/**************************************
	 * XXX inicio da montagem do checksum *
	 **************************************/
	/* preenche o pacote que eh descrito pela RFC para o checksum */
	memcpy(&ctx->ckf.ip6_src, &ip6->ip6_src, sizeof(struct in6_addr));
	memcpy(&ctx->ckf.ip6_dst, &ip6->ip6_dst, sizeof(struct in6_addr));

	ctx->ckf.nxthdr = 0x3a;

	/* XXX copia header do ICMP para checksum */
	memcpy(&ctx->ckf.icmp6, (ctx->ppos - sizeof(struct icmp6_hdr)),
	    sizeof(struct icmp6_hdr));
}

static void
constroi_header_link(struct sock_ctx *ctx)
{
	/* Familia sempre AF_PACKET */
	ctx->saddr.sll_family = AF_PACKET;

	/* tipo de protocolo */
	ctx->saddr.sll_protocol = htons(ETH_P_ALL);

	/* indice da interface */
	ctx->saddr.sll_ifindex = ctx->ifindex;

	/* tamanho do endereco de hardware */
	//ctx->saddr.sll_halen = ETH_ALEN;

	/* ??? */
	//ctx->saddr.sll_pkttype = PACKET_OTHERHOST;

	/* endereco de hardware */
	//memcpy(&ctx->saddr.sll_addr, ctx->mfrom, ETH_ALEN);

	ctx->saddr_len = sizeof(struct sockaddr_ll);
}

static void
constroi_header_tcp(struct sock_ctx *ctx)
{
	struct tcphdr	*tcp;

	tcp = (struct tcphdr *) ctx->ppos;

	/* source port */
	tcp->source = htons(ctx->tcp_port);
	/* destination port */
	tcp->dest = htons(ctx->tcp_port);

	/* sequential number */
	tcp->seq = htonl(ctx->seq_atual);
	/* ack number */
	tcp->ack_seq = htonl(ctx->seq_atual);

	/* data offset */
	tcp->doff = 0;

	/* TCP flags, TH_FIN, TH_SYN, TH_RST, TH_PUSH, TH_ACK, TH_URG */
	//tcp->th_flags = TH_SYN | TH_ACK; // BSD-Style
	tcp->fin = 0;
	tcp->syn = 1;
	tcp->rst = 0;
	tcp->psh = 0;
	tcp->ack = 1;
	tcp->urg = 0;

	/* TCP window */
	tcp->window = htons(0);
	/* TCP checksum */
	tcp->check = htons(0);
	/* TCP urgent pointer ??? */
	tcp->urg_ptr = htons(0);

	ctx->ppos += sizeof(struct tcphdr);
	memcpy(&ctx->ckf.tcp, (ctx->ppos - sizeof(struct tcphdr)),
	    sizeof(struct tcphdr));
}

void
constroi_mensagem(struct sock_ctx *ctx, u_int8_t *mensagem, u_int32_t total)
{
	constroi_header(ctx);
	constroi_header_tcp(ctx);

	memcpy(ctx->ppos, mensagem, total);
	memcpy(ctx->ckf.msg, mensagem, total);

	*ctx->plen = htons(sizeof(struct icmp6_hdr) +
	    sizeof(struct tcphdr) + total);
	ctx->ckf.pkt_len = htonl(ntohs(*ctx->plen));
	ctx->ppos += total;
	*ctx->icmp_cksum =
	    (in_cksum((u_int16_t *) &ctx->ckf, sizeof(ctx->ckf)));
}

void
manda_mensagem(struct sock_ctx *ctx)
{
	constroi_header_link(ctx);

	debug_msg("[PACKET_LEN=%lu]", GET_PACKET_LEN(ctx));
	if (sendto(ctx->sd, ctx->pbuff, GET_PACKET_LEN(ctx), 0,
	    (struct sockaddr *) &ctx->saddr, ctx->saddr_len) == -1)
		err(1, "%s", __FUNCTION__);
}

////////////////////////////////////////////////////////////////////////
// MAIN

static void
usage(void)
{
	fprintf(stderr, "%1$s <-c> -i interface\n"
	    "-s XX:XX:XX:XX:XX:XX -d XX:XX:XX:XX:XX:XX\n"
	    "-o IP6_ADDRESS -w IP6_ADDRESS -p PORTA\n"
	    "========\n"
	    "\t-i - Interface para onde deve se enviar o pacote. (OBRIGATORIO)\n"
   	    "\t-w - Endereco de origem. (OBRIGATORIO)\n"
	    "\t-o - Endereco de destino. (OBRIGATORIO)\n"
	    "\t-s - MAC da interface de origem. (OBRIGATORIO)\n"
	    "\t-d - MAC da interface de destino. (OBRIGATORIO)\n"
	    "\t-c - Programa ira rodar como proxy (default cliente).\n"
	    "\t-p - Porta do TCP (default 8050).\n",
	    __progname);
	exit(EXIT_FAILURE);
}

int
main(int argc, char **argv)
{
	struct sock_ctx		 ctx;
	int			 opt, if_set, ip_set, ip2_set;
	int			 mac_set, mac2_set;
	char			 mensagem[512];
	int			 len;
	fd_set			 read;
	int			 nfds, bread;
	struct timeval		 timer;
	struct sockaddr_in6	 recfrom;
	socklen_t		 ifrom_len;

	__progname = argv[0];
	memset(&ctx, 0, sizeof(ctx));

	if (argc == 1)
		usage();

	inicializa_socket(&ctx);
	if_set = ip_set = ip2_set = 0;
	mac_set = mac2_set = 0;

	while ((opt = getopt(argc, argv, "w:o:i:cs:d:")) != -1) {
		switch (opt) {
		case 'c':
			ctx.proxy = 1;
			break;

		case 's':
			if (mac_str2bin(optarg, ctx.mfrom) == -1) {
				fprintf(stderr, "Endereco de mac %s invalido.\n", optarg);
				exit(EXIT_FAILURE);
			}
			mac2_set = 1;
			break;

		case 'd':
			if (mac_str2bin(optarg, ctx.mto) == -1) {
				fprintf(stderr, "Endereco de mac %s invalido.\n", optarg);
				exit(EXIT_FAILURE);
			}
			mac_set = 1;
			break;

		case 'i':
			memcpy(ctx.ifname, optarg, strlen(optarg));
			if_set = 1;
			break;

		case 'o':
			ip_set = 1;
			inet_pton(AF_INET6, optarg, &ctx.ito.sin6_addr);
			break;

		case 'w':
			ip2_set = 1;
			inet_pton(AF_INET6, optarg, &ctx.ifrom.sin6_addr);
			break;

		default:
			usage();
			/* NOTREACHED */
		}
	}

	if (if_set == 0 || ip_set == 0 || ip2_set == 0
	    || mac_set == 0 || mac2_set == 0)
		usage();

	associa_interface(&ctx);

	if (ctx.proxy) {
		run_proxy(&ctx);
		exit(EXIT_SUCCESS);
	}

	len = sprintf(mensagem, "TESTE PERGUNTA?");
	constroi_mensagem(&ctx, (u_int8_t *) mensagem, len + 1);
	manda_mensagem(&ctx);

	/* XXX espera mensagem de volta */
retry_get:
	memset(&timer, 0, sizeof(struct timeval));
	timer.tv_sec = TEMPO_TIMEOUT;
	timer.tv_usec = 0;

	FD_ZERO(&read);
	FD_SET(ctx.sd, &read);
	nfds = select((ctx.sd + 1), &read, NULL, NULL, &timer);
	if (nfds < 0)
		err(1, "%s", __FUNCTION__);
	else if (nfds == 0) {
		fprintf(stderr, "ERRO: nao consegui receber nada em %d segundos.\n",
		    TEMPO_TIMEOUT);
		exit(EXIT_FAILURE);
	}

	ifrom_len = sizeof(struct sockaddr_in6);
	memset(&recfrom, 0, sizeof(struct sockaddr_in6));

	bread = recvfrom(ctx.sd, ctx.sbuff, BUFSIZ, 0,
	    (struct sockaddr *) &recfrom, &ifrom_len);
	debug_msg("[leu=%d]", bread);
	if (bread == -1)
		err(1, "%s", __FUNCTION__);
	else if (bread == 0) {
		fprintf(stderr, "ERRO: nao consegui ler nada do socket.\n");
		exit(EXIT_SUCCESS);
	}

	/* XXX pega posicao da mensagem */
	ctx.spos = le_mensagem(&ctx, ctx.sbuff, bread);
	if (ctx.spos == NULL) {
		debug_msg("[DESCARTANDO PACOTE DESCONHECIDO]");
		goto retry_get;
	}
	debug_msg("[mensagem=%s]", ctx.spos);

	exit(EXIT_SUCCESS);
}
