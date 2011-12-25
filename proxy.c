#include "includes.h"

static void
responde_mensagem(struct sock_ctx *ctx)
{
	struct ether_header		*eth;
	struct ip6_hdr			*ip6;
	struct icmp6_hdr		*icmp6;
	struct tcphdr			*tcp;
	char				 mensagem[512];
	int				 mlen;

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

	icmp6->icmp6_seq = htons(++ctx->seq_atual);
	/* XXX numero gerado por dados, garantido de ser aleartório */
	icmp6->icmp6_id = htons(42);

	ctx->ppos += sizeof(struct icmp6_hdr);


	/************************************
	 * XXX inicio da montagem da camada *
	 ************************************/
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

	mlen = sprintf(mensagem, "TESTE RESPOSTA");
	constroi_mensagem(ctx, (u_int8_t *) mensagem, mlen + 1);
	manda_mensagem(ctx);
}

u_int8_t *
le_mensagem(struct sock_ctx *ctx, u_int8_t *buf, int len)
{
	struct ether_header		*eth;
	struct ip6_hdr			*ip6;
	struct icmp6_hdr		*icmp6;
	struct tcphdr			*tcp;
	u_int8_t			*pbuff = buf;
	char				 debug_buf[INET6_ADDRSTRLEN];

	/*******************
	 * Camada ethernet *
	 *******************/
	if (len < sizeof(struct ether_header))
		return(NULL);

	eth = (struct ether_header *) buf;

	debug_msg("[ETHER_TYPE=%s]",
	    (eth->ether_type == htons(ETHERTYPE_IPV6)) ?
	    "IPv6" : "NAO_CONHECO");

	/* Filtra pacotes IPv6 */
	if (eth->ether_type != htons(ETHERTYPE_IPV6))
		return(NULL);

	pbuff += sizeof(struct ether_header);


	/***************
	 * Camada IPv6 *
	 ***************/
	if (len < (sizeof(struct ether_header) +
	    sizeof(struct ip6_hdr)))
		return(NULL);

	ip6 = (struct ip6_hdr *) pbuff;
	debug_msg("[orig=%s]", inet_ntop(AF_INET6, &ip6->ip6_src,
	    debug_buf, INET6_ADDRSTRLEN));
	debug_msg("[dest=%s]", inet_ntop(AF_INET6, &ip6->ip6_dst,
	    debug_buf, INET6_ADDRSTRLEN));
	debug_msg("[NEXT_HEADER_TYPE=%s]",
	    (ip6->ip6_nxt == 0x3a) ?
	    "ICMPv6" : "DESCONHECIDO");

	/* Filtra pacotes ICMP6 */
	if (ip6->ip6_nxt != 0x3a)
		return(NULL);

	pbuff += sizeof(struct ip6_hdr);


	/****************
	 * Camada ICMP6 *
	 ****************/
	if (len < (sizeof(struct ether_header) +
	    sizeof(struct ip6_hdr) +
	    sizeof(struct icmp6_hdr)))
		return(NULL);

	icmp6 = (struct icmp6_hdr *) pbuff;

	debug_msg("[ICMP_TYPE=%s]",
	    (icmp6->icmp6_type == ICMP6_ECHO_REQUEST) ? "ECHO_REQUEST" :
	    (icmp6->icmp6_type == ICMP6_ECHO_REPLY) ? "ECHO_REPLY" : "NAO_SEI");

	if (ctx->proxy) {
		if (icmp6->icmp6_type != ICMP6_ECHO_REQUEST)
			return(NULL);
	} else {
		if (icmp6->icmp6_type != ICMP6_ECHO_REPLY)
			return(NULL);
	}

	pbuff += sizeof(struct icmp6_hdr);

	/**************
	 * Camada TCP *
	 **************/
	if (len < (sizeof(struct ether_header) +
	    sizeof(struct ip6_hdr) +
	    sizeof(struct icmp6_hdr) +
	    sizeof(struct tcphdr)))
		return(NULL);

	tcp = (struct tcphdr *) pbuff;

	pbuff += sizeof(struct tcphdr);

	return(pbuff);
}

void
run_proxy(struct sock_ctx *ctx)
{
	fd_set			 read;
	int			 nfds, bread;
	struct timeval		 timer;
	socklen_t		 ifrom_len;
	struct sockaddr_in6	 source;

retry_get:
	memset(&timer, 0, sizeof(struct timeval));
	timer.tv_sec = TEMPO_TIMEOUT;
	timer.tv_usec = 0;

	FD_ZERO(&read);
	FD_SET(ctx->sd, &read);
	nfds = select((ctx->sd + 1), &read, NULL, NULL, &timer);
	if (nfds < 0)
		err(1, "%s", __FUNCTION__);
	else if (nfds == 0) {
		fprintf(stderr, "ERRO: nao consegui receber nada em %d segundos.\n",
		    TEMPO_TIMEOUT);
		exit(EXIT_FAILURE);
	}

	ifrom_len = sizeof(struct sockaddr_in6);
	memset(&source, 0, sizeof(struct sockaddr_in6));

	bread = recvfrom(ctx->sd, ctx->sbuff, BUFSIZ, 0,
	    (struct sockaddr *) &source, &ifrom_len);
	debug_msg("[leu=%d]", bread);
	if (bread == -1)
		err(1, "%s", __FUNCTION__);
	else if (bread == 0) {
		fprintf(stderr, "ERRO: nao consegui ler nada do socket.\n");
		exit(EXIT_SUCCESS);
	}

	/* XXX pega posicao da mensagem */
	ctx->spos = le_mensagem(ctx, ctx->sbuff, bread);
	if (ctx->spos == NULL) {
		debug_msg("[DESCARTANDO PACOTE DESCONHECIDO]");
		goto retry_get;
	}
	debug_msg("[mensagem=%s]", ctx->spos);

	debug_msg("[RESPONDENDO_MENSAGEM_PERGUNTA]");
	responde_mensagem(ctx);
}
