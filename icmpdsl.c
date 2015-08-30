/*
	This file is part of icmpdsl.
	Copyright (C) 2015, Robert L. Thompson

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <stdio.h>

#ifndef PCAP_NETMASK_UNKNOWN
#define PCAP_NETMASK_UNKNOWN	0xffffffff
#endif

struct eth_hdr {
	uint8_t dst[6];
	uint8_t src[6];
	uint16_t type;
	uint8_t data[0];
};

struct ipv4_hdr {
	uint8_t ver_hlen;
	uint8_t tos;
	uint16_t len;
	uint16_t id;
	uint16_t frag_off;
	uint8_t ttl;
	uint8_t proto;
	uint16_t cksum;
	uint32_t src;
	uint32_t dst;
	uint8_t options[0];
};

struct icmpv4_hdr {
	uint8_t type;
	uint8_t code;
	uint16_t cksum;
	union {
		struct {
			uint16_t id;
			uint16_t seq;
		} echo;
		uint32_t gw;
		struct {
			uint16_t rsvd;
			uint16_t mtu;
		} pmtud;
	} hdr;
	uint8_t payload[0];
};

#ifndef TH_SYN
#define TH_SYN	0x02
#endif
#ifndef TH_ACK
#define TH_ACK	0x10
#endif

struct tcp_hdr {
	uint16_t sport;
	uint16_t dport;
	uint32_t seq;
	uint32_t ack;
	uint8_t hlen_rsvd;
	uint8_t flags;
	uint16_t win;
	uint16_t cksum;
	uint16_t urgp;
	uint8_t data[0];
};

static pcap_t *open_pcap(const char *iface, bpf_u_int32 *net, bpf_u_int32 *mask)
{
	pcap_t *pcap = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	char ipv4str[16], filter[128];
	struct bpf_program bpf;

	if (pcap_lookupnet(iface, net, mask, errbuf) != 0) {
		fprintf(stderr, "pcap_lookupnet(): %s\n", errbuf);
		goto fail;
	}
	if (inet_ntop(AF_INET, (const void *)net, ipv4str, sizeof ipv4str) == NULL) {
		perror("inet_ntop()");
		goto fail;
	}
//	snprintf(filter, sizeof filter, "ip dst %s and (tcp[tcpflags] & (tcp-syn | tcp-ack)) = (tcp-syn | tcp-ack)", ipv4str);
	snprintf(filter, sizeof filter, "(tcp[tcpflags] & (tcp-syn | tcp-ack)) = (tcp-syn | tcp-ack)");
	pcap = pcap_create(iface, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_create(): %s\n", errbuf);
		goto fail;
	}
	(void)pcap_setdirection(pcap, PCAP_D_IN);
	if (pcap_set_buffer_size(pcap, 131072) != 0) {
		pcap_perror(pcap, "pcap_set_buffer_size()");
		goto fail;
	}
	if (pcap_activate(pcap) != 0) {
		pcap_perror(pcap, "pcap_activate()");
		goto fail;
	}
	if (pcap_compile(pcap, &bpf, filter, 1, PCAP_NETMASK_UNKNOWN) != 0) {
		pcap_perror(pcap, "pcap_compile()");
		goto fail;
	}
	if (pcap_setfilter(pcap, &bpf) != 0) {
		pcap_perror(pcap, "pcap_setfilter()");
		goto fail;
	}
	pcap_freecode(&bpf);
	return pcap;
fail:
	if (pcap != NULL)
		pcap_close(pcap);
	return NULL;
}

static int open_raw()
{
	int fd;

	fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (fd < 0)
		perror("socket(raw)");
	return fd;
}

static uint16_t inet_checksum_fold(uint32_t sum)
{
	sum = (sum >> 16) + (sum & 0xffff);
	return ~((sum >> 16) + sum);
}

static uint16_t inet_checksum(const uint8_t *payload, unsigned len, uint32_t sum)
{
	const uint16_t *p16 = (const uint16_t *)payload;
	unsigned i;

	for (i = 0; i < len / 2; i++, p16++)
		sum += *p16;
	if (len & 0x1)
		sum += ntohs(*(uint8_t *)p16 << 8);
	return inet_checksum_fold(sum);
}

struct packet_ctx {
	pcap_t *pcap;
	int fd;
	bpf_u_int32 net;
	bpf_u_int32 mask;
	uint16_t mtu;
};

static void packet_handler(u_char *user, const struct pcap_pkthdr *hdr, const u_char *buf)
{
	struct packet_ctx *ctx = (struct packet_ctx *)user;
	const struct eth_hdr *eth;
	const struct ipv4_hdr *ip;
	const struct tcp_hdr *tcp;
	struct ipv4_hdr *ipv4;
	struct icmpv4_hdr *icmp;
	char pkt[sizeof *ipv4 + sizeof *icmp + 1500];
	unsigned iphdrlen, iplen, pktlen;
	ssize_t len;
	struct sockaddr_in sa;

	if (hdr->caplen < sizeof *eth + sizeof *ip)
		return;
	eth = (const struct eth_hdr *)buf;
	if (eth->type != htons(ETHERTYPE_IP))
		return;
	ip = (const struct ipv4_hdr *)eth->data;
	if ((ip->ver_hlen & 0xf0) != 0x40)
		return;
	iphdrlen = (ip->ver_hlen & 0x0f) << 2;
	if (iphdrlen < 20)
		return;
	iplen = ntohs(ip->len);
	if (iplen < iphdrlen || iplen < iphdrlen + sizeof *tcp
	|| ip->proto != IPPROTO_TCP// || ip->dst != ctx->net
	|| (ip->frag_off & htons(0xbfff)) != 0)
		return;
	tcp = (const struct tcp_hdr *)(ip->options - sizeof *ip + iphdrlen);
	if ((tcp->hlen_rsvd & 0xf0) < 0x50
	|| (tcp->flags & (TH_SYN | TH_ACK)) != (TH_SYN | TH_ACK))
		return;
	ipv4 = (struct ipv4_hdr *)pkt;
	ipv4->ver_hlen = 0x45;
	ipv4->tos = 0;
	pktlen = sizeof *ipv4 + sizeof *icmp + iphdrlen + 8;
	ipv4->len = htons(pktlen);
	ipv4->id = rand();
	ipv4->frag_off = 0;
	ipv4->ttl = 255;
	ipv4->proto = IPPROTO_ICMP;
	ipv4->cksum = 0;
	ipv4->src = ip->dst;
	ipv4->dst = ip->src;
	ipv4->cksum = inet_checksum((const uint8_t *)ipv4, sizeof *ipv4, 0);
	icmp = (struct icmpv4_hdr *)ipv4->options;
	icmp->type = ICMP_DEST_UNREACH;
	icmp->code = ICMP_FRAG_NEEDED;
	icmp->cksum = 0;
	icmp->hdr.pmtud.rsvd = 0;
	icmp->hdr.pmtud.mtu = htons(ctx->mtu);
	memcpy(icmp->payload, ip, pktlen - sizeof *ipv4 - sizeof *icmp);
	*(volatile uint32_t *)(icmp->payload + iphdrlen + 4) = htonl(ntohl(*(volatile uint32_t *)(icmp->payload + iphdrlen + 4)) + 1);
	icmp->cksum = inet_checksum((const uint8_t *)icmp, pktlen - sizeof *ipv4, 0);
	memset(&sa, 0, sizeof sa);
	sa.sin_addr.s_addr = ipv4->dst;
	len = sendto(ctx->fd, (const void *)pkt, pktlen, 0, (const struct sockaddr *)&sa, sizeof sa);
	if (len < 0)
		perror("sendto()");
	else if (len != (ssize_t)pktlen)
		fprintf(stderr, "sendto() wrote %i of %u bytes\n", (int)len, pktlen);
}

static bool operate(const char *iface, unsigned long mtu)
{
	bool rv = false;
	struct packet_ctx ctx;

	ctx.pcap = NULL;
	ctx.fd = -1;
	ctx.mtu = mtu;
	ctx.pcap = open_pcap(iface, &ctx.net, &ctx.mask);
	if (ctx.pcap == NULL)
		goto fail;
	ctx.fd = open_raw();
	if (ctx.fd < 0)
		goto fail;

	if (pcap_loop(ctx.pcap, -1, &packet_handler, (u_char *)&ctx) != 0)
		goto fail;

	rv = true;
fail:
	if (ctx.pcap != NULL)
		pcap_close(ctx.pcap);
	if (ctx.fd >= 0)
		close(ctx.fd);
	return rv;
}

int main(int argc, char *argv[])
{
	int rv = EXIT_FAILURE;

	if (argc != 3) {
		fprintf(stderr, "%s iface mtu\n", argv[0]);
		goto fail;
	}
	if (!operate(argv[1], strtoul(argv[2], NULL, 10)))
		goto fail;

	rv = EXIT_SUCCESS;
fail:
	return rv;
}
