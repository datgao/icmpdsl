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
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

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

static int raw_socket()
{
	int fd;

	fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (fd < 0)
		perror("socket(raw)");
	return fd;
}

static int nf_socket()
{
	int fd;

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
	if (fd < 0)
		perror("socket()");
	return fd;
}

static bool nf_cfg_msg(int fd, uint32_t seq, uint16_t msgtype, uint16_t flags, uint8_t family, uint16_t res, const void *data, unsigned len, uint16_t type)
{
	char buf[2048];
	bool rv = false;
	ssize_t xfer;
	int errnum;
	struct nlmsghdr *nlmh = (struct nlmsghdr *)buf;
	struct nfgenmsg *nfgm = (struct nfgenmsg *)(buf + sizeof *nlmh);
	struct nfattr *nfa;
	struct sockaddr_nl sa;
	socklen_t addrlen;

	nlmh->nlmsg_len = NLMSG_LENGTH(sizeof *nfgm);
	nlmh->nlmsg_type = msgtype;
	nlmh->nlmsg_pid = 0;
	nlmh->nlmsg_flags = NLM_F_REQUEST | flags;
	nlmh->nlmsg_seq = seq;
	nfgm->nfgen_family = family;
	nfgm->version = NFNETLINK_V0;
	nfgm->res_id = htons(res);
	if (data != NULL) {
		nfa = (struct nfattr *)(buf + NLMSG_ALIGN(nlmh->nlmsg_len));
		nfa->nfa_type = type;
		nfa->nfa_len = NFA_LENGTH(len);
		memcpy(NFA_DATA(nfa), data, len);
//		nlmh->nlmsg_len = NLMSG_ALIGN(nlmh->nlmsg_len + NFA_ALIGN(len));
		nlmh->nlmsg_len = nlmh->nlmsg_len + nfa->nfa_len;
	}
	memset(&sa, 0, sizeof sa);
	sa.nl_family = AF_NETLINK;
	xfer = sendto(fd, nlmh, nlmh->nlmsg_len, 0, (struct sockaddr *)&sa, sizeof sa);
	if (xfer < 0) {
		perror("sendto()");
		goto fail;
	} else if (xfer != nlmh->nlmsg_len) {
		fprintf(stderr, "sendto(): wrote %i of %u bytes\n", (int)xfer, (unsigned)nlmh->nlmsg_len);
		goto fail;
	}
	if ((flags & NLM_F_ACK) == 0)
		goto success;
	while (true) {
		addrlen = sizeof sa;
		do {
			xfer = recvfrom(fd, buf, sizeof buf, 0, (struct sockaddr *)&sa, &addrlen);
		} while (xfer < 0 && errno == EINTR);
		if (xfer < 0) {
			perror("recvfrom()");
			goto fail;
		}
		if (addrlen != sizeof sa || sa.nl_family != AF_NETLINK) {
			fprintf(stderr, "Unexpected response\n");
			goto fail;
		}
		nlmh = (struct nlmsghdr *)buf;
		if (sa.nl_pid != 0 || seq != nlmh->nlmsg_seq)
			continue;
		while (xfer >= NLMSG_SPACE(0) && NLMSG_OK(nlmh, xfer)) {
			if (nlmh->nlmsg_type == NLMSG_ERROR || (nlmh->nlmsg_type == NLMSG_DONE && (nlmh->nlmsg_flags & NLM_F_MULTI) != 0)) {
				if (nlmh->nlmsg_len < NLMSG_ALIGN(sizeof(struct nlmsgerr))) {
					fprintf(stderr, "Too small\n");
					goto fail;
				}
				errnum = -(*((int *)NLMSG_DATA(nlmh)));
				if (errnum == 0)
					goto success;
				fprintf(stderr, "%s\n", strerror(errnum));
				goto fail;
			}
			nlmh = NLMSG_NEXT(nlmh, xfer);
		}
	}
success:
	rv = true;
fail:
	return rv;
}

static bool nfq_verdict(int fd, uint32_t seq, uint16_t gid, uint32_t id, uint32_t verdict)
{
	struct nfqnl_msg_verdict_hdr nmvh;

	nmvh.id = htonl(id);
	nmvh.verdict = htonl(verdict);
	return nf_cfg_msg(fd, seq, (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_VERDICT, 0, AF_UNSPEC, gid, &nmvh, sizeof nmvh, NFQA_VERDICT_HDR);
}

static bool nfq_cfg_msg(int fd, uint32_t seq, uint8_t family, uint16_t gid, const void *data, unsigned len, uint16_t type)
{
	return nf_cfg_msg(fd, seq, (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG, NLM_F_ACK, family, gid, data, len, type);
}

static bool nfq_cfg_cmd(int fd, uint32_t seq, uint16_t gid, uint8_t cmd, uint16_t pf)
{
	struct nfqnl_msg_config_cmd nmcc;

	nmcc.command = cmd;
	nmcc.pf = htons(pf);
	return nfq_cfg_msg(fd, seq, AF_UNSPEC, gid, &nmcc, sizeof nmcc, NFQA_CFG_CMD);
}

static bool nfq_cfg_mode(int fd, uint32_t seq, uint16_t gid, uint8_t mode, uint32_t range)
{
	struct nfqnl_msg_config_params nmcp;

	nmcp.copy_range = htonl(range);
	nmcp.copy_mode = mode;
	return nfq_cfg_msg(fd, seq, AF_UNSPEC, gid, &nmcp, sizeof nmcp, NFQA_CFG_PARAMS);
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

static bool nfq_process(int fd, const char *pkt, unsigned psz, uint16_t mtu)
{
	const struct ipv4_hdr *ip;
	const struct tcp_hdr *tcp;
	struct ipv4_hdr *ipv4;
	struct icmpv4_hdr *icmp;
	char buf[sizeof *ipv4 + sizeof *icmp + 60 + 8];
	unsigned iphdrlen, iplen, pktlen;
	ssize_t len;
	struct sockaddr_in sa;

	if (psz < sizeof *ip + sizeof *tcp)
		goto out;
	ip = (const struct ipv4_hdr *)pkt;
	if ((ip->ver_hlen & 0xf0) != 0x40)
		goto out;
	iphdrlen = (ip->ver_hlen & 0x0f) << 2;
	if (iphdrlen < 20)
		goto out;
	iplen = ntohs(ip->len);
	if (iplen < iphdrlen || iplen < iphdrlen + sizeof *tcp
	|| ip->proto != IPPROTO_TCP// || ip->dst != ctx->net
	|| (ip->frag_off & htons(0xbfff)) != 0)
		goto out;
	tcp = (const struct tcp_hdr *)(ip->options - sizeof *ip + iphdrlen);
	if ((tcp->hlen_rsvd & 0xf0) < 0x50
	|| (tcp->flags & (TH_SYN | TH_ACK)) != (TH_SYN | TH_ACK))
		goto out;
	ipv4 = (struct ipv4_hdr *)buf;
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
	icmp->hdr.pmtud.mtu = htons(mtu);
	memcpy(icmp->payload, ip, pktlen - sizeof *ipv4 - sizeof *icmp);
	*(volatile uint32_t *)(icmp->payload + iphdrlen + 4) = htonl(ntohl(*(volatile uint32_t *)(icmp->payload + iphdrlen + 4)) + 1);
	icmp->cksum = inet_checksum((const uint8_t *)icmp, pktlen - sizeof *ipv4, 0);
	memset(&sa, 0, sizeof sa);
	sa.sin_addr.s_addr = ipv4->dst;
	len = sendto(fd, (const void *)buf, pktlen, 0, (const struct sockaddr *)&sa, sizeof sa);
	if (len < 0) {
		perror("sendto()");
		goto fail;
	} else if (len != (ssize_t)pktlen) {
		fprintf(stderr, "sendto() wrote %i of %u bytes\n", (int)len, pktlen);
		goto fail;
	}
	printf("%u\n", (unsigned)time(NULL));
out:
	return true;
fail:
	return false;
}

static bool nfq_operate(uint16_t mtu, uint16_t qid)
{
	bool rv = false;
	int fd = -1, sfd = -1;
	uint32_t seq = 0, id = 0;
	ssize_t xfer;
	unsigned len, sz, psz;
	char buf[2048];
	const char *ptr, *pkt;
	const struct nlmsghdr *nlmh;
	const struct nfgenmsg *nfgm;
	const struct nfattr *nfa;
	const struct nfqnl_msg_packet_hdr *nmph;

	sfd = raw_socket();
	if (sfd < 0)
		goto fail;
	fd = nf_socket();
	if (fd < 0 || !nfq_cfg_cmd(fd, seq++, 0, NFQNL_CFG_CMD_PF_UNBIND, AF_INET)
	|| !nfq_cfg_cmd(fd, seq++, 0, NFQNL_CFG_CMD_PF_BIND, AF_INET)
	|| !nfq_cfg_cmd(fd, seq++, qid, NFQNL_CFG_CMD_BIND, AF_UNSPEC)
	|| !nfq_cfg_mode(fd, seq++, qid, NFQNL_COPY_PACKET, sizeof buf))
		goto fail;

	while (true) {
		do {
			xfer = recv(fd, buf, sizeof buf, 0);
		} while (xfer < 0 && errno == EINTR);
		if (xfer < 0) {
			perror("recv()");
			goto fail;
		}
		ptr = (const char *)buf;
		while (xfer >= NLMSG_SPACE(0)) {
			nlmh = (const struct nlmsghdr *)ptr;
			if (nlmh->nlmsg_len < sizeof *nlmh || xfer < nlmh->nlmsg_len) {
				fprintf(stderr, "Truncated message\n");
				goto fail;
			}
			if (NFNL_SUBSYS_ID(nlmh->nlmsg_type) == NFNL_SUBSYS_QUEUE
			&& NFNL_MSG_TYPE(nlmh->nlmsg_type) == NFQNL_MSG_PACKET) {
				pkt = NULL;
				if (nlmh->nlmsg_len < NLMSG_LENGTH(NLMSG_ALIGN(sizeof *nfgm))) {
					fprintf(stderr, "Malformed message\n");
					goto fail;
				}
				nfgm = NLMSG_DATA(nlmh);
				if (nlmh->nlmsg_len > NLMSG_LENGTH(NLMSG_ALIGN(sizeof *nfgm))) {
					nfa = NFM_NFA(nfgm);
					sz = nlmh->nlmsg_len - NLMSG_ALIGN(sizeof *nfgm);
					while (NFA_OK(nfa, sz)) {
						switch (NFA_TYPE(nfa)) {
						case NFQA_PACKET_HDR:
							nmph = NFA_DATA(nfa);
							id = ntohl(nmph->packet_id);
							break;
						case NFQA_PAYLOAD:
							pkt = NFA_DATA(nfa);
							psz = NFA_PAYLOAD(nfa);
							break;
						default:
							break;
						}
						nfa = NFA_NEXT(nfa, sz);
					}
				}
				if ((pkt != NULL && !nfq_process(sfd, pkt, psz, mtu))
				|| !nfq_verdict(fd, seq, qid, id, NF_ACCEPT))
					goto fail;
			}
			len = NLMSG_ALIGN(nlmh->nlmsg_len);
			if (len > xfer)
				len = xfer;
			xfer -= len;
			ptr += len;
		}
	}

	rv = true;
fail:
	return rv;
}

int main(int argc, char *argv[])
{
	int rv = EXIT_FAILURE;

	if (!nfq_operate(argc > 1 ? strtoul(argv[1], NULL, 10) : 1400, argc > 2 ? strtoul(argv[2], NULL, 10) : 0))
		goto fail;
	rv = EXIT_SUCCESS;
fail:
	return rv;
}
