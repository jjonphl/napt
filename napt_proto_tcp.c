#include "napt.h"
#include <linux/tcp.h>

struct tcp_data {
    __u16 v4port[2], v6port[2];
};

/* ripped off from rr */

static unsigned long tcp_timeouts[]
= { 30 MINS, 	/*	TCP_CONNTRACK_NONE,	*/
    5 DAYS,	/*	TCP_CONNTRACK_ESTABLISHED,	*/
    2 MINS,	/*	TCP_CONNTRACK_SYN_SENT,	*/
    60 SECS,	/*	TCP_CONNTRACK_SYN_RECV,	*/
    2 MINS,	/*	TCP_CONNTRACK_FIN_WAIT,	*/
    2 MINS,	/*	TCP_CONNTRACK_TIME_WAIT,	*/
    10 SECS,	/*	TCP_CONNTRACK_CLOSE,	*/
    60 SECS,	/*	TCP_CONNTRACK_CLOSE_WAIT,	*/
    30 SECS,	/*	TCP_CONNTRACK_LAST_ACK,	*/
    2 MINS,	/*	TCP_CONNTRACK_LISTEN,	*/
};

/* TCP_CONNTRACK_NONE == TNS_GROUND */
enum tcp_conntrack {
    TCP_CONNTRACK_NONE,
    TCP_CONNTRACK_ESTABLISHED,
    TCP_CONNTRACK_SYN_SENT,
    TCP_CONNTRACK_SYN_RECV,
    TCP_CONNTRACK_FIN_WAIT,
    TCP_CONNTRACK_TIME_WAIT,
    TCP_CONNTRACK_CLOSE,
    TCP_CONNTRACK_CLOSE_WAIT,
    TCP_CONNTRACK_LAST_ACK,
    TCP_CONNTRACK_LISTEN,
    TCP_CONNTRACK_MAX
};

#define sNO TCP_CONNTRACK_NONE
#define sES TCP_CONNTRACK_ESTABLISHED
#define sSS TCP_CONNTRACK_SYN_SENT
#define sSR TCP_CONNTRACK_SYN_RECV
#define sFW TCP_CONNTRACK_FIN_WAIT
#define sTW TCP_CONNTRACK_TIME_WAIT
#define sCL TCP_CONNTRACK_CLOSE
#define sCW TCP_CONNTRACK_CLOSE_WAIT
#define sLA TCP_CONNTRACK_LAST_ACK
#define sLI TCP_CONNTRACK_LISTEN
#define sIV TCP_CONNTRACK_MAX

/* this is cool. present state is the column label, input is
   the row label, and next state is their intersection at
   the table **/
static enum tcp_conntrack tcp_conntracks[2][5][TCP_CONNTRACK_MAX] = {
    {
	/*	ORIGINAL (based on sends) */
	/* 	  sNO, sES, sSS, sSR, sFW, sTW, sCL, sCW, sLA, sLI 	*/
	/*syn*/	{sSS, sES, sSS, sSR, sSS, sSS, sSS, sSS, sSS, sLI },
	/*fin*/	{sTW, sFW, sSS, sTW, sFW, sTW, sCL, sTW, sLA, sLI },
	/*ack*/	{sES, sES, sSS, sES, sFW, sTW, sCL, sCW, sLA, sES },
	/*rst*/ {sCL, sCL, sSS, sCL, sCL, sTW, sCL, sCL, sCL, sCL },
	/*none*/{sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV }
    },
    {
	/*	REPLY (based on receive*/
	/* 	  sNO, sES, sSS, sSR, sFW, sTW, sCL, sCW, sLA, sLI 	*/
	/*syn*/	{sSR, sES, sSR, sSR, sSR, sSR, sSR, sSR, sSR, sSR },
	/*fin*/	{sCL, sCW, sSS, sTW, sTW, sTW, sCL, sCW, sLA, sLI },
	/*ack*/	{sCL, sES, sSS, sSR, sFW, sTW, sCL, sCW, sCL, sLI },
	/*rst*/ {sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sLA, sLI },
	/*none*/{sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV }
    }
};

static unsigned int get_conntrack_index(const struct tcphdr *tcph)
{
    if (tcph->rst) return 3;
    else if (tcph->syn) return 0;
    else if (tcph->fin) return 1;
    else if (tcph->ack) return 2;
    else return 4;
}

static int update_state(const void *pkt, struct tn_ctrack *ct, 
			int dir, int idx)
{
    struct tcphdr *tcp = (struct tcphdr *)pkt;

    ct->state[idx] = tcp_conntracks[(dir == ct->dir) ? 0 : 1]
	[get_conntrack_index(tcp)][ct->state[idx]];

    return tcp_timeouts[ct->state[idx]];
}

static int ismine(const void *hdr, int *hint, int *ofs, int dir, int *size)
{
    struct tcphdr *tcp;
    __u8 proto = ((__u8)*hint);


    if (dir == V4TOV6) { /* the easy part */
	if (proto != IPPROTO_TCP) return -EINVAL;
	tcp = (struct tcphdr *)(hdr + *ofs);
	*ofs += sizeof(struct tcphdr);
    } else if (dir == V6TOV4) {
	if (proto != IPPROTO_TCP) {
	    void *start;      
	    if ((start = find_ip6_hdr(hdr + *ofs, IPPROTO_TCP, 
				      (__u8)*hint, 0 )) == NULL)
	      return -EFAULT;
	    tcp = (struct tcphdr *)start;
	    *ofs = start - hdr + sizeof(struct tcphdr);
	} else {
	    tcp = (struct tcphdr *)(hdr + *ofs);
	    *ofs += sizeof(struct tcphdr);
	}
    } else return -EINVAL;

    *hint = tcp->dest;/* dest port as hint */
    if (size) *size += sizeof(struct tcphdr);
    return 0; 
}

static int pkt_to_tuple(const void *hdr, struct tn_tuple *t, int *ofs,
			int dir, int idx)
{
    struct tcphdr *tcp;
    struct tcp_data *d = (struct tcp_data *)
	&(t->data[t->proto->hier[idx]->max_data - sizeof(struct tcp_data)]);


    if (dir == V4TOV6) {
	tcp = (struct tcphdr *)(hdr + *ofs);

	d->v4port[NAT_HOST] = tcp->dest;
	d->v4port[NAT_DEST] = tcp->source;
    } else if (dir == V6TOV4) {
	void *start = find_ip6_hdr(hdr, IPPROTO_TCP, 0,  1);

	if (start == NULL) return -EFAULT;
	else tcp = (struct tcphdr *) start;

	d->v6port[NAT_HOST] = tcp->dest;
	d->v6port[NAT_DEST] = tcp->source;
	*ofs = start - hdr;
    }

    return 0;
}

static int complete_tuple(struct tn_tuple *t, int dir, int idx)
{
    struct tn_proto *p = t->proto->hier[idx];
    struct tcp_data *tcp = (struct tcp_data *)&
	(t->data[p->max_data 
		- sizeof(struct tcp_data)]);
    __u16 *port;
    __u16 min, max, i;

    /* find nat_info */
    if (dir == V4TOV6) {
	tcp->v6port[NAT_DEST] = tcp->v4port[NAT_HOST];
	tcp->v6port[NAT_HOST] = tcp->v4port[NAT_DEST];    
	port = &(tcp->v6port[NAT_HOST]);
    } else if (dir == V6TOV4) {
	tcp->v4port[NAT_DEST] = tcp->v6port[NAT_HOST];
	tcp->v4port[NAT_HOST] = tcp->v6port[NAT_DEST];
	port = &(tcp->v4port[NAT_HOST]);

    } else {
	return -EINVAL;
    }

     /* rip-off from ip_nat_proto_tcp.c */
    if (ntohs(*port) < 1024) {
	/* Loose convention: >> 512 is credential passing */
	if (ntohs(*port)<512) {
	    min = 1; max = 511;
	} else if (ntohs(*port)<1024) {
	    min = 600; max = 1023;
	}
    } else {
	min = 1024; max = 65535;
    }
        
   
    for (i = min; i <= max; i++) {
	*port = htons(i);
	if (napt_find_ctrack(t, dir) == NULL) break;
    }

    if (i == max) return -EFAULT;
    return 0;
}

static int tuple_cmp(const struct tn_tuple *t1, const struct tn_tuple *t2,
		     int dir, int idx)
{
    struct tn_proto *p1 = t1->proto->hier[idx];
    struct tcp_data *d1, *d2;

    if (p1 != t2->proto->hier[idx] ||
	strcmp(p1->name, "tcp") != 0)
	return 0;

    d1 = (struct tcp_data *)&(t1->
			      data[p1->max_data - sizeof(struct tcp_data)]);
    d2 = (struct tcp_data *)&(t2->
			      data[p1->max_data - sizeof(struct tcp_data)]);

    if (dir == V4TOV6) {
	return memcmp(d1->v4port, d2->v4port, sizeof(__u16) * 2) == 0;
    } else if (dir == V6TOV4)
	return memcmp(d1->v6port, d2->v6port, sizeof(__u16) * 2) == 0;

    return 0;
}


static int translate(struct tn_translate *t)
{
    struct tn_proto *p= t->ct->tuple.proto->hier[t->idx];
    struct tcphdr *tcp;
    struct tcp_data *d;
    int  len = 0;

    tcp = t->out->h.th = (struct tcphdr *)skb_put(t->out,
						   sizeof(struct tcphdr));

    d = (struct tcp_data *)&(t->ct->tuple.data[p->max_data - 
						sizeof(struct tcp_data)]);


    if (t->dir == V4TOV6) {
	memcpy(tcp, t->pkt->data+t->pkt_ofs, sizeof(struct tcphdr));
	if (t->ct->dir == t->dir) tcp->source = d->v6port[NAT_HOST];
	else { 
	    tcp->dest = d->v6port[NAT_DEST];
	}
    } else if (t->dir == V6TOV4) {
	void *start = find_ip6_hdr(t->pkt->nh.ipv6h, IPPROTO_TCP, 0, 1);
	if (start == NULL) return -EFAULT;
	memcpy(tcp, start, sizeof(struct tcphdr));
	t->pkt_ofs = (unsigned)(start - VOID t->pkt->data);
	if (t->ct->dir == t->dir) tcp->source = d->v4port[NAT_HOST];
	else {
	    tcp->dest = d->v4port[NAT_DEST];
	}
	len = t->pkt->len - (unsigned)(VOID start - VOID t->pkt);
    } else return -EINVAL;


    /* CHECK FOR DATA LENGTH!!!! */
    t->pkt_ofs += sizeof(struct tcphdr);

    /* except for ports, everything in tcp header is the same, so
       it doesn't matter which we pass (the old or new) */
    t->add_timeout = update_state(tcp, t->ct, t->dir, t->idx);
    if (t->idx < t->ct->tuple.proto->states - 1 &&
	t->pkt_ofs < t->pkt->len) { /* we are not last */
	int ret;
	t->idx++;
	ret = t->ct->tuple.proto->hier[t->idx]->translate(t);
	t->idx--;
	if (ret) return ret;
    } else { /* if we are last, just copy rest */
	/* only most upper protocol sets timeout */
	if (t->pkt->len > t->pkt_ofs) {
	    unsigned int len = (unsigned int)(t->pkt->tail - 
					      (t->pkt->data + t->pkt_ofs));

	    memcpy(skb_put(t->out, len), VOID (t->pkt->data+t->pkt_ofs), len);
	    t->pkt_ofs += len;
	}
    }

    tcp->check = 0;
    len = (unsigned int)(VOID t->out->tail - VOID(t->out->h.th));

    /* now do the freaking checksum */
    if (t->dir == V4TOV6) {
	struct ipv6hdr *ip6h = t->out->nh.ipv6h;
	/* rfc2460 says something about routing header options...
	   DICK! */
	tcp->check = csum_ipv6_magic(&ip6h->saddr, &ip6h->daddr,
				     len, IPPROTO_TCP,
				     csum_partial((unsigned char *)tcp,
						  len, 0));
    } else {
	struct iphdr *iph = t->out->nh.iph;
	tcp->check = csum_tcpudp_magic(iph->saddr, iph->daddr, len,
				       IPPROTO_TCP, 
				       csum_partial((unsigned char *)tcp,
						    len, 0));
    }

    return 0;
}

static int new(struct tn_proto *p)
{

    if (p == NULL) return -EINVAL;

    memset(p, 0, sizeof(struct tn_proto));
    strcpy(p->name, "tcp");
    p->states = 1;
    p->ismine = ismine;
    p->pkt_to_tuple = pkt_to_tuple;
    p->complete_tuple = complete_tuple;
    p->new_ctrack = generic_new_ctrack;
    p->translate = translate;
    p->tuple_cmp = tuple_cmp;
    p->max_data = sizeof(struct tcp_data);
    p->__mod = THIS_MODULE;

    return 0;
}

int __init napt_proto_tcp_init()
{
    /* temporary */
    if (napt_register_proto("tcp", new)) return -1;
    return napt_append_proto_tree(napt_find_proto_by_name(NULL, "ip"), "tcp");
    /* return napt_register_proto("tcp", new); */
}

void __exit napt_proto_tcp_exit()
{
    /* how does conntrack do that it can't be unloaded ? */
    napt_remove_proto_tree(NULL, "tcp");
    napt_unregister_proto("tcp");
}

module_init(napt_proto_tcp_init);
module_exit(napt_proto_tcp_exit);
