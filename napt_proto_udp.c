#include "napt.h"
#include <linux/udp.h>

struct udp_data {
    __u16 v4port[2], v6port[2];
};

/* just like in ip, because it is stateless like ip, only more time.
   i don't like the idea of exporting it...
*/
static int update_state(const void *pkt, 
			struct tn_ctrack *ct, int dir, int idx)
{
    __u8 *state = &(ct->state[ct->tuple.proto->hier[idx]->states-1]);
    int ret = 0;


    if (*state == ST_GROUND) {
	if (dir == ct->dir) {
	    *state = ST_ORIGDIR;
	    ret = 3 MINS;
	} else {
	    printk("napt: packet in opposite direction seen first!\n");
	    ret = 0;
	}
    } else if (*state == ST_ORIGDIR) {
	if (dir == ct->dir) ret = 3 MINS;
	else {
	    *state = ST_REPLIED;
	    ret = 10 MINS;
	}
    } else if (*state == ST_REPLIED)
	ret = 10 MINS;

    return ret;
}

static int ismine(const void *hdr, int *hint, int *ofs, int dir, int *size)
{
    struct udphdr *udp;
    __u8 proto = ((__u8)*hint);

    if (dir == V4TOV6) { /* the easy part */
	if (proto != IPPROTO_UDP) return -EINVAL;
	udp = (struct udphdr *)(hdr + *ofs);
	*ofs += sizeof(struct udphdr);
    } else if (dir == V6TOV4) {
	if (proto != IPPROTO_UDP) {
	    void *start;      
	    if ((start = find_ip6_hdr(hdr + *ofs, IPPROTO_UDP,
				      (__u8)*hint, 0)) == NULL)
		return -EFAULT;
	    udp = (struct udphdr *)start;
	    *ofs = start - hdr + sizeof(struct udphdr);
	} else {
	    udp = (struct udphdr *)(hdr + *ofs);
	    *ofs += sizeof(struct udphdr);
	}
    } else return -EINVAL;
    
    *hint = udp->dest; /* dest port as hint (note sign expansion) */ 
    if (size) *size += sizeof(struct udphdr);
    return 0;
}

static int pkt_to_tuple(const void *hdr, struct tn_tuple *t, int *ofs, 
			int dir, int idx)
{
    struct udphdr *udp;
    struct udp_data *d = (struct udp_data *)
	&(t->data[t->proto->hier[idx]->max_data - sizeof(struct udp_data)]);

    if (dir == V4TOV6) {
	udp = (struct udphdr *)(hdr + *ofs);

	d->v4port[NAT_HOST] = udp->dest;
	d->v4port[NAT_DEST] = udp->source;
    } else if (dir == V6TOV4) {
	void *start = find_ip6_hdr(hdr, IPPROTO_UDP, 0, 1);

	if (start == NULL) return -EINVAL;
	else udp = (struct udphdr *) start;

	d->v6port[NAT_HOST] = udp->dest;
	d->v6port[NAT_DEST] = udp->source;
	*ofs = start - hdr;
    }

    return 0;
}

static int complete_tuple(struct tn_tuple *t, int dir, int idx)
{
    struct udp_data *udp = (struct udp_data *)
	&(t->data[t->proto->hier[idx]->max_data - sizeof(struct udp_data)]);
    __u16 *port;
    __u16 min, max, i;

    /* find nat_info */
    if (dir == V4TOV6) {
	udp->v6port[NAT_DEST] = udp->v4port[NAT_HOST];
	udp->v6port[NAT_HOST] = udp->v4port[NAT_DEST];    
	port = &(udp->v6port[NAT_HOST]);

    } else if (dir == V6TOV4) {
	udp->v4port[NAT_DEST] = udp->v6port[NAT_HOST];
	udp->v4port[NAT_HOST] = udp->v6port[NAT_DEST];
	port = &(udp->v4port[NAT_HOST]);

    } else {
	return -EINVAL;
    }

    if (ntohs(*port) < 1024) {
	/* Loose convention: >> 512 is credential passing */
	if (ntohs(*port)<512) {
	    min = 1; max = 511;
	} else if (ntohs(*port)<1024){
	    min = 600; max = 1023;
	}
    } else {
	min = 1024; max = 65535;
    }
    

    for (i = min; i <= max; i++) {
	*port = htons(i);
	if (napt_find_ctrack(t, dir) == NULL) break;
    }

    if (i > max) return -EFAULT;
  
    return 0;
}

static int tuple_cmp(const struct tn_tuple *t1,  const struct tn_tuple *t2,
		     int dir, int idx)
{
    struct tn_proto *p1 = t1->proto->hier[idx];
    struct udp_data *d1, *d2;

    if (p1 != t2->proto->hier[idx] ||
	strcmp(p1->name, "udp") != 0)
	return 0;

    d1 = (struct udp_data *)&(t1->
			      data[p1->max_data - sizeof(struct udp_data)]);
    d2 = (struct udp_data *)&(t2->
			      data[p1->max_data - sizeof(struct udp_data)]);

    if (dir == V4TOV6) {
	return memcmp(d1->v4port, d2->v4port, sizeof(__u16) * 2) == 0;
    } else if (dir == V6TOV4)
	return memcmp(d1->v6port, d2->v6port, sizeof(__u16) * 2) == 0;

    return 0;
}

/* i think this is done */
static int translate(struct tn_translate *t)
{
    struct tn_proto *p= t->ct->tuple.proto->hier[t->idx];
    struct udphdr *udp;
    struct udp_data *d;

    udp = t->out->h.uh = (struct udphdr *)skb_put(t->out,
						   sizeof(struct udphdr));

    d = (struct udp_data *)&(t->ct->tuple.data[p->max_data - 
						sizeof(struct udp_data)]);

    if (t->dir == V4TOV6) {
	memcpy(udp, t->pkt->data+t->pkt_ofs, sizeof(struct udphdr));
	if (t->ct->dir == t->dir) udp->source = d->v6port[NAT_HOST];
	else { 
	    udp->dest = d->v6port[NAT_DEST];
	}
    } else if (t->dir == V6TOV4) {
	void *start = find_ip6_hdr(t->pkt->nh.ipv6h, IPPROTO_UDP, 0, 1);
	if (start == NULL) return -EFAULT;
	memcpy(udp, start, sizeof(struct udphdr));
	t->pkt_ofs = (unsigned)(start - VOID t->pkt->data);
	if (t->ct->dir == t->dir) udp->source = d->v4port[NAT_HOST];
	else {
	    udp->dest = d->v4port[NAT_DEST];
	}
    } else return -EINVAL;


    t->pkt_ofs += sizeof(struct udphdr);


    t->add_timeout = update_state(udp, t->ct, t->dir, t->idx);
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

    /* DONE from here down */
    udp->len = htons(VOID t->out->tail - VOID udp);
    udp->check = 0;

    /* now do the freaking checksum */
    if (t->dir == V4TOV6) {
	struct ipv6hdr *ip6h = t->out->nh.ipv6h;
	/* rfc2460 says something about routing header options...
	   DICK! */
	udp->check = csum_ipv6_magic(&ip6h->saddr, &ip6h->daddr,
				     ntohs(udp->len), IPPROTO_UDP,
				     csum_partial((unsigned char *)udp,
						  ntohs(udp->len), 0));
    } else {
	struct iphdr *iph = t->out->nh.iph;
	udp->check = csum_tcpudp_magic(iph->saddr, iph->daddr, ntohs(udp->len),
				       IPPROTO_UDP, 
				       csum_partial((unsigned char *)udp,
						    ntohs(udp->len), 0));
    }

    return 0;
}

static int new(struct tn_proto *p)
{

    if (p == NULL) return -EINVAL;

    memset(p, 0, sizeof(struct tn_proto));
    strcpy(p->name, "udp");
    p->states = 1;
    p->ismine = ismine;
    p->pkt_to_tuple = pkt_to_tuple;
    p->complete_tuple = complete_tuple;
    p->new_ctrack = generic_new_ctrack;
    p->translate = translate;
    p->tuple_cmp = tuple_cmp;
    p->max_data = sizeof(struct udp_data);
    p->__mod = THIS_MODULE;

    return 0;
}

/* saka na kopyahin sa napt_proto_ip pag sigurado na */
int __init napt_proto_udp_init()
{
    /* temporary */
    if (napt_register_proto("udp", new)) return -1;
    return napt_append_proto_tree(napt_find_proto_by_name(NULL, "ip"), "udp");
}

void __exit napt_proto_udp_exit()
{
    /* how does conntrack do that it can't be unloaded ? */
    napt_remove_proto_tree(NULL, "udp");
    napt_unregister_proto("udp");
}

module_init(napt_proto_udp_init);
module_exit(napt_proto_udp_exit);
