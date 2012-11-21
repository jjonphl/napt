#include "napt.h"
#include <linux/kernel.h>
#include <linux/if_ether.h>
#include <linux/inetdevice.h>
#include <net/if_inet6.h>

static __u32 g_v4addr;
static struct in6_addr g_v6addr;

static char *v4iface, *v6iface;
MODULE_PARM(v4iface, "s");
MODULE_PARM(v6iface, "s");

static int update_state(const void *pkt, 
			struct tn_ctrack *ct, int dir, int idx)
{
    __u8 *state = &(ct->state[ct->tuple.proto->hier[idx]->states-1]);
    int ret = 0;


    if (*state == ST_GROUND) {
	if (dir == ct->dir) {
	    *state = ST_ORIGDIR;
	    ret = 5 MINS; /* temporary lang */
	} else {
	    ret = 0;
	}
    } else if (*state == ST_ORIGDIR) {
	if (dir == ct->dir) ret = 1 MINS;
	else {
	    *state = ST_REPLIED;
	    ret = 7 MINS;
	}
    } else if (*state == ST_REPLIED)
	ret = 7 MINS;

    return ret;
}


static int ismine(const void *hdr, int *hint, int *ofs, int dir, int *size)
{
    if (dir == V4TOV6 && ntohs(*hint) == ETH_P_IP) {
	struct iphdr *iph = (struct iphdr *)(hdr + *ofs);
	if (iph->version != 4) return 0; /* the least check we can do */
	*ofs += iph->ihl * 4;
	if (size) *size += sizeof(struct ipv6hdr);
	*hint = (unsigned) iph->protocol; /* this is only 8 bits */
    } else if (dir == V6TOV4 && ntohs(*hint) == ETH_P_IPV6) {
	struct ipv6hdr *ip6h = (struct ipv6hdr *)(hdr + *ofs);
	__u8 ret, *curhdr;

	if (ip6h->version != 6) return 0;

	ret = (ip6h->nexthdr);
	curhdr = (__u8 *)hdr + sizeof(struct ipv6hdr);

	*ofs += sizeof(struct ipv6hdr);
	do {
	    switch(ret) {
	    case NEXTHDR_FRAGMENT: /* network specific headers */
		*ofs += sizeof(struct frag_hdr);
		ret = *curhdr;
		curhdr += sizeof(struct frag_hdr);
		break;
	    case NEXTHDR_HOP:
	    case NEXTHDR_ROUTING:
	    case NEXTHDR_DEST:
		*ofs += curhdr[1]; 
		ret = *curhdr;
		curhdr += curhdr[1];
		break;
	    default: *hint = ret; goto ISMINE_V6_DONE;
	    }
	} while (1);
    ISMINE_V6_DONE:
	if (size) *size += sizeof(struct iphdr);
    }
    
    return 0;
}

static int pkt_to_tuple(const void *hdr, struct tn_tuple *t,
		    int *ofs, int dir, int idx)
{
    /* TODO: do tunneled (i.e. when idx != 0)  */
    if (idx != 0) return -EPROTONOSUPPORT;

    printk("napt ip: making tuple (%d)!!!\n", dir);
    if (dir == V4TOV6) {
	struct iphdr *iph = (struct iphdr *)(hdr + *ofs);
	/* because mapping between v4 to v6 is "explicit" w/o
	   ::ffff:a.b.c.d (i think) */
	t->v4addr[NAT_HOST] = iph->daddr;
	t->v4addr[NAT_DEST] = iph->saddr;
	*ofs += iph->ihl * 4;
    } else if (dir == V6TOV4) {
	struct ipv6hdr *iph = (struct ipv6hdr *)(hdr + *ofs);
	/* temporary, more "powerful" looks up nat mapping */
	memcpy(&t->v6addr[NAT_HOST], &iph->saddr, sizeof(iph->daddr));
	memcpy(&t->v6addr[NAT_DEST], &iph->daddr, sizeof(iph->daddr));
	*ofs += sizeof(struct ipv6hdr);
    } else return -EINVAL;
    return 0;
}

static int complete_tuple(struct tn_tuple *t, 
			  int dir, int idx)
{
    int ret = -EINVAL;
    if (dir == V4TOV6) {
	ret = -EPROTONOSUPPORT;
    } else if (dir == V6TOV4) {
	struct in6_addr *p_v6addr = &t->v6addr[NAT_DEST];
	if (ipv6_addr_type(p_v6addr) | IPV6_ADDR_COMPATv4) {
	    t->v4addr[NAT_HOST] = g_v4addr;
	    t->v4addr[NAT_DEST] = (p_v6addr->s6_addr32[3]);
	    ret = 0;
	}
    } 
    return ret;
}


static int tuple_cmp(const struct tn_tuple *tt1, const struct tn_tuple *tt2, 
		     int dir, int idx)
{
    /* 0 here is failure */
    if (idx != 0) return 0;
    if (dir == V4TOV6) {
	if (((tt1->v4addr[NAT_HOST] == tt2->v4addr[NAT_HOST]) &&
	     (tt1->v4addr[NAT_DEST] == tt2->v4addr[NAT_DEST])) ||
	    ((tt1->v4addr[NAT_HOST] == tt2->v4addr[NAT_DEST]) &&
	     (tt1->v4addr[NAT_DEST] == tt2->v4addr[NAT_HOST]))) return 1;
    } else if (dir == V6TOV4) {
	if ((memcmp(&tt1->v6addr[NAT_HOST],&tt2->v6addr[NAT_HOST], 
		    sizeof(struct in6_addr)) == 0 &&
	     memcmp(&tt1->v6addr[NAT_DEST],&tt2->v6addr[NAT_DEST],
		    sizeof(struct in6_addr)) == 0) ||
	    (memcmp(&tt1->v6addr[NAT_HOST],&tt2->v6addr[NAT_DEST],
		    sizeof(struct in6_addr)) == 0 &&
	     memcmp(&tt1->v6addr[NAT_DEST],&tt2->v6addr[NAT_HOST],
		    sizeof(struct in6_addr)) == 0)) return 1;
    }

    return 0;

}


static int translate(struct tn_translate *t)
{

    /* next upper protocol _will_ always look at ip header */

    if (t->dir == V4TOV6) {
	struct iphdr *iph = (struct iphdr *)(t->pkt->data + t->pkt_ofs);
	struct ipv6hdr *ip6h = t->out->nh.ipv6h = 
	    (struct ipv6hdr *)skb_put(t->out, sizeof(struct ipv6hdr));
	__u8 *proto = &(ip6h->nexthdr);

	/* hop limit, determine as early as possible if there
	   is error */
	if (iph->ttl < 2) {
	    icmp_send(t->pkt, ICMP_TIME_EXCEEDED, 0, 0);
	    return -EFAULT;
	}

	memset(ip6h, 0, sizeof(struct ipv6hdr));

	ip6h->hop_limit = iph->ttl--;

	/* if there are options, fish for source routing errors as 
	   stated in [SIIT] */
	if (iph->ihl > 5)  { 
	    struct ip_option *optstart = (struct ip_option *)((void *)iph + 
							      sizeof(struct iphdr));
	    struct ip_option *opt;
	    __u8 optarg;
	    int optlen = 0; /* not used ??? */

	    for (opt = optstart; (void *)opt < (void *)optstart + (iph->ihl-5)*4; ) {
		switch (opt->type) {
		case 0 : /* end of option list */
		    optlen++;
		    goto OPT_FINISH;
		case 1: /* no operation */
		    optlen++;
		    ((void *)opt)++; break;
		case 130: /* security */
		    optlen += 11;
		    ((void *)opt) += 11; break;
		case 131: /* loose source routing */
		case 137: /* strict source routing */
		    optarg = *(__u8*)((void *)opt + 2);
		    if (optarg < opt->length) {
			icmp_send(t->pkt, ICMP_DEST_UNREACH, ICMP_SR_FAILED, 0);
			return -EFAULT;
		    } else ((void *)opt) += opt->length;
		    optlen += opt->length;
		    break;
		case 7: /* record route */
		case 68: /* internet timestamp */
		    optlen += opt->length;
		    ((void *)opt) += opt->length; break;
		case 136: /* stream identifier */
		    optlen += 4;
		    ((void *)opt) += 4; break;
		default: /* param problem, unknown option */
		    icmp_send(t->pkt, ICMP_PARAMETERPROB, 0, htonl(20 << 24));
		    return -EFAULT;
		}
	    }
	}
    OPT_FINISH:

	/* version */
	ip6h->version = 6;
	ip6h->tclass1 = 0; /* their struct is crap */


	/* source and destination address */
	{
	    struct in6_addr *addr1, *addr2;
	    if (t->ct->dir == V6TOV4) {
		addr1 = &t->ct->tuple.v6addr[NAT_DEST];
		addr2 = &t->ct->tuple.v6addr[NAT_HOST];
	    }
	    else {
		addr1 = &t->ct->tuple.v6addr[NAT_HOST];
		addr2 = &t->ct->tuple.v6addr[NAT_DEST];
	    }
	    memcpy(&(ip6h->saddr), addr1, sizeof(ip6h->saddr));
	    memcpy(&ip6h->daddr, addr2, sizeof(ip6h->saddr));
	}
  
	/* flow label (traffic class is flow_lbl[0] */
	memset(&ip6h->tclass2_flow, 0, sizeof(ip6h->tclass2_flow));


	/* if fragmented */
	if (iph->frag_off & htons(IP_MF)) {
	    struct frag_hdr *frag = (struct frag_hdr *)
		skb_put(t->out, sizeof(struct frag_hdr));

	    ip6h->nexthdr = NEXTHDR_FRAGMENT;
	    ip6h->payload_len = htons(sizeof(struct frag_hdr));
	    proto =  (__u8 *)&(frag->nexthdr);
	    frag->identification = htonl(iph->id);
	    frag->frag_off = (iph->frag_off << 3) & IP6_OFFSET;
	    frag->frag_off |= (iph->frag_off & IP_MF) ? 1 : 0;
	} 

	if (iph->protocol != IPPROTO_ICMP)
	    *proto = iph->protocol;
	else *proto = IPPROTO_ICMPV6;

	t->pkt_ofs += iph->ihl * 4;

    } else if (t->dir == V6TOV4) {
	struct ipv6hdr *ip6h = (struct ipv6hdr *)(t->pkt->data + t->pkt_ofs);
	struct iphdr *iph = t->out->nh.iph = 
	    (struct iphdr *)skb_put(t->out, sizeof(struct iphdr));
	__u8 *nxthdr = (__u8 *)(ip6h + 1); 
	__u8 curhdr = ip6h->nexthdr;
	int fragmented = 0;

	/* ttl */
	if (ip6h->hop_limit < 2) {
	    /* CNANGE send_err */
	    icmpv6_send(t->pkt, ICMPV6_TIME_EXCEED, 0, 0, t->pkt->dst->dev);
	    return -EFAULT;
	}
	memset(iph, 0, sizeof(struct iphdr));

	iph->ttl = htons(ntohs(ip6h->hop_limit-1));

	while (curhdr != NEXTHDR_TCP &&
	       curhdr != NEXTHDR_UDP &&
	       curhdr != NEXTHDR_ICMP &&
	       curhdr != NEXTHDR_NONE) {
	    /* disregard esp and auth (naks, hehehe) */
	    switch (curhdr) {
	    case NEXTHDR_ROUTING:
		if (nxthdr[3] > 0) {
		    icmpv6_send(t->pkt, ICMPV6_PARAMPROB, 0, 
				htonl((unsigned long)
				      (VOID &(nxthdr[3]) - 
				       VOID t->pkt->nh.ipv6h)),
				t->pkt->dst->dev);
		    return -EFAULT;
		}
		
		nxthdr += (nxthdr[1]+1) * 8;
		break;
	    case NEXTHDR_FRAGMENT: {
		struct frag_hdr *frag = (struct frag_hdr *)nxthdr;
		fragmented = 1;

		iph->id = htons(((__u16)(ntohl(frag->identification)) & 0xFFFF));

		/* DF = 0 */ /* ??? */
		if (frag->frag_off & IP6_MF) /* MDF(6) -> MF(4)*/
		    iph->frag_off = iph->frag_off | IP_MF;

		iph->frag_off |= (frag->frag_off >> 3) & IP_OFFSET;
		nxthdr = (__u8*)frag;
	    } break;
	    /* case NEXTHDR_HOP:
	       case NEXTHDR_DEST: */
	    default:
		/* not specified by rfc2460, skip for the moment*/
		/* got this style from ip6_input_finish =P */
		nxthdr += (nxthdr[1]+1) * 8;
		break;

	    }
	    curhdr = *nxthdr;
	}
        
	if (curhdr != IPPROTO_ICMPV6)
	    iph->protocol = curhdr; /* even if NEXTHDR_NONE, bahala na! XP */
	else iph->protocol = IPPROTO_ICMP;
	if (!fragmented) 
	    /* iph->id = 0, iph->frag_off(MF) = 0, 
	       iph->frag_off(FRAG_OFF) = 0 */
	    iph->frag_off |= htons(IP_DF);

   
	/* version */
	iph->version = 4;
    
	/* header length (no option) */
	iph->ihl = 5;

	/* source and destination */
	if (t->ct->dir == V6TOV4) {
	    iph->daddr = t->ct->tuple.v4addr[NAT_DEST];
	    iph->saddr = t->ct->tuple.v4addr[NAT_HOST];
	} else {
	    iph->daddr = t->ct->tuple.v4addr[NAT_HOST];
	    iph->saddr = t->ct->tuple.v4addr[NAT_DEST];
	}

	/* tos */
	/* if (!(gopts.flags & IP4_ZERO_TOS)) 
	   iph->tos = (ip6h->priority << 4) +  
	    ((ip6h->flow_lbl[0] & 0xF0) >> 4); */

	t->pkt_ofs = (unsigned)(VOID nxthdr - VOID t->pkt->data);

    }


    t->add_timeout = update_state(VOID t->pkt->nh.iph, t->ct, t->dir, t->idx);

    if (t->idx < t->ct->tuple.proto->states - 1 &&
	t->pkt_ofs < t->pkt->len) { /* we are not last */

	int ret;
	t->idx++;
	ret = t->ct->tuple.proto->hier[t->idx]->translate(t);
	t->idx--;
	if (ret) return ret;
    } else { /* if we are last, just copy rest */
	/* only most upper protocol sets timeout */
	
	if (t->out->tail - t->pkt_ofs > t->out->data) {
	    void *buf, *start;
	    buf = skb_put(t->out, (unsigned)(t->out->tail - t->pkt_ofs));
	    start = t->pkt->data + t->pkt_ofs;
	    memcpy(buf, start, (unsigned)(t->pkt->tail - t->pkt_ofs));
	}
    }

    if (t->dir == V6TOV4) {
	struct iphdr *iph = (struct iphdr *)t->out->nh.iph;
	iph->tot_len = htons((unsigned)(VOID t->out->tail - VOID t->out->nh.iph));
	ip_send_check(iph);
    } else {
	struct ipv6hdr *ip6h = (struct ipv6hdr *)t->out->nh.ipv6h;
	ip6h->payload_len = htons((unsigned)(VOID t->out->tail - 
					     VOID (t->out->nh.ipv6h+1)));
    }

    return 0;
}    


static int new(struct tn_proto *p)
{

    if (p == NULL) return -EINVAL;

    memset(p, 0, sizeof(struct tn_proto));
    strcpy(p->name, "ip");
    p->states = 1;
    p->ismine = ismine;
    p->pkt_to_tuple = pkt_to_tuple;
    p->complete_tuple = complete_tuple;
    p->new_ctrack = generic_new_ctrack;
    p->translate = translate;
    p->tuple_cmp = tuple_cmp;
    p->__mod = THIS_MODULE;
    return 0;
}


static int setup_gaddr(struct net_device *dev, int dir)
{
    int ret = -1;
    if (dir == V4TOV6) {
	struct in_device *indev;
	indev = ((struct in_device *)dev->ip_ptr);
	if (!indev) { printk("napt ip: no indev!\n"); goto DONE_GADDR; }
	if (!indev->ifa_list) { 
	    printk("napt ip: no ifa_list!\n"); goto DONE_GADDR; 
	}
	g_v4addr = indev->ifa_list->ifa_address;
	ret = 0;
    } else if (dir == V6TOV4) {
	struct inet6_dev *indev;
	struct inet6_ifaddr *addr;
	int flag = 0;

	indev = ((struct inet6_dev *)dev->ip6_ptr);
	if (!indev) { printk("napt ip: no inet6_dev!\n"); goto DONE_GADDR; }
	addr = indev->addr_list;

	for (addr = indev->addr_list; addr; addr = addr->if_next)
	    if (addr->scope == IFA_GLOBAL) { flag = 1; break; }	

	if (!flag) { 
	    printk("napt ip: no global ip6 addr!\n"); goto DONE_GADDR;
	}
	memcpy(&g_v6addr, &addr->addr, sizeof(g_v6addr));
	ret = 0;
    }

 DONE_GADDR:
    dev_put(dev);
    return ret;
}

int __init napt_proto_ip_init()
{
    int ret;
    struct net_device *dev;    
    /*
    __u8 *addr = (__u8 *)&g_v4addr;
    addr[0] = 192;
    addr[1] = 168;
    addr[2] = 123;
    addr[3] = 5;
    */

    if (!v4iface) {
	/* default: v4iface 1st device, v6iface 2nd device */
	if (!(dev = dev_get_by_index(2))) {
	    printk("napt ip: no device 0\n");
	    return -1;
	}
    }
    else 
	if (!(dev = dev_get_by_name(v4iface))) {
	    printk("napt ip: no device 0\n"); 
	    return -1;
	}

    if (setup_gaddr(dev, V4TOV6)) return -1;

    printk("napt ip: v4 (%d.%d.%d.%d)\n", NIPQUAD(g_v4addr));
    
    if (!v6iface) {
	if (!(dev = dev_get_by_index(3))) {
	    printk("napt ip: no device 1\n");
	    return -1;
	}
    } else
	if (!(dev = dev_get_by_name(v6iface))) {
	    printk("napt ip: no device 0\n"); 
	    return -1;
	} 

    if (setup_gaddr(dev, V6TOV4)) return -1;
    printk("napt ip: v6 (%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n)\n",
		    NIP6(g_v6addr));

    if ((ret = napt_register_proto("ip", new))) return ret;
    if ((ret = napt_append_proto_tree(NULL, "ip"))) return ret;
    return 0;
}

void __exit napt_proto_ip_exit()
{
    /* how does conntrack do that it can't be unloaded ? */
    /*if (!napt_remove_proto_tree(NULL, "ip") &&
        !napt_unregister_proto("ip")) MOD_DEC_USE_COUNT; */
    napt_remove_proto_tree(NULL, "ip");
    napt_unregister_proto("ip");
}

module_init(napt_proto_ip_init);
module_exit(napt_proto_ip_exit);
