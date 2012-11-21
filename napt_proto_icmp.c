#define __NAPT_NEEDS_SEND__
#include "napt.h"


struct icmp_data {
    __u8 type[2], code[2];
    __u16 echo_id;
    __u8 dir;
};

#define ECHO_TIMEOUT   1 MINS

static int update_state(const void *pkt, struct tn_ctrack *ct, int dir, int idx)
{
    struct icmphdr *icmp = (struct icmphdr *)pkt;
    int ret = 0;

    if (dir == V4TOV6) {
	if (icmp->type == ICMP_ECHO || icmp->type == ICMP_ECHOREPLY)
	    ret = ECHO_TIMEOUT;
    } else if (dir == V6TOV4) {
	if (icmp->type == ICMPV6_ECHO_REQUEST || 
	    icmp->type == ICMPV6_ECHO_REPLY) ret = ECHO_TIMEOUT;
    }

    return ret;
}

static int ismine(const void *prev_hdr, int *hint, int *ofs, int dir, int *size)
{
    icmp_hint h;
    struct icmphdr *icmp;
    if (dir == V4TOV6 && *hint == IPPROTO_ICMP) {
	icmp = (struct icmphdr *)(prev_hdr + *ofs);
    } else if (dir == V6TOV4) {
	if (*hint != IPPROTO_ICMPV6) {
	    void *start = find_ip6_hdr(prev_hdr + *ofs, IPPROTO_ICMPV6,
				       (__u8)*hint,  0);
	    if (start == NULL) return -EFAULT;
	    icmp = (struct icmphdr *)start;
	} else icmp = (struct icmphdr *)(prev_hdr + *ofs);

    } else return -EINVAL;

    h.icmp.type = icmp->type; h.icmp.code = icmp->code;
    if (size) *size += sizeof(struct icmphdr);
    *hint = h.i;
    return 0;
}


static int pkt_to_tuple(const void *hdr, struct tn_tuple *tm, 
			int *ofs, int dir, int idx)
{
    struct icmp_data *d = (struct icmp_data *)&(tm->
	data[tm->proto->hier[idx]->max_data - sizeof(struct icmp_data)]);

    /* intercept V4TOV6 dest unreachable by return an error,
       finding the ctrack and translating */
    if (dir == V4TOV6) {
	struct icmphdr *icmp;
	icmp = (struct icmphdr *)(hdr + *ofs);

	switch (icmp->type)
	    { /* just follow [SIIT] */
	    case ICMP_ECHO:
		d->type[dir] = ICMP_ECHOREPLY; goto SET_CODE_V4;
	    case ICMP_ECHOREPLY:
		d->type[dir] = ICMP_ECHO; goto SET_CODE_V4;
	    case ICMP_DEST_UNREACH:
	    case ICMP_TIME_EXCEEDED:
	    case ICMP_PARAMETERPROB:
		break;
	    default: return -EINVAL;
	    }

	d->type[dir] = icmp->type; 

    SET_CODE_V4:
	d->code[dir] = icmp->code;
	if (d->type[dir] == ICMP_ECHO || d->type[dir] == ICMP_ECHOREPLY)
	    d->echo_id = icmp->un.echo.id;

    } else if (dir == V6TOV4) {
	void *start = find_ip6_hdr(hdr, IPPROTO_ICMPV6, 0, 1);
	struct icmp6hdr *icmp;

	printk("napt icmp: mk_tuple V6TOV4\n");
	if (start == NULL) return -EINVAL;
	icmp = (struct icmp6hdr *)start;
	printk("napt icmp: start not null (%d)\n", icmp->icmp6_type);

	switch (icmp->icmp6_type)
	    {
	    case ICMPV6_ECHO_REQUEST:
		d->type[dir] = ICMPV6_ECHO_REPLY; goto SET_CODE_V6;
	    case ICMPV6_ECHO_REPLY:
		d->type[dir] = ICMPV6_ECHO_REQUEST; goto SET_CODE_V6;
	    case ICMPV6_DEST_UNREACH:
	    case ICMPV6_PKT_TOOBIG:
	    case ICMPV6_TIME_EXCEED:
	    case ICMPV6_PARAMPROB:
		break;
	    default:
		printk("napt icmp: inval?\n");
		return -EINVAL;
	    }
	d->type[dir] = icmp->icmp6_type; 

    SET_CODE_V6:
	d->code[dir] = icmp->icmp6_code;
	if (d->type[dir] == ICMPV6_ECHO_REQUEST || 
	    d->type[dir] == ICMPV6_ECHO_REPLY)
	    d->echo_id = icmp->icmp6_identifier; 		
    } else
	return -EINVAL;

    *ofs += sizeof(struct icmphdr);
    return 0;
}

static int complete_tuple(struct tn_tuple *t, int dir, int idx)
{
    struct tn_proto *p = t->proto->hier[idx];
    struct icmp_data *d = (struct icmp_data *)
       &(t->data[p->max_data - sizeof(struct icmp_data)]);


    if (dir == V4TOV6) {
	d->code[V6TOV4] = d->code[dir];
	switch(d->type[dir])
	    {
	    case ICMP_ECHO:
		d->type[V6TOV4] = ICMPV6_ECHO_REPLY;
		break;
	    case ICMP_ECHOREPLY:
		d->type[V6TOV4] = ICMPV6_ECHO_REQUEST;
		break;
	    case ICMP_DEST_UNREACH:
		d->type[V6TOV4] = ICMPV6_DEST_UNREACH;
		switch (d->code[dir]) 
		    {    
		    case 0:
		    case 1: 
		    case 5: /* SIIT says unlikely */
		    case 6:
		    case 7:
		    case 8:
		    case 11:
		    case 12: d->code[V6TOV4] = 0; break;
		    case 2: 
			d->type[V6TOV4] = ICMPV6_PARAMPROB;
			d->code[V6TOV4] = 1;
			break;
		    case 3:
			d->code[V6TOV4] = 4;
			break;
		    case 4:
			d->type[V6TOV4] = ICMPV6_PKT_TOOBIG;
			d->code[V6TOV4] = 0;
			break;
		    case 9:
		    case 10: d->code[V6TOV4] = 1; break;
		    default: return -EINVAL;
		    }
	    case ICMP_TIME_EXCEEDED:
		d->type[V6TOV4] = ICMPV6_TIME_EXCEED; break;
	    case ICMP_PARAMETERPROB:
		d->type[V6TOV4] = ICMPV6_PARAMPROB;
		/* to do: translate pointer! */
		break;
	    default: 
		printk("napt icmp: v4 complete tuple err (%d)", d->type[dir]);
		return -EFAULT;
	    }
    } else if (dir == V6TOV4) {
	d->code[V4TOV6] = d->code[dir];
	printk("napt icmp: v6 complete tuple (%d)", d->type[dir]);
	switch (d->type[dir])
	    {
	    case ICMPV6_ECHO_REQUEST:
		d->type[V4TOV6] = ICMP_ECHOREPLY; break;
	    case ICMPV6_ECHO_REPLY:
		d->type[V4TOV6] = ICMP_ECHO; break;
	    case ICMPV6_DEST_UNREACH:
		d->type[V4TOV6] = ICMP_DEST_UNREACH;
		switch(d->code[dir])
		    {
		    case 0:
		    case 2:
		    case 3: d->type[V4TOV6] = 1; break;
		    case 1: d->type[V4TOV6] = 10; break;
		    case 4: d->type[V4TOV6] = 3;
		    default : return -EINVAL;
		    }
		break;
	    case ICMPV6_PKT_TOOBIG:
		d->type[V4TOV6] = ICMP_DEST_UNREACH;
		d->code[V4TOV6] = 4; /* adjust mtu */
		break;
	    case ICMPV6_TIME_EXCEED:
		d->type[V4TOV6] = ICMP_TIME_EXCEEDED; break;
	    case ICMPV6_PARAMPROB:
		if (d->code[dir] == 1) {
		    d->type[V4TOV6] = ICMP_DEST_UNREACH;
		    d->code[V4TOV6] = 2;
		} else {
		    d->type[V4TOV6] = ICMP_PARAMETERPROB;
		    d->code[V4TOV6] = 0;
		} break;
	    default : 
		printk("napt icmp: v6 complete tuple err (%d)", d->type[dir]);
		return -EFAULT;
	    }
    }

    return 0;
}


static int tuple_cmp(const struct tn_tuple *t1, const struct tn_tuple *t2, 
		     int dir, int idx)
{
    struct tn_proto *p1 = t1->proto;
    struct icmp_data *d1, *d2;

    if (p1->hier[idx] != t2->proto->hier[idx] ||
	strcmp(p1->hier[idx]->name, "icmp") != 0) return -EINVAL;

    p1 = p1->hier[idx];
    d1 = (struct icmp_data *)&(t1->data[p1->max_data - 
				       sizeof(struct icmp_data)]);
    d2 = (struct icmp_data *)&(t2->data[p1->max_data - 
				       sizeof(struct icmp_data)]);


    if (d1->type[dir] != d2->type[dir] || d1->code[dir] != d2->code[dir]) 
	return 0;


    if (dir == V4TOV6) {
	if (d1->type[dir] == ICMP_ECHO || d1->type[dir] == ICMP_ECHOREPLY)
	    return (d1->echo_id == d2->echo_id);

    } else if (dir == V6TOV4) {
	if (d1->type[dir] == ICMPV6_ECHO_REQUEST || 
	    d1->type[dir] == ICMPV6_ECHO_REPLY)
	    return (d1->echo_id == d2->echo_id);
    }


    return 1;
}

static inline int icmp_inner_translate(struct tn_translate *t)
{
    struct tn_ctrack *ct;
    struct tn_tuple tuple;
    int ret = 0, hint;

    if (t->dir == V4TOV6) hint = ETH_P_IP;
    else if (t->dir == V6TOV4) hint = ETH_P_IPV6;
    else return -EINVAL;

    if ((napt_mk_tuple(VOID t->pkt->data+
		       t->pkt_ofs+sizeof(struct icmphdr),
		       htons(hint), t->dir, 
		       &tuple, NULL)) || 
	(ct = napt_find_ctrack(&tuple, t->dir)) == NULL) 
	return -EFAULT;
	  
    t->pkt_ofs += sizeof(struct icmphdr);
    ret = napt_translate(t->pkt, &t->out, ct, t->pkt_ofs , t->dir);
    return ret;

}

/* shit, these craps are already skb's! */
static int translate(struct tn_translate *t)
{
    struct icmphdr *icmp, *tmp_i4 = NULL; 
    struct icmp6hdr *icmp6, *tmp_i6 = NULL;
    struct icmp_data *d;

    int max_data = t->ct->tuple.proto->hier[t->idx]->max_data;

    icmp  = t->out->h.icmph = (struct icmphdr *)skb_put(t->out, 
						     sizeof(struct icmphdr));

    icmp6 = (struct icmp6hdr *) icmp;

    d  = (struct icmp_data *)&t->ct->tuple.data[max_data - 
						sizeof(struct icmp_data)];

    if (t->dir == V4TOV6) {
	/* it is going to the v6 cloud */

	tmp_i4 = (struct icmphdr *)(VOID t->pkt->data + t->pkt_ofs);
	tmp_i6 = (struct icmp6hdr *)tmp_i4;

	icmp6->icmp6_type = d->type[V6TOV4];
	icmp6->icmp6_code = d->code[V6TOV4];

	switch (icmp6->icmp6_type) 
	    {
	    case ICMPV6_ECHO_REQUEST:
	    case ICMPV6_ECHO_REPLY: {
		int len;
		t->pkt_ofs += sizeof(struct icmphdr);
		len = t->pkt->len - t->pkt_ofs;
		icmp6->icmp6_identifier = d->echo_id; 
		icmp6->icmp6_sequence = tmp_i4->un.echo.sequence;
		memcpy(skb_put(t->out, len), t->pkt->data+t->pkt_ofs, len);
		goto IP6_ECHO_START;
	    }
	    /* echo processing */
	    case ICMPV6_PARAMPROB:
		if (icmp6->icmp6_code == 1) { /* protocol unreachable */

		    int ret = icmp_inner_translate(t) ;
		    if (ret) return ret;
		    /* at the next header field */
		    icmp6->icmp6_pointer = htonl(sizeof(struct ipv6hdr)); 
	  	  
		    /* don't allow helper? goto checksum part */
		} else if (icmp6->icmp6_code == 4) { /* v4 param prob */
		    struct iphdr *tmp_ip = (struct iphdr *)(tmp_i4 + 1);
		    __u8 *ptr = (__u8*)&(tmp_i4->un.echo); /* hehehehe */

		    if (!(tmp_ip->ihl > 5 && 
			  (*ptr > 20 && *ptr < tmp_ip->ihl * 4))) 
			/* it is pointing to the options field, drop, we're not
			   sending packets with options */

			return -EINVAL  ;

		    /* TODO: find where it is pointing, then convert it
		       to v6 header equivalent. for now... */
		    return -EINVAL; 
		    /* question: kelangan pa ba 'to? saan pa ba pwedeng 
		       magka param-prob within ip header na hindi options?
		       i copy-paste mo na lang yung sa taas */
		}
		break;
	    case ICMPV6_PKT_TOOBIG: { 
		    int ret = icmp_inner_translate(t);
		    if (ret) return ret;
		    /* mtu stuff */
		    icmp6->icmp6_mtu = htonl(ntohs(tmp_i4->un.frag.mtu));
	    }
	    }

	skb_trim(t->out,IPV6_MIN_MTU);

    IP6_ECHO_START:

	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_cksum = 
	    csum_ipv6_magic(&t->ct->tuple.v6addr[NAT_HOST],
			    &t->ct->tuple.v6addr[NAT_DEST],
			    IPPROTO_ICMPV6,
			    (unsigned)(VOID t->out->tail - VOID icmp6),
			    csum_partial((unsigned char *)icmp6,
					 (unsigned)
					 (VOID t->out->tail - VOID icmp6),
					 0));

	t->pkt_ofs = t->pkt->len;

    } else if (t->dir == V6TOV4) {
	int len;

	tmp_i6 = (struct icmp6hdr *)find_ip6_hdr(t->pkt->data, 
						 IPPROTO_ICMPV6, 0, 1);

	if (tmp_i6 == NULL) return -EINVAL;
	t->pkt_ofs = (unsigned)(VOID tmp_i6 - VOID t->pkt->data);

	tmp_i4 = (struct icmphdr *)tmp_i6;
	icmp->type = d->type[V4TOV6]; icmp->code = d->code[V4TOV6];

	switch (icmp->type) {
	case ICMP_ECHO:
	case ICMP_ECHOREPLY: {
	    len = (unsigned)(VOID t->pkt->tail - VOID(tmp_i6 + 1));
	    icmp->un.echo.id = d->echo_id;
	    icmp->un.echo.sequence = tmp_i6->icmp6_sequence;
	    t->pkt_ofs += sizeof(struct icmp6hdr);
	    memcpy(skb_put(t->out, len), t->pkt->data + t->pkt_ofs, len);
	    goto IP_ECHO_START;
	}

	case ICMP_DEST_UNREACH:
	    if (icmp->code == 4) { /* fragmentation needed */
		int ret = icmp_inner_translate(t);
		if (ret) return ret;
		/* icmp mtu field! */
		icmp->un.frag.mtu = htons(ntohl(tmp_i6->icmp6_mtu));
	    }
	    break;
	case ICMP_PARAMETERPROB:
	    if (icmp->code == 0) { /* parameter problem */
		/* todo: this! */
		return -EINVAL;

		/*
		if (tmp_i6->icmp6_pointer > sizeof(struct ipv6hdr)) 
		    return -EINVAL;
		*/
		
	    } break;
	default: return -EINVAL;

	}

	/* most icmpv4 msgs only include 8 bytes of original packet */
	skb_trim(t->out, (unsigned)( VOID(icmp+1) - VOID t->out->data +
				     sizeof(struct iphdr) + 8));

    IP_ECHO_START:
	/* i decree that this handler can't have an upper handler! */
	icmp->checksum = 0;
	icmp->checksum = csum_fold(csum_partial((unsigned char *)icmp,
				       (unsigned)( VOID t->out->tail - 
						   VOID icmp), 0));
    }

    t->add_timeout = update_state(tmp_i4, t->ct, t->dir, t->idx);
    return 0;
}

static int new(struct tn_proto *p)
{

    if (p == NULL) return -EINVAL;

    memset(p, 0, sizeof(struct tn_proto));
    strcpy(p->name, "icmp");
    p->states = 1;
    p->ismine = ismine;
    p->pkt_to_tuple = pkt_to_tuple;
    p->complete_tuple = complete_tuple;
    p->new_ctrack = generic_new_ctrack;
    p->translate = translate;
    p->tuple_cmp = tuple_cmp;
    p->max_data = sizeof(struct icmp_data);
    p->__mod = THIS_MODULE;

    return 0;
}

int __init napt_proto_icmp_init()
{
    /* temporary */
    if (napt_register_proto("icmp", new)) return -1;
    return napt_append_proto_tree(napt_find_proto_by_name(NULL, "ip"), "icmp");

    /* return napt_register_proto("icmp", new); */
}

void __exit napt_proto_icmp_exit()
{
    /* how does conntrack do that it can't be unloaded ? */
    napt_remove_proto_tree(NULL, "icmp");
    napt_unregister_proto("icmp");
}

module_init(napt_proto_icmp_init);
module_exit(napt_proto_icmp_exit);
