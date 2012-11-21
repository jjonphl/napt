#define __NAPT_MAIN_C__
#define __NAPT_NEEDS_SEND__
#include <linux/modversions.h>
#include "napt.h"
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <net/ip6_route.h>
#include <linux/kmod.h>
#include <linux/proc_fs.h>

static kmem_cache_t *napt_ctrack_cachep;
static rwlock_t ctrack_lock;
static struct list_head cthead;


/*****************************************************************
 * miscellaneous stuff
 *****************************************************************/


static inline void ctrack_get(struct tn_ctrack *ct)
{
    WRITE_LOCK(&ctrack_lock);
    atomic_inc(&ct->__refcnt);
    WRITE_UNLOCK(&ctrack_lock);
}

static inline void ctrack_put(struct tn_ctrack *ct)
{
    /* it is assumed that we are called with WRITE_LOCK */
    if (atomic_dec_and_test(&ct->__refcnt)) {
	del_timer(&ct->timeo); /* irrelevant if timer is still on or not */
	if (ct->list.next) list_del(LIST ct);
	napt_proto_reset_refcnt(ct->tuple.proto->hier, 
				ct->tuple.proto->states);
	kmem_cache_free(napt_ctrack_cachep, VOID ct);
	MOD_DEC_USE_COUNT;
    }
}

static void death_by_timeout(unsigned long d)
{
    struct tn_ctrack *ct = CTRACK d;
    WRITE_LOCK(&ctrack_lock);
    ctrack_put((struct tn_ctrack *)d);
    printk("napt: dying by timeout...\n");
    /* we need to get it out of the list even if there are
       still transactions using this. ctrack_put deletes it also 
       from the list after everybody stops using it */
    if (ct->list.next) list_del(LIST ct); 
    ct->list.next = ct->list.prev = NULL;
    WRITE_UNLOCK(&ctrack_lock);

}

void napt_clear_ctracks()
{
    struct tn_ctrack *ct;

    WRITE_LOCK(&ctrack_lock);
    while ((ct = CTRACK cthead.next) != CTRACK &cthead)
        ctrack_put(ct);
    WRITE_UNLOCK(&ctrack_lock);
}

/*****************************************************************
 * end of miscellaneous stuff
 *****************************************************************/

/*****************************************************************
 * core functions
 *****************************************************************/


int napt_new_ctrack(struct tn_tuple *t, struct tn_ctrack **ct, int dir)
{
    struct tn_proto *p = t->proto;
    int i, ret = 0;

    if (p->states > MAX_PROTO_NEST) return -EINVAL;

    *ct = CTRACK kmem_cache_alloc(napt_ctrack_cachep, GFP_ATOMIC);

    if (! (*ct)) { ret = -ENOMEM; goto NEWCTRACK_CTERR; }

    for (i = 0; i < p->states; i++)
	if ((ret = (p->hier)[i]->complete_tuple(t, dir, i))) 
	    goto NEWCTRACK_COMPERR;

    memset(*ct, 0, sizeof(struct tn_ctrack));
    init_timer(&((*ct)->timeo));
    (*ct)->timeo.data = (unsigned long)*ct;
    (*ct)->timeo.function = death_by_timeout;
    memcpy(&(*ct)->tuple, t, sizeof(struct tn_tuple));
    (*ct)->dir = dir;
    atomic_set(&((*ct)->__refcnt), 1); /* canceled by death_by_timeout */

    for (i = 0; i < p->states; i++) {
	if ((ret = (p->hier)[i]->new_ctrack(t, *ct, dir, i))) {
	    napt_proto_reset_refcnt(p->hier, i);
	    goto NEWCTRACK_COMPERR;
	}
	(*ct)->state[i] = ST_GROUND;
    }

    WRITE_LOCK(&ctrack_lock);
    list_add(LIST *ct, &cthead);
    atomic_inc(&(*ct)->__refcnt); /* canceled by translate */
    WRITE_UNLOCK(&ctrack_lock);

    MOD_INC_USE_COUNT;
    return ret;

 NEWCTRACK_COMPERR:
    kmem_cache_free(napt_ctrack_cachep, *ct);
    *ct = NULL;
 NEWCTRACK_CTERR:
    return ret;
}

static int tuple_cmp(const struct tn_ctrack *ct, const struct tn_tuple *t2, 
		     int dir)
{
    int i;
    const struct tn_tuple *t1 = &ct->tuple;
    struct tn_proto *p = t1->proto;

    if (t1->proto != t2->proto) return 0;

    for (i = 0; i < p->states; i++) {
	if (!(p->hier)[i]->tuple_cmp(t1, t2, dir, i))
	    return 0;
    }

    return 1;
}

struct tn_ctrack * napt_find_ctrack(const struct tn_tuple *t, int dir)
{
    struct tn_ctrack *ct;

    ct = LIST_FIND(&cthead, tuple_cmp, struct tn_ctrack *, t, dir);
    if (ct) ctrack_get(ct);
    return ct;
}

int napt_mk_tuple(const void *nlhdr, int hint, int dir, 
		  struct tn_tuple *tuple, int *sz)
{
    struct tn_proto *p;
    int i, ofs;

    if (nlhdr == NULL) return -EINVAL;
    p = napt_find_proto_by_pkt(nlhdr, hint, dir, tuple, sz);

    if (p == NULL) {
	return -EPROTONOSUPPORT;
    }

    tuple->proto = p;

    for (ofs = i = 0; i < p->states; i++) 
	if ((p->hier)[i]->pkt_to_tuple(nlhdr, tuple, &ofs, dir, i))
	    return -EFAULT;
    
    return 0;
}

int napt_translate(struct sk_buff *in, struct sk_buff **out, 
		   struct tn_ctrack *ct, int sz, int dir)
{
    struct tn_translate t;
    int ret = 0, hlen;
    struct dst_entry *dst = NULL;
    static struct in6_addr addr_any;

    WRITE_LOCK(&ctrack_lock);

    if (!ct || !in || !sz) {  
	if (ct) ctrack_put(ct); WRITE_UNLOCK(&ctrack_lock);return -EINVAL; 
    }
    

    t.pkt = in;
    t.ct = ct;
    t.dir = dir;
    t.idx = t.add_timeout = t.pkt_ofs = 0;

    if (*out) {
	t.pkt_ofs = sz;
	goto DONE_WITH_SKB;
    }

    /* route first, info is on the ctrack */
    if (dir == V4TOV6) {
	struct flowi fl;
	memset(&fl, sizeof(fl), 0);
	memset(&addr_any, 0, sizeof(addr_any));
	if (ct->dir == V4TOV6) 	fl.fl6_dst = &ct->tuple.v6addr[NAT_DEST];
	else fl.fl6_dst = &ct->tuple.v6addr[NAT_HOST];
	fl.fl6_src = &addr_any;
	dst = ip6_route_output(NULL, &fl);
	if (!dst || dst->error) {
	    ret = -EFAULT; goto NAPT_TRANSLATE_DONE;
	}
    } else if (dir == V6TOV4) {
	struct rt_key rk;
	struct rtable *rt;

	if (ct->dir == V6TOV4) 
	    rk.dst = (uint32_t)ct->tuple.v4addr[NAT_DEST];
	else rk.dst = (uint32_t)ct->tuple.v4addr[NAT_HOST];
	rk.tos = 0;
	rk.src = 0;
	rk.oif = 0;
	if (ip_route_output_key(&rt, &rk) || !rt) {
	    ret = -EFAULT; goto NAPT_TRANSLATE_DONE;
	}
	dst = &rt->u.dst;
    }

    /* create skbuff (better bigger than short) */
    hlen = (dst->dev->hard_header_len + 15) & ~15;
    *out = alloc_skb((sz+hlen+sizeof(struct frag_hdr)) * 1.2, GFP_ATOMIC);
    if (!*out) {  ret = -ENOMEM; goto NAPT_TRANSLATE_DONE; }
    (*out)->dst = dst;
    (*out)->priority = 0;
    skb_reserve(*out, hlen);

 DONE_WITH_SKB:
    t.out = *out;

    if (!((ct->tuple.proto->hier[0])->translate(&t))) {  /* success */
	/* translate() modifies ctracks (e.g. state), so WRITE_LOCK
	   is just right */
	mod_timer(&(ct->timeo), jiffies + t.add_timeout);
    } else { 
	kfree_skb(*out); dev_put(dst->dev);
	ret = -EFAULT; 
    }

 NAPT_TRANSLATE_DONE:
    ctrack_put(ct);
    WRITE_UNLOCK(&ctrack_lock);

    return ret;
}

/*****************************************************************
 * end of core functions
 *****************************************************************/

static unsigned int redirect_hook(unsigned int hook,
			      struct sk_buff **pskb,
			      const struct net_device *indev,
			      const struct net_device *outdev,
			      int (*okfn)(struct sk_buff *))
{
    struct iphdr *iph = (*pskb)->nh.iph;
    struct tn_tuple tuple;
    struct tn_ctrack *ct;
    struct sk_buff *skb = NULL;
    int sz = (*pskb)->len;

    if (iph->version == 4) {
	if (napt_mk_tuple(iph, (*pskb)->protocol, V4TOV6, &tuple, &sz)) {
	    /* not our problem if we can't make a tuple of it */
	    return NF_ACCEPT;
	}
        
	if (!(ct = napt_find_ctrack(&tuple, V4TOV6))) {
	    if (napt_new_ctrack(&tuple, &ct, V4TOV6)) {
		return NF_ACCEPT;
	    }
	}

	/* let translate() calculate (estimate) length of out header */
	if (napt_translate(*pskb, &skb, ct, sz, V4TOV6) == 0) {
	    my_ip6send(skb);
	    kfree_skb(*pskb);
	    return NF_STOLEN;
	}

    } else if (iph->version == 6) {
	struct ipv6hdr *ip6h = (*pskb)->nh.ipv6h;

	if (napt_mk_tuple(ip6h, (*pskb)->protocol, V6TOV4, &tuple, &sz)) {
	    return NF_ACCEPT;
	}

	if (!(ct = napt_find_ctrack(&tuple, V6TOV4))) {
	    if (napt_new_ctrack(&tuple, &ct, V6TOV4)) {
		return NF_ACCEPT;
	    }
	}


	if (napt_translate(*pskb, &skb, ct, sz, V6TOV4) == 0) {
	    my_ip4send(skb);
	    kfree_skb(*pskb);
	    return NF_STOLEN;
	}
    }

    return NF_ACCEPT;
}


static struct nf_hook_ops redir4 =
{ {NULL, NULL}, redirect_hook, PF_INET, NF_IP_PRE_ROUTING, 0 };

static struct nf_hook_ops redir6 =
{ {NULL, NULL}, redirect_hook, PF_INET6, NF_IP6_PRE_ROUTING, 0 };


/* proc_fs funcs, wala lang, para mukhang totoo hehehe */
#define PROCFILE "napt_ctracks"
static int proc_read(char *page, char **start,
                     off_t off, int count, 
                     int *eof, void *data)
{
    int len = 0, i;
    struct tn_ctrack *ct;
    struct tn_proto *p;

    for (ct = CTRACK cthead.next; ct != CTRACK &cthead; 
		    ct = CTRACK ct->list.next) {
	p = ct->tuple.proto;
	if (p == NULL) {
		printk("napt: p is null?\n");
		break;
	}
	len += sprintf(page+len, "ct: ");
	for (i = 0; i < p->states; i++) 
	    len += sprintf(page+len, "[%s] ", (p->hier)[i]->name);
	len += sprintf(page+len, "(expires:%lu)\n", ct->timeo.expires);
    }

    return len;
}

static struct proc_dir_entry *p;
static int init_or_fini(int init)
{

    if (!init) goto FINISH;

    /* ripped off from ip_conntrack_core's ip_conntrack_init() */

    napt_ctrack_cachep = kmem_cache_create("napt_ctracks",
					   sizeof(struct tn_ctrack),
					   0, SLAB_HWCACHE_ALIGN, NULL, NULL);
    if (!napt_ctrack_cachep) goto CTRACK_CACHE;

    if (nf_register_hook(&redir4)) goto REG_V4_HOOK;
    if (nf_register_hook(&redir6)) goto REG_V6_HOOK;
    if (!(p = create_proc_entry(PROCFILE, 0444, NULL))) goto REG_NO_PROC;
    p->owner = THIS_MODULE;
    p->read_proc = proc_read;
    p->write_proc = NULL;
    p->data = 0;

    INIT_LIST_HEAD(&cthead);
    rwlock_init(&ctrack_lock);

    return 0;

 FINISH:
    remove_proc_entry(PROCFILE, NULL);
 REG_NO_PROC:
   nf_unregister_hook(&redir6);
 REG_V6_HOOK:
    nf_unregister_hook(&redir4);
 REG_V4_HOOK:
    /* we won't be destroyed until there's a single conntrack
       alive */
    kmem_cache_destroy(napt_ctrack_cachep);
 CTRACK_CACHE:
    return -1;
}

int __init napt_init(void)
{
    return init_or_fini(1);
}

void __exit napt_finish()
{
    init_or_fini(0);
}

module_init(napt_init);
module_exit(napt_finish);

EXPORT_SYMBOL(napt_find_ctrack);
EXPORT_SYMBOL(napt_new_ctrack);
EXPORT_SYMBOL(napt_mk_tuple);
EXPORT_SYMBOL(napt_translate);
EXPORT_SYMBOL(napt_clear_ctracks);
