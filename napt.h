#ifndef __NAPT_H__
#define __NAPT_H__

#include <linux/config.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <asm/uaccess.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <net/ipv6.h>
#include <net/icmp.h>   /* for icmp_send */
#include <linux/icmpv6.h> /* for icmpv6_send */
#include <net/checksum.h>
#include <asm/checksum.h>

/* all these for LIST_FIND, !@#$!$@#$! */
#define ASSERT_READ_LOCK(x)
#define ASSERT_WRITE_LOCK(x)
#include <linux/netfilter_ipv4/lockhelp.h>
#include <linux/netfilter_ipv4/listhelp.h>


/* constants */
#define MAX_TUPLE_DATA   128
#define MAX_PROTO_NEST   7
#define PROTONAME_MAX    11
#define MAX_PROTOS       10

#define V4TOV6 0
#define V6TOV4 1

/* possible states */
#define ST_GROUND  0 /* ground state */
#define ST_ORIGDIR 1
#define ST_REPLIED 2

/* casts */
#define CTRACK   (struct tn_ctrack *)
#define PROTO    (struct tn_proto *)
#define VOID     (void *)
#define LIST     (struct list_head *)

/* ip6 fragment header masks */
#define IP6_MF      0x0001
#define IP6_RES     0x0006
#define IP6_OFFSET  0xFFF8

/* time units, ripped off from ip_conntrack_proto_tcp.c */
#define SECS *HZ
#define MINS * 60 SECS
#define HOURS * 60 MINS
#define DAYS * 24 HOURS

/* for v4/v6 array index */
#define NAT_HOST 0
#define NAT_DEST 1

/* wala lang */
#define READ_LOCK(x)       read_lock_irq(x)
#define READ_UNLOCK(x)     read_unlock_irq(x)
#define WRITE_LOCK(x)      write_lock_irq(x)
#define WRITE_UNLOCK(x)    write_unlock_irq(x)


typedef union {
    int i;
    struct { __u8 type, code; } icmp;
} icmp_hint;

struct tn_translate {
    struct sk_buff *pkt, *out;
    struct tn_ctrack *ct;
    unsigned short pkt_ofs,
	add_timeout, dir, idx;
};

struct tn_proto;

struct tn_tuple {
    u_int32_t v4addr[2];
    struct in6_addr v6addr[2];
    struct tn_proto *proto;
    char data[MAX_TUPLE_DATA]; /* this is the start of extra data */
};

struct tn_ctrack {
    struct list_head list;
    struct tn_tuple tuple;
    __u8 state[MAX_PROTO_NEST];
    __u8 dir;
    struct timer_list timeo;
    int size; /* save space */
    atomic_t __refcnt;
};

struct tn_proto {
    struct list_head list;
    struct tn_proto *hier[MAX_PROTO_NEST];
    struct tn_proto *parent, *child;
    struct module *__mod;

    char name[PROTONAME_MAX];
    __u16 max_data, states;

    /* update state is now internal to proto module */

    int (*ismine)(const void *hdr, int *hint, int *ofs, int dir, int *size);

    int (*pkt_to_tuple)(const void *hdr, struct tn_tuple *t,
			int *ofs, int dir, int idx);

    int (*complete_tuple)(struct tn_tuple *t, int dir, int idx);

    int (*new_ctrack)(const struct tn_tuple *t, struct tn_ctrack *ct,
		      int dir, int idx);

    int (*tuple_cmp)(const struct tn_tuple *t1, const struct tn_tuple *t2, 
		     int dir, int idx);

    int (*translate)(struct tn_translate *t);

};


/* extra structs we are not provided */
struct ip_option {
    __u8 type;
    __u8 length;
    __u8 *data;
};

int generic_new_ctrack(const struct tn_tuple *t, struct tn_ctrack *ct,
		       int dir,int idx);


/* function prototypes */

#ifndef __NAPT_MAIN_C__
extern struct tn_ctrack *napt_find_ctrack(const struct tn_tuple *t, int dir);

extern int napt_new_ctrack(struct tn_tuple *t, struct tn_ctrack **ct, 
			   int dir);

extern int napt_mk_tuple(const void *nlhdr, int hint, int dir, 
			 struct tn_tuple *t, int *sz);

extern int napt_translate(struct sk_buff *in, struct sk_buff **out, 
			  struct tn_ctrack *ct, int sz, int dir);
#endif


/* breadth first search of proto for those recognizing this packet */
struct tn_proto *napt_find_proto_by_pkt(const void *nlhdr, int hint, int dir, 
				   struct tn_tuple *tuple, int *sz);

/* depth first search in the tree */
struct tn_proto *napt_find_proto_by_name(struct tn_proto *parent, 
					 const char *name);

/* int register_proto(char *parent, struct tn_proto *tn); */
int napt_append_proto_tree(struct tn_proto *parent, const char *name);

int napt_remove_proto_tree(struct tn_proto *parent, const char *name);

int napt_register_proto(char *name, int (*ctor)(struct tn_proto *));

int napt_unregister_proto(char *name);

void napt_proto_reset_refcnt(struct tn_proto **p, int cnt);

/* misc: */
void napt_clear_ctracks();

/* find an equivalent of this !! */
void *find_ip6_hdr(const void *hdr, __u8 hdrcode, __u8 curhdr, __u8 isv6hdr);

#ifdef __NAPT_NEEDS_SEND__
/* these just sends, doesn't route or anything */
static inline void my_ip4send(struct sk_buff *skb)
{
    ip_send(skb);
}

static inline void my_ip6send(struct sk_buff *skb)
{
    struct neighbour *neigh = skb->dst->neighbour;
    int err;
    if (!neigh) return;
    skb->protocol = ntohs(ETH_P_IPV6);
    skb->dev = skb->dst->dev;

    write_lock_bh(&neigh->lock);
    neigh->used = jiffies;
    err = skb->dev->hard_header(skb, skb->dev, 
			   ntohs(skb->protocol), neigh->ha, NULL, skb->len);
    write_unlock_bh(&neigh->lock);
    if (err >= 0) neigh->ops->queue_xmit(skb);
    else { printk("napt: no hard header!\n"); kfree_skb(skb); }

    /* skb->dst->output(skb); */
}
#endif

/* i stole this somewhere i forgot */
#define NIP6(addr) \
	ntohs((addr).s6_addr16[0]), \
	ntohs((addr).s6_addr16[1]), \
	ntohs((addr).s6_addr16[2]), \
	ntohs((addr).s6_addr16[3]), \
	ntohs((addr).s6_addr16[4]), \
	ntohs((addr).s6_addr16[5]), \
	ntohs((addr).s6_addr16[6]), \
	ntohs((addr).s6_addr16[7])


/* for userspace! (sana) */
#define AF_NAPT     30
#define PF_NAPT     AF_NAPT

/* todo:
  1. create a struct net_proto_family struct
     (napt_sock_create);
  2. do sock_register();

 */
#endif
