#define __NAPT_PROTO_C__
#include "napt.h"
#include <linux/proc_fs.h>

static struct protos_factory {
    char name[PROTONAME_MAX];
    int (*ctor)(struct tn_proto *);
} protos[MAX_PROTOS];


static kmem_cache_t *ptree_cache;
static rwlock_t  ptree_lock, pfact_lock;
static struct tn_proto *rootproto = NULL;

/*****************************************************************
 * misc 
 *****************************************************************/

static inline void mod_refcnt(struct tn_proto *p, int get)
{
    if (get) __MOD_INC_USE_COUNT(p->__mod);
    else __MOD_DEC_USE_COUNT(p->__mod);
}

void napt_proto_reset_refcnt(struct tn_proto **p, int cnt) 
{
    int i;
    /* i think we don't need locks here */

    for (i = 0; i < cnt; i++)
	mod_refcnt(p[i], 0);
}

/*****************************************************************
 * proto handler management functions
 *****************************************************************/

int napt_register_proto(char *name, int (*ctor)(struct tn_proto *))
{
    int i, idx = -ENOMEM;

    if (name == NULL || ctor == NULL) return -EINVAL;

    WRITE_LOCK(&pfact_lock);
    for (i = 0; i < MAX_PROTOS ; i++) {
	/* make sure unique name */
	if (strcmp(protos[i].name, name) == 0) return -EEXIST;
	/* find first free spot */
	else if (protos[i].name[0] == 0 && idx < 0) idx = i;
    }

    /* we found a free spot? */
    if (idx != -1) {
	strncpy(protos[idx].name, name, PROTONAME_MAX);
	protos[idx].ctor = ctor;
	idx = 0;
    }

    WRITE_UNLOCK(&pfact_lock);

    return idx;
}

int napt_unregister_proto(char *name)
{
    int i, ret = -ENOENT;
    if (name == NULL) return -EINVAL;

    WRITE_LOCK(&pfact_lock);
    for (i = 0; i < MAX_PROTOS; i++)
	if (strcmp(protos[i].name, name) == 0) {
	    protos[i].name[0] = 0;
	    ret = 0;
	    break;
	}
    WRITE_UNLOCK(&pfact_lock);

    return ret;
}


struct tn_proto *napt_find_proto_by_pkt(const void *nlhdr, int hint, int dir, 
					struct tn_tuple *tuple, int *size)
{
    int htemp, ofs = 0, ofstemp;
    struct list_head *l;
    struct tn_proto *p = rootproto, *p2;
    int sz = 0;

    READ_LOCK(&ptree_lock);

    while (p && !p->ismine(nlhdr, &hint, &ofs, dir, &sz)) {
	if (!p->child) goto FOUND_PROTO;
	l = LIST (p->child);
	ofstemp = ofs;

	htemp = hint;
	if (!p->child->ismine(nlhdr, &htemp, &ofstemp, dir, NULL)) p = p->child;
	else {
	    p2 = PROTO (l->next);
	    while(p2 != PROTO l) {
		ofstemp = ofs; htemp = hint;
		if (!p2->ismine(nlhdr, &htemp, &ofstemp, dir, NULL)) break;
		p2 = PROTO (LIST p2)->next;
	    }
	    p = p2;
	}
    }

    if (p) p = p->parent;

 FOUND_PROTO:
    READ_UNLOCK(&ptree_lock);

    /* here, *size have the size of the original input packet
       this means just copy the rest of the input packet
       after last protocol is finished with his part of the packet */
    if (size) *size = sz + (*size > ofs ? (*size - ofs) : 0);
    return p;
}

static struct tn_proto *fpbn(struct tn_proto *parent, const char *name)
{
    struct tn_proto *p, *ret = NULL;
    if (parent == NULL) return NULL;
    
    p = parent;

    if (!strcmp(p->name, name)) ret = p;
    else if ((ret = fpbn(p->child, name)) == NULL) {
	struct tn_proto *head = p;
	for (p = PROTO p->list.next; p != head; p = PROTO p->list.next) {
	    if (!strcmp(p->name, name)) { ret = p; break; }
	    if ((ret = fpbn(p->child, name)) != NULL) break;
		
	}
    }

    return ret;
}
    
struct tn_proto *napt_find_proto_by_name(struct tn_proto  *parent, 
					 const char *name)
{
    struct tn_proto *p;
    if (!name) return NULL;
    if (parent == NULL) parent = rootproto;

    READ_LOCK(&ptree_lock);
    p = fpbn(parent, name);
    READ_UNLOCK(&ptree_lock);
    return p;
}



static struct tn_proto *new_proto(const char *name)
{
    int i;
    struct tn_proto *p = NULL;
    struct protos_factory *f;

    READ_LOCK(&pfact_lock);
    WRITE_LOCK(&ptree_lock);
    for (i = 0; i < MAX_PROTOS; i++) {
	f = &protos[i];
	if (strcmp(f->name, name) == 0) {
	    p = kmem_cache_alloc(ptree_cache, GFP_ATOMIC);
	    break;
	}
    }

    if (p) {

	if (f->ctor && f->ctor(p)) {
	    kmem_cache_free(ptree_cache, VOID p);
	    p = NULL;
	}
    }
    WRITE_UNLOCK(&ptree_lock);
    READ_UNLOCK(&pfact_lock);
    return p;
}


/*
for encapsulation, the user will not have 
*/
int napt_append_proto_tree(struct tn_proto *parent, const char *name)
{
    struct tn_proto *p;

    if (name == NULL) {
	return -EINVAL;
    } else if (!(p = new_proto(name))) 
	return -EPROTONOSUPPORT;

    p->child = NULL;

    WRITE_LOCK(&ptree_lock);

    if (rootproto == NULL) {
	if (parent != NULL) return -ENOENT;

	rootproto = p; 
	p->list.next = p->list.prev = LIST p;
	p->states = 1;
	p->hier[0] = p;
	p->parent = NULL;

    } else {
	if (parent != NULL) {
	    if (parent->child == NULL) {
		p->list.next = p->list.prev = LIST p;
		parent->child = p;
	    } else {
		list_add(LIST p, LIST parent->child);
	    }
	    p->parent = parent;
	    p->states = parent->states + 1;
	    memcpy(p->hier, parent->hier, 
		   parent->states * sizeof(struct tn_proto *));
	    p->hier[parent->states] = p;
	    p->max_data += parent->max_data;
	    mod_refcnt(parent, 1);

	} else { /* proto peer of rootproto */
	    p->states = 1;
	    p->hier[0] = p;
	    p->parent = NULL;
	    list_add(LIST p, LIST rootproto);
	}
    
    }

    WRITE_UNLOCK(&ptree_lock);
    return 0;
}

int napt_remove_proto_tree(struct tn_proto *parent, const char *name)
{
    struct tn_proto *p = napt_find_proto_by_name(parent, name);
    int ret = 0;


    if (!name) return -EINVAL;

    if (p == NULL) {
	return -EINVAL;
    }

    WRITE_LOCK(&ptree_lock);
    if (p->child != NULL) { ret = -EFAULT; goto RPT_DONE; }
    if ((parent = p->parent)) {
	mod_refcnt(parent, 0);
        if (p->list.next != LIST p) {
	    parent->child = PROTO p->list.next;
	    list_del(LIST p);
        } else parent->child = NULL;
    } else { /* fix rootproto */
	if (rootproto == p) {
	    if (p->list.next != LIST p) {
		rootproto = PROTO p->list.next;
		list_del(LIST p);
	    } else rootproto = NULL;
	} else list_del(LIST p);
    }
    kmem_cache_free(ptree_cache, VOID p);

 RPT_DONE:
    WRITE_UNLOCK(&ptree_lock);
    return ret;
}

int generic_new_ctrack(const struct tn_tuple *t, struct tn_ctrack *ct,
				 int dir,int idx)
{
    mod_refcnt((t->proto->hier)[idx], 1);
    return 0;
}

void *find_ip6_hdr(const void *hdr, __u8 hdrcode, __u8 curhdr, __u8 isv6hdr)
{
    __u8 *nxt;

    if (isv6hdr) {
	struct ipv6hdr *ip6hdr = (struct ipv6hdr *)hdr;
	if (ip6hdr->nexthdr == hdrcode) return (void *)ip6hdr + 
					    sizeof(struct ipv6hdr);
	else {
	    nxt = (__u8 *)((void *)hdr + sizeof(struct ipv6hdr));
	    curhdr = ip6hdr->nexthdr;
	}
    } else nxt = (__u8 *)hdr;

    while ((curhdr != hdrcode) && (curhdr != IPPROTO_UDP && 
				   curhdr != IPPROTO_TCP &&
				   curhdr != IPPROTO_ICMPV6 &&
				   curhdr != IPPROTO_NONE)) {
	curhdr = *nxt;
	if (curhdr != NEXTHDR_FRAGMENT) { 
	    nxt += (nxt[1]+1) * 8;
	} else {
	    nxt += sizeof(struct frag_hdr);
	}
    }

    if (curhdr != hdrcode) nxt = NULL;

    return (void *)nxt;
}

/* proc fs */
static struct proc_dir_entry *p;
#define PROCFILE "napt_protos"

static void print_protos(char *s, struct tn_proto *p, int level, int *len)
{
    if (p) {
	struct tn_proto *p2;
	int i;
	for (i = *len; i < *len + (level*2); i++) s[i] = ' ';
	*len += level * 4;
	*len += sprintf(s+(*len),"|-> %s\n", p->name);
	print_protos(s, p->child, level+1, len);
	if (p != PROTO p->list.next) 
	    for (p2 = PROTO p->list.next; p2 != p; p2 = PROTO p2->list.next) {
		for (i = *len; i < *len + (level*2); i++) s[i] = ' ';
		*len += level * 2;
		*len += sprintf(s+(*len),"|-> %s\n", p2->name);
		print_protos(s, p2->child, level+1, len);
	    }
    }
}

static int proc_read(char *page, char **start,
                     off_t off, int count, 
                     int *eof, void *data)
{
    int len = 0;

    READ_LOCK(&ptree_lock);
    if (rootproto) {
	len = sprintf(page, "%s\n", rootproto->name);
	if (rootproto->child)
		print_protos(page, rootproto->child, 1, &len); 
    } else len = sprintf(page, "NONE.\n");
    READ_UNLOCK(&ptree_lock);

    return len;
}


/* end of proc fs */


int __init napt_proto_init()
{
    if (!(ptree_cache = kmem_cache_create("napt_protos",
					  sizeof(struct tn_proto),
					  0, SLAB_HWCACHE_ALIGN, NULL, NULL)))
	return -ENOMEM;
    rwlock_init(&ptree_lock);
    rwlock_init(&pfact_lock);

    if (!(p = create_proc_entry(PROCFILE, 0444, NULL))) goto REG_NO_PROC;
    p->owner = THIS_MODULE;
    p->read_proc = proc_read;
    p->write_proc = NULL;
    p->data = 0;

 REG_NO_PROC:
    return 0;
}

void __exit napt_proto_finish()
{
    if (p) remove_proc_entry(PROCFILE, NULL);
    kmem_cache_destroy(ptree_cache);
}
/*****************************************************************
 * end of proto handler management functions
 *****************************************************************/

module_init(napt_proto_init);
module_exit(napt_proto_finish);

EXPORT_SYMBOL(napt_find_proto_by_pkt);
EXPORT_SYMBOL(napt_find_proto_by_name);
EXPORT_SYMBOL(napt_append_proto_tree);
EXPORT_SYMBOL(napt_remove_proto_tree);
EXPORT_SYMBOL(napt_register_proto);
EXPORT_SYMBOL(napt_unregister_proto);
EXPORT_SYMBOL(generic_new_ctrack);
EXPORT_SYMBOL(find_ip6_hdr);
EXPORT_SYMBOL(napt_proto_reset_refcnt);
