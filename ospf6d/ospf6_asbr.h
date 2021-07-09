/*
 * Copyright (C) 2001 Yasuhiro Ohara
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef OSPF6_ASBR_H
#define OSPF6_ASBR_H

/* for struct ospf6_prefix */
#include "ospf6_proto.h"
/* for struct ospf6_lsa */
#include "ospf6_lsa.h"
/* for struct ospf6_route */
#include "ospf6_route.h"

/* Debug option */
extern unsigned char conf_debug_ospf6_asbr;
#define OSPF6_DEBUG_ASBR_ON() (conf_debug_ospf6_asbr = 1)
#define OSPF6_DEBUG_ASBR_OFF() (conf_debug_ospf6_asbr = 0)
#define IS_OSPF6_DEBUG_ASBR (conf_debug_ospf6_asbr)

struct ospf6_external_info {
	/* External route type */
	int type;

	/* Originating Link State ID */
	uint32_t id;

	struct in6_addr forwarding;

	route_tag_t tag;

	ifindex_t ifindex;

};

/* OSPF6 ASBR Summarisation */
typedef enum {
	OSPF6_ROUTE_AGGR_NONE = 0,
	OSPF6_ROUTE_AGGR_ADD,
	OSPF6_ROUTE_AGGR_DEL,
	OSPF6_ROUTE_AGGR_MODIFY
} ospf6_aggr_action_t;

#define OSPF6_EXTERNAL_AGGRT_NO_ADVERTISE 0x1
#define OSPF6_EXTERNAL_AGGRT_ORIGINATED 0x2

#define OSPF6_EXTERNAL_RT_COUNT(aggr)    \
	(((struct ospf6_external_aggr_rt *)aggr)->match_extnl_hash->count)

struct ospf6_external_aggr_rt {
	/* range address and masklen */
	struct prefix p;

	/* use bits for OSPF6_EXTERNAL_AGGRT_NO_ADVERTISE and
	 * OSPF6_EXTERNAL_AGGRT_ORIGINATED
	 */
	uint16_t aggrflags;

	/* To store external metric-type */
	uint8_t mtype;

	/* Route tag for summary address */
	route_tag_t tag;

	/* To store aggregated metric config */
	int metric;

	/* To Store the LS ID when LSA is originated */
	uint32_t id;

	/* Action to be done after delay timer expiry */
	int action;

	/* Hash table of matching external routes */
	struct hash *match_extnl_hash;
};

/* AS-External-LSA */
#define OSPF6_AS_EXTERNAL_LSA_MIN_SIZE         4U /* w/o IPv6 prefix */
struct ospf6_as_external_lsa {
	uint32_t bits_metric;

	struct ospf6_prefix prefix;
	/* followed by none or one forwarding address */
	/* followed by none or one external route tag */
	/* followed by none or one referenced LS-ID */
};

#define OSPF6_ASBR_BIT_T  ntohl (0x01000000)
#define OSPF6_ASBR_BIT_F  ntohl (0x02000000)
#define OSPF6_ASBR_BIT_E  ntohl (0x04000000)

#define OSPF6_ASBR_METRIC(E) (ntohl ((E)->bits_metric & htonl (0x00ffffff)))
#define OSPF6_ASBR_METRIC_SET(E, C)                                            \
	{                                                                      \
		(E)->bits_metric &= htonl(0xff000000);                         \
		(E)->bits_metric |= htonl(0x00ffffff) & htonl(C);              \
	}

extern void ospf6_asbr_lsa_add(struct ospf6_lsa *lsa);

extern void ospf6_asbr_lsa_remove(struct ospf6_lsa *lsa,
				  struct ospf6_route *asbr_entry);
extern void ospf6_asbr_lsentry_add(struct ospf6_route *asbr_entry,
				   struct ospf6 *ospf6);
extern void ospf6_asbr_lsentry_remove(struct ospf6_route *asbr_entry,
				      struct ospf6 *ospf6);

extern int ospf6_asbr_is_asbr(struct ospf6 *o);
extern void ospf6_asbr_redistribute_add(int type, ifindex_t ifindex,
					struct prefix *prefix,
					unsigned int nexthop_num,
					struct in6_addr *nexthop,
					route_tag_t tag, struct ospf6 *ospf6);
extern void ospf6_asbr_redistribute_remove(int type, ifindex_t ifindex,
					   struct prefix *prefix,
					   struct ospf6 *ospf6);

extern int ospf6_redistribute_config_write(struct vty *vty,
					   struct ospf6 *ospf6);

extern void ospf6_asbr_init(void);
extern void ospf6_asbr_redistribute_disable(struct ospf6 *ospf6);
extern void ospf6_asbr_redistribute_reset(struct ospf6 *ospf6);
extern void ospf6_asbr_terminate(void);
extern void ospf6_asbr_send_externals_to_area(struct ospf6_area *);
extern void ospf6_asbr_remove_externals_from_area(struct ospf6_area *oa);

extern int config_write_ospf6_debug_asbr(struct vty *vty);
extern int ospf6_distribute_config_write(struct vty *vty, struct ospf6 *ospf6);
extern void install_element_ospf6_debug_asbr(void);
extern void ospf6_asbr_update_route_ecmp_path(struct ospf6_route *old,
					      struct ospf6_route *route,
					      struct ospf6 *ospf6);
extern void ospf6_asbr_distribute_list_update(struct ospf6 *ospf6,
					      struct ospf6_redist *red);
struct ospf6_redist *ospf6_redist_lookup(struct ospf6 *ospf6, int type,
					 unsigned short instance);
extern void ospf6_asbr_routemap_update(const char *mapname);
extern struct ospf6_lsa *
ospf6_as_external_lsa_originate(struct ospf6_route *route,
				struct ospf6 *ospf6);
extern void ospf6_asbr_status_update(struct ospf6 *ospf6, int status);

int ospf6_asbr_external_rt_advertise(struct ospf6 *ospf6,
				     struct prefix *p);
int ospf6_external_aggr_delay_timer_set(struct ospf6 *ospf6,
					unsigned int interval);
int ospf6_asbr_external_rt_no_advertise(struct ospf6 *ospf6,
						struct prefix *p);

struct ospf6_external_aggr_rt *
ospf6_external_aggr_config_lookup(struct ospf6 *ospf6, struct prefix *p);

int ospf6_external_aggr_config_set(struct ospf6 *ospf6, struct prefix *p,
				   route_tag_t tag, int metric, int mtype);

int ospf6_external_aggr_config_unset(struct ospf6 *ospf6,
					struct prefix *p);
void ospf6_handle_external_lsa_origination(struct ospf6 *ospf6,
					       struct ospf6_route *rt,
					       struct prefix *p);
void ospf6_external_aggregator_free(struct ospf6_external_aggr_rt *aggr);
void ospf6_unset_all_aggr_flag(struct ospf6 *ospf6);
void ospf6_fill_aggr_route_details(struct ospf6 *ospf6,
					  struct ospf6_external_info *ei_aggr,
					  struct ospf6_route *rt_aggr,
					  struct ospf6_external_aggr_rt *aggr);
#endif /* OSPF6_ASBR_H */
