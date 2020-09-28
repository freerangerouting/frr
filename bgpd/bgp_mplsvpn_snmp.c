/* MPLS/BGP L3VPN MIB
 * Copyright (C) 2020 Volta Networks Inc
 *
 * This file is part of FRR.
 *
 * FRRouting is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRRouting is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include "if.h"
#include "log.h"
#include "prefix.h"
#include "command.h"
#include "thread.h"
#include "smux.h"
#include "filter.h"
#include "hook.h"
#include "libfrr.h"
#include "version.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_mplsvpn_snmp.h"

#define BGP_mplsvpn_notif_enable_true 1
#define BGP_mplsvpn_notif_enable_false 2

/* MPLSL3VPN MIB described in RFC4382 */
#define MPLSL3VPNMIB 1, 3, 6, 1, 2, 1, 10, 166, 11

/* MPLSL3VPN Scalars */
#define MPLSL3VPNCONFIGUREDVRFS 1
#define MPLSL3VPNACTIVEVRFS 2
#define MPLSL3VPNCONNECTEDINTERFACES 3
#define MPLSL3VPNNOTIFICATIONENABLE 4
#define MPLSL3VPNCONFMAXPOSSRTS 5
#define MPLSL3VPNVRFCONFRTEMXTHRSHTIME 6
#define MPLSL3VPNILLLBLRCVTHRSH 7

/* MPLSL3VPN VRF Table */
#define MPLSL3VPNVRFVPNID 1
#define MPLSL3VPNVRFDESC 2
#define MPLSL3VPNVRFRD 3
#define MPLSL3VPNVRFCREATIONTIME 4
#define MPLSL3VPNVRFOPERSTATUS 5
#define MPLSL3VPNVRFACTIVEINTERFACES 6
#define MPLSL3VPNVRFASSOCIATEDINTERFACES 7
#define MPLSL3VPNVRFCONFMIDRTETHRESH 8
#define MPLSL3VPNVRFCONFHIGHRTETHRSH 9
#define MPLSL3VPNVRFCONFMAXROUTES 10
#define MPLSL3VPNVRFCONFLASTCHANGED 11
#define MPLSL3VPNVRFCONFROWSTATUS 12
#define MPLSL3VPNVRFCONFADMINSTATUS 13
#define MPLSL3VPNVRFCONFSTORAGETYPE 14

/* SNMP value hack. */
#define INTEGER ASN_INTEGER
#define INTEGER32 ASN_INTEGER
#define COUNTER32 ASN_COUNTER
#define OCTET_STRING ASN_OCTET_STR
#define IPADDRESS ASN_IPADDRESS
#define GAUGE32 ASN_UNSIGNED
#define TIMETICKS ASN_TIMETICKS

/* Declare static local variables for convenience. */
SNMP_LOCAL_VARIABLES

/* BGP-MPLS-MIB innstances */
static oid mpls_l3vpn_oid[] = {MPLSL3VPNMIB};
static char rd_buf[RD_ADDRSTRLEN];
static uint8_t bgp_mplsvpn_notif_enable = SNMP_FALSE;

static uint8_t *mplsL3vpnConfiguredVrfs(struct variable *, oid[], size_t *, int,
					size_t *, WriteMethod **);

static uint8_t *mplsL3vpnActiveVrfs(struct variable *, oid[], size_t *, int,
				    size_t *, WriteMethod **);

static uint8_t *mplsL3vpnConnectedInterfaces(struct variable *, oid[], size_t *,
					     int, size_t *, WriteMethod **);

static uint8_t *mplsL3vpnNotificationEnable(struct variable *, oid[], size_t *,
					    int, size_t *, WriteMethod **);

static uint8_t *mplsL3vpnVrfConfMaxPossRts(struct variable *, oid[], size_t *,
					   int, size_t *, WriteMethod **);

static uint8_t *mplsL3vpnVrfConfRteMxThrshTime(struct variable *, oid[],
					       size_t *, int, size_t *,
					       WriteMethod **);

static uint8_t *mplsL3vpnIllLblRcvThrsh(struct variable *, oid[], size_t *, int,
					size_t *, WriteMethod **);

static uint8_t *mplsL3vpnVrfTable(struct variable *, oid[], size_t *, int,
				  size_t *, WriteMethod **);


static struct variable mpls_l3vpn_variables[] = {
	/* BGP version. */
	{MPLSL3VPNCONFIGUREDVRFS,
	 GAUGE32,
	 RONLY,
	 mplsL3vpnConfiguredVrfs,
	 3,
	 {1, 1, 1} },
	{MPLSL3VPNACTIVEVRFS,
	 GAUGE32,
	 RONLY,
	 mplsL3vpnActiveVrfs,
	 3,
	 {1, 1, 2} },
	{MPLSL3VPNCONNECTEDINTERFACES,
	 GAUGE32,
	 RONLY,
	 mplsL3vpnConnectedInterfaces,
	 3,
	 {1, 1, 3} },
	{MPLSL3VPNNOTIFICATIONENABLE,
	 INTEGER,
	 RWRITE,
	 mplsL3vpnNotificationEnable,
	 3,
	 {1, 1, 4} },
	{MPLSL3VPNCONFMAXPOSSRTS,
	 GAUGE32,
	 RONLY,
	 mplsL3vpnVrfConfMaxPossRts,
	 3,
	 {1, 1, 5} },
	{MPLSL3VPNVRFCONFRTEMXTHRSHTIME,
	 GAUGE32,
	 RONLY,
	 mplsL3vpnVrfConfRteMxThrshTime,
	 3,
	 {1, 1, 6} },
	{MPLSL3VPNILLLBLRCVTHRSH,
	 GAUGE32,
	 RONLY,
	 mplsL3vpnIllLblRcvThrsh,
	 3,
	 {1, 1, 7} },

	/* Vrf Table */
	{MPLSL3VPNVRFVPNID,
	 OCTET_STRING,
	 RONLY,
	 mplsL3vpnVrfTable,
	 5,
	 {1, 2, 2, 1, 2} },
	{MPLSL3VPNVRFDESC,
	 OCTET_STRING,
	 RONLY,
	 mplsL3vpnVrfTable,
	 5,
	 {1, 2, 2, 1, 3} },
	{MPLSL3VPNVRFRD,
	 OCTET_STRING,
	 RONLY,
	 mplsL3vpnVrfTable,
	 5,
	 {1, 2, 2, 1, 4} },
	{MPLSL3VPNVRFCREATIONTIME,
	 TIMETICKS,
	 RONLY,
	 mplsL3vpnVrfTable,
	 5,
	 {1, 2, 2, 1, 5} },
	{MPLSL3VPNVRFOPERSTATUS,
	 INTEGER,
	 RONLY,
	 mplsL3vpnVrfTable,
	 5,
	 {1, 2, 2, 1, 6} },
	{MPLSL3VPNVRFACTIVEINTERFACES,
	 GAUGE32,
	 RONLY,
	 mplsL3vpnVrfTable,
	 5,
	 {1, 2, 2, 1, 7} },
	{MPLSL3VPNVRFASSOCIATEDINTERFACES,
	 GAUGE32,
	 RONLY,
	 mplsL3vpnVrfTable,
	 5,
	 {1, 2, 2, 1, 8} },
	{MPLSL3VPNVRFCONFMIDRTETHRESH,
	 GAUGE32,
	 RONLY,
	 mplsL3vpnVrfTable,
	 5,
	 {1, 2, 2, 1, 9} },
	{MPLSL3VPNVRFCONFHIGHRTETHRSH,
	 GAUGE32,
	 RONLY,
	 mplsL3vpnVrfTable,
	 5,
	 {1, 2, 2, 1, 10} },
	{MPLSL3VPNVRFCONFMAXROUTES,
	 GAUGE32,
	 RONLY,
	 mplsL3vpnVrfTable,
	 5,
	 {1, 2, 2, 1, 11} },
	{MPLSL3VPNVRFCONFLASTCHANGED,
	 TIMETICKS,
	 RONLY,
	 mplsL3vpnVrfTable,
	 5,
	 {1, 2, 2, 1, 12} },
	{MPLSL3VPNVRFCONFROWSTATUS,
	 INTEGER,
	 RONLY,
	 mplsL3vpnVrfTable,
	 5,
	 {1, 2, 2, 1, 13} },
	{MPLSL3VPNVRFCONFADMINSTATUS,
	 INTEGER,
	 RONLY,
	 mplsL3vpnVrfTable,
	 5,
	 {1, 2, 2, 1, 14} },
	{MPLSL3VPNVRFCONFSTORAGETYPE,
	 INTEGER,
	 RONLY,
	 mplsL3vpnVrfTable,
	 5,
	 {1, 2, 2, 1, 15} },
};

/* timeticks are in hundredths of a second */
static void bgp_mpls_l3vpn_update_timeticks(time_t *counter)
{
	struct timeval tv;

	monotime(&tv);
	*counter = (tv.tv_sec * 100) + (tv.tv_usec / 10000);
}

static int bgp_mpls_l3vpn_update_last_changed(struct bgp *bgp)
{
	if (bgp->snmp_stats)
		bgp_mpls_l3vpn_update_timeticks(
			&(bgp->snmp_stats->modify_time));
	return 0;
}

static int bgp_init_snmp_stats(struct bgp *bgp)
{
	if (is_bgp_vrf_mplsvpn(bgp)) {
		if (bgp->snmp_stats == NULL) {
			bgp->snmp_stats = XCALLOC(
				MTYPE_BGP, sizeof(struct bgp_snmp_stats));
			/* fix up added routes */
			if (bgp->snmp_stats)
				bgp_mpls_l3vpn_update_timeticks(
					&(bgp->snmp_stats->creation_time));
		}
	} else {
		if (bgp->snmp_stats) {
			XFREE(MTYPE_BGP, bgp->snmp_stats);
			bgp->snmp_stats = NULL;
		}
	}
	/* Something changed - update the timestamp */
	bgp_mpls_l3vpn_update_last_changed(bgp);
	return 0;
}

static bool is_bgp_vrf_active(struct bgp *bgp)
{
	struct vrf *vrf;
	struct interface *ifp;

	/* if there is one interface in the vrf which is up then it is deemed
	 *  active
	 */
	vrf = vrf_lookup_by_id(bgp->vrf_id);
	if (vrf == NULL)
		return false;
	RB_FOREACH (ifp, if_name_head, &vrf->ifaces_by_name) {
		/* if we are in a vrf skip the l3mdev */
		if (bgp->name && strncmp(ifp->name, bgp->name, VRF_NAMSIZ) == 0)
			continue;

		if (if_is_up(ifp))
			return true;
	}
	return false;
}

static int bgp_vrf_check_update_active(struct bgp *bgp, struct interface *ifp)
{
	bool new_active = false;

	if (!is_bgp_vrf_mplsvpn(bgp) || bgp->snmp_stats == NULL)
		return 0;
	new_active = is_bgp_vrf_active(bgp);
	if (bgp->snmp_stats->active != new_active) {
		/* add trap in here */
		bgp->snmp_stats->active = new_active;
	}
	return 0;
}

static uint8_t *mplsL3vpnConfiguredVrfs(struct variable *v, oid name[],
					size_t *length, int exact,
					size_t *var_len,
					WriteMethod **write_method)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	uint32_t count = 0;

	if (smux_header_generic(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		if (is_bgp_vrf_mplsvpn(bgp))
			count++;
	}
	return SNMP_INTEGER(count);
}

static uint8_t *mplsL3vpnActiveVrfs(struct variable *v, oid name[],
				    size_t *length, int exact, size_t *var_len,
				    WriteMethod **write_method)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	uint32_t count = 0;

	if (smux_header_generic(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		if (is_bgp_vrf_mplsvpn(bgp) && is_bgp_vrf_active(bgp))
			count++;
	}
	return SNMP_INTEGER(count);
}

static uint8_t *mplsL3vpnConnectedInterfaces(struct variable *v, oid name[],
					     size_t *length, int exact,
					     size_t *var_len,
					     WriteMethod **write_method)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	uint32_t count = 0;
	struct vrf *vrf;

	if (smux_header_generic(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		if (is_bgp_vrf_mplsvpn(bgp)) {
			vrf = vrf_lookup_by_name(bgp->name);
			if (vrf == NULL)
				continue;

			count += vrf_interface_count(vrf);
		}
	}

	return SNMP_INTEGER(count);
}

static int write_mplsL3vpnNotificationEnable(int action, uint8_t *var_val,
					     uint8_t var_val_type,
					     size_t var_val_len, uint8_t *statP,
					     oid *name, size_t length)
{
	uint32_t intval;

	if (var_val_type != ASN_INTEGER) {
		return SNMP_ERR_WRONGTYPE;
	}

	if (var_val_len != sizeof(long)) {
		return SNMP_ERR_WRONGLENGTH;
	}

	intval = *(long *)var_val;
	bgp_mplsvpn_notif_enable = intval;
	return SNMP_ERR_NOERROR;
}

static uint8_t *mplsL3vpnNotificationEnable(struct variable *v, oid name[],
					    size_t *length, int exact,
					    size_t *var_len,
					    WriteMethod **write_method)
{
	if (smux_header_generic(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	*write_method = write_mplsL3vpnNotificationEnable;
	return SNMP_INTEGER(bgp_mplsvpn_notif_enable);
}

static uint8_t *mplsL3vpnVrfConfMaxPossRts(struct variable *v, oid name[],
					   size_t *length, int exact,
					   size_t *var_len,
					   WriteMethod **write_method)
{
	if (smux_header_generic(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	return SNMP_INTEGER(0);
}

static uint8_t *mplsL3vpnVrfConfRteMxThrshTime(struct variable *v, oid name[],
					       size_t *length, int exact,
					       size_t *var_len,
					       WriteMethod **write_method)
{
	if (smux_header_generic(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	return SNMP_INTEGER(0);
}

static uint8_t *mplsL3vpnIllLblRcvThrsh(struct variable *v, oid name[],
					size_t *length, int exact,
					size_t *var_len,
					WriteMethod **write_method)
{
	if (smux_header_generic(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	return SNMP_INTEGER(0);
}


/* 1.3.6.1.2.1.10.166.11.1.2.2.1.x = 14*/
#define VRFTAB_NAMELEN 14

static struct bgp *bgp_lookup_by_name_next(const char *vrf_name)
{
	struct bgp *bgp, *bgp_next = NULL;
	struct listnode *node, *nnode;
	bool first = false;

	/*
	 * the vrfs are not stored alphabetically but since we are using the
	 * vrf name as an index we need the getnext function to return them
	 * in a atrict order. Thus run through and find the best next one.
	 */
	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		if (!is_bgp_vrf_mplsvpn(bgp))
			continue;
		if (strnlen(vrf_name, VRF_NAMSIZ) == 0 && bgp_next == NULL) {
			first = true;
			bgp_next = bgp;
			continue;
		}
		if (first || strncmp(bgp->name, vrf_name, VRF_NAMSIZ) > 0) {
			if (bgp_next == NULL)
				bgp_next = bgp;
			else if (strncmp(bgp->name, bgp_next->name, VRF_NAMSIZ)
				 < 0)
				bgp_next = bgp;
		}
	}
	return bgp_next;
}

static struct bgp *bgpL3vpnTable_lookup(struct variable *v, oid name[],
					size_t *length, char *vrf_name,
					int exact)
{
	struct bgp *bgp = NULL;
	size_t namelen = v ? v->namelen : VRFTAB_NAMELEN;
	int len;

	if (*length - namelen > VRF_NAMSIZ)
		return NULL;
	oid2string(name + namelen, *length - namelen, vrf_name);
	if (exact) {
		/* Check the length. */
		bgp = bgp_lookup_by_name(vrf_name);
		if (bgp && !is_bgp_vrf_mplsvpn(bgp))
			return NULL;
	} else {
		bgp = bgp_lookup_by_name_next(vrf_name);

		if (bgp == NULL)
			return NULL;

		len = strnlen(bgp->name, VRF_NAMSIZ);
		oid_copy_str(name + namelen, bgp->name, len);
		*length = len + namelen;
	}
	return bgp;
}

static uint8_t *mplsL3vpnVrfTable(struct variable *v, oid name[],
				  size_t *length, int exact, size_t *var_len,
				  WriteMethod **write_method)
{
	char vrf_name[VRF_NAMSIZ];
	struct bgp *l3vpn_bgp;

	if (smux_header_table(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	memset(vrf_name, 0, VRF_NAMSIZ);
	l3vpn_bgp = bgpL3vpnTable_lookup(v, name, length, vrf_name, exact);

	if (!l3vpn_bgp)
		return NULL;

	switch (v->magic) {
	case MPLSL3VPNVRFVPNID:
		*var_len = 0;
		return NULL;
	case MPLSL3VPNVRFDESC:
		*var_len = strnlen(l3vpn_bgp->name, VRF_NAMSIZ);
		return (uint8_t *)l3vpn_bgp->name;
	case MPLSL3VPNVRFRD:
		/*
		 * this is a horror show but the MIB dicates one RD per vrf
		 * and not one RD per AFI as we (FRR) have. So this little gem
		 * returns the V4 one if it's set OR the v6 one if it's set or
		 * zero-length string id neither are set
		 */
		memset(rd_buf, 0, RD_ADDRSTRLEN);
		if (CHECK_FLAG(l3vpn_bgp->vpn_policy[AFI_IP].flags,
			       BGP_VPN_POLICY_TOVPN_RD_SET))
			prefix_rd2str(&l3vpn_bgp->vpn_policy[AFI_IP].tovpn_rd,
				      rd_buf, sizeof(rd_buf));
		else if (CHECK_FLAG(l3vpn_bgp->vpn_policy[AFI_IP6].flags,
				    BGP_VPN_POLICY_TOVPN_RD_SET))
			prefix_rd2str(&l3vpn_bgp->vpn_policy[AFI_IP6].tovpn_rd,
				      rd_buf, sizeof(rd_buf));

		*var_len = strnlen(rd_buf, RD_ADDRSTRLEN);
		return (uint8_t *)rd_buf;
	case MPLSL3VPNVRFCREATIONTIME:
		return SNMP_INTEGER(
			(uint32_t)l3vpn_bgp->snmp_stats->creation_time);
	case MPLSL3VPNVRFOPERSTATUS:
		if (l3vpn_bgp->snmp_stats->active)
			return SNMP_INTEGER(1);
		else
			return SNMP_INTEGER(2);
	case MPLSL3VPNVRFACTIVEINTERFACES:
		return SNMP_INTEGER(bgp_vrf_interfaces(l3vpn_bgp, true));
	case MPLSL3VPNVRFASSOCIATEDINTERFACES:
		return SNMP_INTEGER(bgp_vrf_interfaces(l3vpn_bgp, false));
	case MPLSL3VPNVRFCONFMIDRTETHRESH:
		return SNMP_INTEGER(0);
	case MPLSL3VPNVRFCONFHIGHRTETHRSH:
		return SNMP_INTEGER(0);
	case MPLSL3VPNVRFCONFMAXROUTES:
		return SNMP_INTEGER(0);
	case MPLSL3VPNVRFCONFLASTCHANGED:
		return SNMP_INTEGER(
			(uint32_t)l3vpn_bgp->snmp_stats->modify_time);
	case MPLSL3VPNVRFCONFROWSTATUS:
		return SNMP_INTEGER(1);
	case MPLSL3VPNVRFCONFADMINSTATUS:
		return SNMP_INTEGER(1);
	case MPLSL3VPNVRFCONFSTORAGETYPE:
		return SNMP_INTEGER(2);
		return NULL;
	}
	return NULL;
}

void bgp_mpls_l3vpn_module_init(void)
{
	hook_register(bgp_vrf_status_changed, bgp_vrf_check_update_active);
	hook_register(bgp_snmp_init_stats, bgp_init_snmp_stats);
	hook_register(bgp_snmp_update_last_changed,
		      bgp_mpls_l3vpn_update_last_changed);
	REGISTER_MIB("mplsL3VpnMIB", mpls_l3vpn_variables, variable,
		     mpls_l3vpn_oid);
}