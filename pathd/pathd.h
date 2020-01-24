/*
 * Copyright (C) 2019  NetDEF, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _FRR_PATHD_H_
#define _FRR_PATHD_H_

/* maximum length of an IP string including null byte */
#define MAX_IP_STR_LENGTH 46

/* maximum amount of candidate paths */
#define MAX_SR_POLICY_CANDIDATE_PATH_N 100

#include "lib/mpls.h"
#include "lib/ipaddr.h"
#include "lib/srte.h"
#include "lib/hook.h"

enum te_protocol_origin {
	TE_ORIGIN_PCEP = 1,
	TE_ORIGIN_BGP = 2,
	TE_ORIGIN_CONFIG = 3,
};

enum te_candidate_path_type {
	TE_CANDIDATE_PATH_EXPLICIT = 0,
	TE_CANDIDATE_PATH_DYNAMIC = 1,
};

struct te_segment_list_segment {
	RB_ENTRY(te_segment_list_segment) entry;

	/* Index of the Label. */
	uint32_t index;

	/* Label Value. */
	mpls_label_t sid_value;
};
RB_HEAD(te_segment_list_segment_instance_head, te_segment_list_segment);
RB_PROTOTYPE(te_segment_list_segment_instance_head, te_segment_list_segment,
	     entry, te_segment_list_segment_instance_compare)

struct te_segment_list {
	RB_ENTRY(te_segment_list) entry;

	/* Name of the Segment List. */
	char *name;

	/* Nexthops. */
	struct te_segment_list_segment_instance_head segments;
};
RB_HEAD(te_segment_list_instance_head, te_segment_list);
RB_PROTOTYPE(te_segment_list_instance_head, te_segment_list, entry,
	     te_segment_list_instance_compare)

struct te_candidate_path {
	RB_ENTRY(te_candidate_path) entry;

	/* Backpoiner to SR Policy */
	struct te_sr_policy *sr_policy;

	/* Administrative preference. */
	uint32_t preference;

	/* true when created, false after triggering the "created" hook. */
	bool created;

	/* Symbolic Name. */
	char *name;

	/* The associated Segment List. */
	char *segment_list_name;

	/* The Protocol-Origin. */
	enum te_protocol_origin protocol_origin;

	/* The Originator */
	struct ipaddr originator;

	/* The Discriminator */
	uint32_t discriminator;

	/* Flag for best Candidate Path */
	bool is_best_candidate_path;

	/* The Type (explixit or dynamic) */
	enum te_candidate_path_type type;
};
RB_HEAD(te_candidate_path_instance_head, te_candidate_path);
RB_PROTOTYPE(te_candidate_path_instance_head, te_candidate_path, entry,
	     te_candidate_path_instance_compare)

struct te_sr_policy {
	RB_ENTRY(te_sr_policy) entry;

	/* Color */
	uint32_t color;

	/* Endpoint */
	struct ipaddr endpoint;

	/* Name */
	char *name;

	/* Binding SID */
	mpls_label_t binding_sid;

	/* Active Candidate Path Key */
	uint32_t best_candidate_path_key;

	/* Operational Status in Zebra */
	enum zebra_sr_policy_status status;

	/* Candidate Paths */
	struct te_candidate_path_instance_head candidate_paths;
};
RB_HEAD(te_sr_policy_instance_head, te_sr_policy);
RB_PROTOTYPE(te_sr_policy_instance_head, te_sr_policy, entry,
	     te_sr_policy_instance_compare)

DECLARE_HOOK(pathd_candidate_created,
             (struct te_candidate_path *te_candidate_path),
             (te_candidate_path))
DECLARE_HOOK(pathd_candidate_updated,
             (struct te_candidate_path *te_candidate_path),
             (te_candidate_path))
DECLARE_HOOK(pathd_candidate_removed,
             (struct te_candidate_path *te_candidate_path),
             (te_candidate_path))

extern struct te_segment_list_instance_head te_segment_list_instances;
extern struct te_sr_policy_instance_head te_sr_policy_instances;

extern struct zebra_privs_t pathd_privs;

/* Prototypes. */
void path_zebra_init(struct thread_master *master);
void path_zebra_add_sr_policy(struct te_sr_policy *sr_policy,
			      struct te_segment_list *segment_list);
void path_zebra_delete_sr_policy(struct te_sr_policy *sr_policy);
void path_cli_init(void);

struct te_segment_list *te_segment_list_create(const char *name);
void te_segment_list_del(struct te_segment_list *te_segment_list);
struct te_segment_list_segment *
te_segment_list_segment_add(struct te_segment_list *te_segment_list,
			    uint32_t index);
void te_segment_list_segment_del(
	struct te_segment_list *te_segment_list,
	struct te_segment_list_segment *te_segment_list_segment);
void te_segment_list_segment_sid_value_add(
	struct te_segment_list_segment *te_segment_list_segment,
	mpls_label_t label);
struct te_sr_policy *te_sr_policy_create(uint32_t color,
					 struct ipaddr *endpoint);
void te_sr_policy_del(struct te_sr_policy *te_sr_policy);
void te_sr_policy_name_set(struct te_sr_policy *te_sr_policy, const char *name);
void te_sr_policy_name_unset(struct te_sr_policy *te_sr_policy);
void te_sr_policy_binding_sid_add(struct te_sr_policy *te_sr_policy,
				  mpls_label_t binding_sid);
void te_sr_policy_candidate_path_set_active(struct te_sr_policy *te_sr_policy);
struct te_candidate_path *
te_sr_policy_candidate_path_add(struct te_sr_policy *te_sr_policy,
				uint32_t preference);
void te_sr_policy_candidate_path_name_set(
	struct te_candidate_path *te_candidate_path, const char *name);
void te_sr_policy_candidate_path_protocol_origin_add(
	struct te_candidate_path *te_candidate_path,
	enum te_protocol_origin protocol_origin);
void te_sr_policy_candidate_path_originator_add(
	struct te_candidate_path *te_candidate_path, struct ipaddr *originator);
void te_sr_policy_candidate_path_discriminator_add(
	struct te_candidate_path *te_candidate_path, uint32_t discriminator);
void te_sr_policy_candidate_path_type_add(
	struct te_candidate_path *te_candidate_path,
	enum te_candidate_path_type type);
void te_sr_policy_candidate_path_segment_list_name_set(
	struct te_candidate_path *te_candidate_path,
	const char *segment_list_name);
void te_sr_policy_candidate_path_delete(
	struct te_candidate_path *te_candidate_path);
struct te_sr_policy *te_sr_policy_get(uint32_t color, struct ipaddr *endpoint);
struct te_segment_list *te_segment_list_get(const char *name);
struct te_candidate_path *find_candidate_path(struct te_sr_policy *te_sr_policy,
					      uint32_t preference);

void pathd_candidate_updated(struct te_candidate_path *te_candidate_path);

#endif /* _FRR_PATHD_H_ */
