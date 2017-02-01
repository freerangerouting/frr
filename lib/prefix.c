/*
 * Prefix related functions.
 * Copyright (C) 1997, 98, 99 Kunihiro Ishiguro
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
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#include <zebra.h>

#include "prefix.h"
#include "vty.h"
#include "sockunion.h"
#include "memory.h"
#include "log.h"

DEFINE_MTYPE_STATIC(LIB, PREFIX, "Prefix")

/* Maskbit. */
static const u_char maskbit[] = {0x00, 0x80, 0xc0, 0xe0, 0xf0,
			         0xf8, 0xfc, 0xfe, 0xff};

static const struct in6_addr maskbytes6[] =
{
  /* /0   */ { { { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /1   */ { { { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /2   */ { { { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /3   */ { { { 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /4   */ { { { 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /5   */ { { { 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /6   */ { { { 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /7   */ { { { 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /8   */ { { { 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /9   */ { { { 0xff, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /10  */ { { { 0xff, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /11  */ { { { 0xff, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /12  */ { { { 0xff, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /13  */ { { { 0xff, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /14  */ { { { 0xff, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /15  */ { { { 0xff, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /16  */ { { { 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /17  */ { { { 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /18  */ { { { 0xff, 0xff, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /19  */ { { { 0xff, 0xff, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /20  */ { { { 0xff, 0xff, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /21  */ { { { 0xff, 0xff, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /22  */ { { { 0xff, 0xff, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /23  */ { { { 0xff, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /24  */ { { { 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /25  */ { { { 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /26  */ { { { 0xff, 0xff, 0xff, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /27  */ { { { 0xff, 0xff, 0xff, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /28  */ { { { 0xff, 0xff, 0xff, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /29  */ { { { 0xff, 0xff, 0xff, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /30  */ { { { 0xff, 0xff, 0xff, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /31  */ { { { 0xff, 0xff, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /32  */ { { { 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /33  */ { { { 0xff, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /34  */ { { { 0xff, 0xff, 0xff, 0xff, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /35  */ { { { 0xff, 0xff, 0xff, 0xff, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /36  */ { { { 0xff, 0xff, 0xff, 0xff, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /37  */ { { { 0xff, 0xff, 0xff, 0xff, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /38  */ { { { 0xff, 0xff, 0xff, 0xff, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /39  */ { { { 0xff, 0xff, 0xff, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /40  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /41  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /42  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /43  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /44  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /45  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /46  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /47  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /48  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /49  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /50  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /51  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /52  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /53  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /54  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /55  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /56  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /57  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /58  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /59  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /60  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /61  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /62  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /63  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /64  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /65  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /66  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /67  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /68  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /69  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /70  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /71  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /72  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /73  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /74  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /75  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /76  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /77  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /78  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /79  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /80  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /81  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /82  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /83  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /84  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /85  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /86  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /87  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /88  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00 } } },
  /* /89  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x00 } } },
  /* /90  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc0, 0x00, 0x00, 0x00, 0x00 } } },
  /* /91  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xe0, 0x00, 0x00, 0x00, 0x00 } } },
  /* /92  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0, 0x00, 0x00, 0x00, 0x00 } } },
  /* /93  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf8, 0x00, 0x00, 0x00, 0x00 } } },
  /* /94  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc, 0x00, 0x00, 0x00, 0x00 } } },
  /* /95  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x00 } } },
  /* /96  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 } } },
  /* /97  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00 } } },
  /* /98  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc0, 0x00, 0x00, 0x00 } } },
  /* /99  */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xe0, 0x00, 0x00, 0x00 } } },
  /* /100 */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0, 0x00, 0x00, 0x00 } } },
  /* /101 */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf8, 0x00, 0x00, 0x00 } } },
  /* /102 */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc, 0x00, 0x00, 0x00 } } },
  /* /103 */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x00, 0x00, 0x00 } } },
  /* /104 */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00 } } },
  /* /105 */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00 } } },
  /* /106 */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc0, 0x00, 0x00 } } },
  /* /107 */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xe0, 0x00, 0x00 } } },
  /* /108 */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0, 0x00, 0x00 } } },
  /* /109 */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf8, 0x00, 0x00 } } },
  /* /110 */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc, 0x00, 0x00 } } },
  /* /111 */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x00, 0x00 } } },
  /* /112 */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00 } } },
  /* /113 */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80, 0x00 } } },
  /* /114 */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc0, 0x00 } } },
  /* /115 */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xe0, 0x00 } } },
  /* /116 */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0, 0x00 } } },
  /* /117 */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf8, 0x00 } } },
  /* /118 */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc, 0x00 } } },
  /* /119 */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x00 } } },
  /* /120 */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00 } } },
  /* /121 */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80 } } },
  /* /122 */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc0 } } },
  /* /123 */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xe0 } } },
  /* /124 */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0 } } },
  /* /125 */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf8 } } },
  /* /126 */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc } } },
  /* /127 */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe } } },
  /* /128 */ { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } } }
};

/* Number of bits in prefix type. */
#ifndef PNBBY
#define PNBBY 8
#endif /* PNBBY */

#define MASKBIT(offset)  ((0xff << (PNBBY - (offset))) & 0xff)

unsigned int
prefix_bit (const u_char *prefix, const u_char prefixlen)
{
  unsigned int offset = prefixlen / 8;
  unsigned int shift  = 7 - (prefixlen % 8);
  
  return (prefix[offset] >> shift) & 1;
}

unsigned int
prefix6_bit (const struct in6_addr *prefix, const u_char prefixlen)
{
  return prefix_bit((const u_char *) &prefix->s6_addr, prefixlen);
}

int
str2family(const char *string)
{
  if (!strcmp("ipv4", string))
    return AF_INET;
  else if (!strcmp("ipv6", string))
    return AF_INET6;
  else if (!strcmp("ethernet", string))
    return AF_ETHERNET;
  return -1;
}

/* Address Famiy Identifier to Address Family converter. */
int
afi2family (afi_t afi)
{
  if (afi == AFI_IP)
    return AF_INET;
  else if (afi == AFI_IP6)
    return AF_INET6;
  else if (afi == AFI_L2VPN)
    return AF_ETHERNET;
  return 0;
}

afi_t
family2afi (int family)
{
  if (family == AF_INET)
    return AFI_IP;
  else if (family == AF_INET6)
    return AFI_IP6;
  else if (family == AF_ETHERNET)
    return AFI_L2VPN;
  return 0;
}

const char *
afi2str(afi_t afi)
{
  switch (afi) {
    case AFI_IP:
	return "IPv4";
    case AFI_IP6:
	return "IPv6";
    case AFI_ETHER:
	return "ethernet";
    case AFI_L2VPN:
	return "l2vpn";
    case AFI_MAX:
        return "bad-value";
    default:
	break;
  }
  return NULL;
}

const char *
safi2str(safi_t safi)
{
  switch (safi) {
    case SAFI_UNICAST:
	return "unicast";
    case SAFI_MULTICAST:
	return "multicast";
    case SAFI_ENCAP:
	return "encap";
    case SAFI_MPLS_VPN:
	return "vpn";
    case SAFI_EVPN:
	return "evpn";
  }
  return NULL;
}

/* If n includes p prefix then return 1 else return 0. */
int
prefix_match (const struct prefix *n, const struct prefix *p)
{
  int offset;
  int shift;
  const u_char *np, *pp;

  /* If n's prefix is longer than p's one return 0. */
  if (n->prefixlen > p->prefixlen)
    return 0;

  /* Set both prefix's head pointer. */
  np = (const u_char *)&n->u.prefix;
  pp = (const u_char *)&p->u.prefix;
  
  offset = n->prefixlen / PNBBY;
  shift =  n->prefixlen % PNBBY;

  if (shift)
    if (maskbit[shift] & (np[offset] ^ pp[offset]))
      return 0;
  
  while (offset--)
    if (np[offset] != pp[offset])
      return 0;
  return 1;
}

/* Copy prefix from src to dest. */
void
prefix_copy (struct prefix *dest, const struct prefix *src)
{
  dest->family = src->family;
  dest->prefixlen = src->prefixlen;

  if (src->family == AF_INET)
    dest->u.prefix4 = src->u.prefix4;
  else if (src->family == AF_INET6)
    dest->u.prefix6 = src->u.prefix6;
  else if (src->family == AF_ETHERNET)
    {
      memcpy (&dest->u.prefix_evpn, &src->u.prefix_evpn, sizeof (struct evpn_addr));
    }
  else if (src->family == AF_UNSPEC)
    {
      dest->u.lp.id = src->u.lp.id;
      dest->u.lp.adv_router = src->u.lp.adv_router;
    }
  else
    {
      zlog (NULL, LOG_ERR, "prefix_copy(): Unknown address family %d",
	      src->family);
      assert (0);
    }
}

/* 
 * Return 1 if the address/netmask contained in the prefix structure
 * is the same, and else return 0.  For this routine, 'same' requires
 * that not only the prefix length and the network part be the same,
 * but also the host part.  Thus, 10.0.0.1/8 and 10.0.0.2/8 are not
 * the same.  Note that this routine has the same return value sense
 * as '==' (which is different from prefix_cmp).
 */
int
prefix_same (const struct prefix *p1, const struct prefix *p2)
{
  if ((p1 && !p2) || (!p1 && p2))
    return 0;

  if (!p1 && !p2)
    return 1;

  if (p1->family == p2->family && p1->prefixlen == p2->prefixlen)
    {
      if (p1->family == AF_INET)
	if (IPV4_ADDR_SAME (&p1->u.prefix4.s_addr, &p2->u.prefix4.s_addr))
	  return 1;
      if (p1->family == AF_INET6 )
	if (IPV6_ADDR_SAME (&p1->u.prefix6.s6_addr, &p2->u.prefix6.s6_addr))
	  return 1;
      if (p1->family == AF_ETHERNET )
        if (!memcmp (&p1->u.prefix_evpn, &p2->u.prefix_evpn, sizeof (struct evpn_addr)))
          return 1;
    }
  return 0;
}

/*
 * Return 0 if the network prefixes represented by the struct prefix
 * arguments are the same prefix, and 1 otherwise.  Network prefixes
 * are considered the same if the prefix lengths are equal and the
 * network parts are the same.  Host bits (which are considered masked
 * by the prefix length) are not significant.  Thus, 10.0.0.1/8 and
 * 10.0.0.2/8 are considered equivalent by this routine.  Note that
 * this routine has the same return sense as strcmp (which is different
 * from prefix_same).
 */
int
prefix_cmp (const struct prefix *p1, const struct prefix *p2)
{
  int offset;
  int shift;

  /* Set both prefix's head pointer. */
  const u_char *pp1 = (const u_char *)&p1->u.prefix;
  const u_char *pp2 = (const u_char *)&p2->u.prefix;

  if (p1->family != p2->family || p1->prefixlen != p2->prefixlen)
    return 1;

  offset = p1->prefixlen / PNBBY;
  shift = p1->prefixlen % PNBBY;

  if (shift)
    if (maskbit[shift] & (pp1[offset] ^ pp2[offset]))
      return 1;

  while (offset--)
    if (pp1[offset] != pp2[offset])
      return 1;

  return 0;
}

/*
 * Count the number of common bits in 2 prefixes. The prefix length is
 * ignored for this function; the whole prefix is compared. If the prefix
 * address families don't match, return -1; otherwise the return value is
 * in range 0 ... maximum prefix length for the address family.
 */
int
prefix_common_bits (const struct prefix *p1, const struct prefix *p2)
{
  int pos, bit;
  int length = 0;
  u_char xor;

  /* Set both prefix's head pointer. */
  const u_char *pp1 = (const u_char *)&p1->u.prefix;
  const u_char *pp2 = (const u_char *)&p2->u.prefix;

  if (p1->family == AF_INET)
    length = IPV4_MAX_BYTELEN;
  if (p1->family == AF_INET6)
    length = IPV6_MAX_BYTELEN;
  if (p1->family == AF_ETHERNET)
    length = 8 * sizeof (struct evpn_addr);

  if (p1->family != p2->family || !length)
    return -1;

  for (pos = 0; pos < length; pos++)
    if (pp1[pos] != pp2[pos])
      break;
  if (pos == length)
    return pos * 8;

  xor = pp1[pos] ^ pp2[pos];
  for (bit = 0; bit < 8; bit++)
    if (xor & (1 << (7 - bit)))
      break;

  return pos * 8 + bit;
}

/* Return prefix family type string. */
const char *
prefix_family_str (const struct prefix *p)
{
  if (p->family == AF_INET)
    return "inet";
  if (p->family == AF_INET6)
    return "inet6";
  if (p->family == AF_ETHERNET)
    return "ether";
  return "unspec";
}

/* Allocate new prefix_ipv4 structure. */
struct prefix_ipv4 *
prefix_ipv4_new ()
{
  struct prefix_ipv4 *p;

  /* Call prefix_new to allocate a full-size struct prefix to avoid problems
     where the struct prefix_ipv4 is cast to struct prefix and unallocated
     bytes were being referenced (e.g. in structure assignments). */
  p = (struct prefix_ipv4 *)prefix_new();
  p->family = AF_INET;
  return p;
}

/* Free prefix_ipv4 structure. */
void
prefix_ipv4_free (struct prefix_ipv4 *p)
{
  prefix_free((struct prefix *)p);
}

/* When string format is invalid return 0. */
int
str2prefix_ipv4 (const char *str, struct prefix_ipv4 *p)
{
  int ret;
  int plen;
  char *pnt;
  char *cp;

  /* Find slash inside string. */
  pnt = strchr (str, '/');

  /* String doesn't contail slash. */
  if (pnt == NULL) 
    {
      /* Convert string to prefix. */
      ret = inet_aton (str, &p->prefix);
      if (ret == 0)
	return 0;

      /* If address doesn't contain slash we assume it host address. */
      p->family = AF_INET;
      p->prefixlen = IPV4_MAX_BITLEN;

      return ret;
    }
  else
    {
      cp = XMALLOC (MTYPE_TMP, (pnt - str) + 1);
      strncpy (cp, str, pnt - str);
      *(cp + (pnt - str)) = '\0';
      ret = inet_aton (cp, &p->prefix);
      XFREE (MTYPE_TMP, cp);

      /* Get prefix length. */
      plen = (u_char) atoi (++pnt);
      if (plen > IPV4_MAX_PREFIXLEN)
	return 0;

      p->family = AF_INET;
      p->prefixlen = plen;
    }

  return ret;
}

/* When string format is invalid return 0. */
int
str2prefix_eth (const char *str, struct prefix_eth *p)
{
  int		ret = 0;
  int		plen = 48;
  char		*pnt;
  char		*cp = NULL;
  const char	*str_addr = str;
  unsigned int	a[6];
  int		i;

  /* Find slash inside string. */
  pnt = strchr (str, '/');

  if (pnt)
    {
      /* Get prefix length. */
      plen = (u_char) atoi (++pnt);
      if (plen > 48)
	{
	  ret = 0;
	  goto done;
	}

      cp = XMALLOC (MTYPE_TMP, (pnt - str) + 1);
      strncpy (cp, str, pnt - str);
      *(cp + (pnt - str)) = '\0';

      str_addr = cp;
    }

  /* Convert string to prefix. */
  if (sscanf(str_addr, "%2x:%2x:%2x:%2x:%2x:%2x",
    a+0, a+1, a+2, a+3, a+4, a+5) != 6)
    {
      ret = 0;
      goto done;
    }
  for (i = 0; i < 6; ++i)
    {
      p->eth_addr.octet[i] = a[i] & 0xff;
    }
  p->prefixlen = plen;
  p->family = AF_ETHERNET;
  ret = 1;

done:
  if (cp)
    XFREE (MTYPE_TMP, cp);

  return ret;
}

/* Convert masklen into IP address's netmask (network byte order). */
void
masklen2ip (const int masklen, struct in_addr *netmask)
{
  assert (masklen >= 0 && masklen <= IPV4_MAX_BITLEN);

  /* left shift is only defined for less than the size of the type.
   * we unconditionally use long long in case the target platform
   * has defined behaviour for << 32 (or has a 64-bit left shift) */

  if (sizeof(unsigned long long) > 4)
    netmask->s_addr = htonl(0xffffffffULL << (32 - masklen));
  else
    netmask->s_addr = htonl(masklen ? 0xffffffffU << (32 - masklen) : 0);
}

/* Convert IP address's netmask into integer. We assume netmask is
   sequential one. Argument netmask should be network byte order. */
u_char
ip_masklen (struct in_addr netmask)
{
  uint32_t tmp = ~ntohl(netmask.s_addr);
  if (tmp)
    /* clz: count leading zeroes. sadly, the behaviour of this builtin
     * is undefined for a 0 argument, even though most CPUs give 32 */
    return __builtin_clz(tmp);
  else
    return 32;
}

/* Apply mask to IPv4 prefix (network byte order). */
void
apply_mask_ipv4 (struct prefix_ipv4 *p)
{
  struct in_addr mask;
  masklen2ip(p->prefixlen, &mask);
  p->prefix.s_addr &= mask.s_addr;
}

/* If prefix is 0.0.0.0/0 then return 1 else return 0. */
int
prefix_ipv4_any (const struct prefix_ipv4 *p)
{
  return (p->prefix.s_addr == 0 && p->prefixlen == 0);
}

/* Allocate a new ip version 6 route */
struct prefix_ipv6 *
prefix_ipv6_new (void)
{
  struct prefix_ipv6 *p;

  /* Allocate a full-size struct prefix to avoid problems with structure
     size mismatches. */
  p = (struct prefix_ipv6 *)prefix_new();
  p->family = AF_INET6;
  return p;
}

/* Free prefix for IPv6. */
void
prefix_ipv6_free (struct prefix_ipv6 *p)
{
  prefix_free((struct prefix *)p);
}

/* If given string is valid return pin6 else return NULL */
int
str2prefix_ipv6 (const char *str, struct prefix_ipv6 *p)
{
  char *pnt;
  char *cp;
  int ret;

  pnt = strchr (str, '/');

  /* If string doesn't contain `/' treat it as host route. */
  if (pnt == NULL) 
    {
      ret = inet_pton (AF_INET6, str, &p->prefix);
      if (ret == 0)
	return 0;
      p->prefixlen = IPV6_MAX_BITLEN;
    }
  else 
    {
      int plen;

      cp = XMALLOC (MTYPE_TMP, (pnt - str) + 1);
      strncpy (cp, str, pnt - str);
      *(cp + (pnt - str)) = '\0';
      ret = inet_pton (AF_INET6, cp, &p->prefix);
      XFREE (MTYPE_TMP, cp);
      if (ret == 0)
	return 0;
      plen = (u_char) atoi (++pnt);
      if (plen > IPV6_MAX_BITLEN)
	return 0;
      p->prefixlen = plen;
    }
  p->family = AF_INET6;

  return ret;
}

/* Convert struct in6_addr netmask into integer.
 * FIXME return u_char as ip_maskleni() does. */
int
ip6_masklen (struct in6_addr netmask)
{
  int len = 0;
  unsigned char val;
  unsigned char *pnt;
  
  pnt = (unsigned char *) & netmask;

  while ((*pnt == 0xff) && len < IPV6_MAX_BITLEN)
    {
      len += 8;
      pnt++;
    } 
  
  if (len < IPV6_MAX_BITLEN)
    {
      val = *pnt;
      while (val) 
	{
	  len++;
	  val <<= 1;
	}
    }
  return len;
}

void
masklen2ip6 (const int masklen, struct in6_addr *netmask)
{
  assert (masklen >= 0 && masklen <= IPV6_MAX_BITLEN);
  memcpy (netmask, maskbytes6 + masklen, sizeof (struct in6_addr));
}

void
apply_mask_ipv6 (struct prefix_ipv6 *p)
{
  u_char *pnt;
  int index;
  int offset;

  index = p->prefixlen / 8;

  if (index < 16)
    {
      pnt = (u_char *) &p->prefix;
      offset = p->prefixlen % 8;

      pnt[index] &= maskbit[offset];
      index++;

      while (index < 16)
	pnt[index++] = 0;
    }
}

void
apply_mask (struct prefix *p)
{
  switch (p->family)
    {
      case AF_INET:
        apply_mask_ipv4 ((struct prefix_ipv4 *)p);
        break;
      case AF_INET6:
        apply_mask_ipv6 ((struct prefix_ipv6 *)p);
        break;
      default:
        break;
    }
  return;
}

/* Utility function of convert between struct prefix <=> union sockunion.
 * FIXME This function isn't used anywhere. */
struct prefix *
sockunion2prefix (const union sockunion *dest,
		  const union sockunion *mask)
{
  if (dest->sa.sa_family == AF_INET)
    {
      struct prefix_ipv4 *p;

      p = prefix_ipv4_new ();
      p->family = AF_INET;
      p->prefix = dest->sin.sin_addr;
      p->prefixlen = ip_masklen (mask->sin.sin_addr);
      return (struct prefix *) p;
    }
  if (dest->sa.sa_family == AF_INET6)
    {
      struct prefix_ipv6 *p;

      p = prefix_ipv6_new ();
      p->family = AF_INET6;
      p->prefixlen = ip6_masklen (mask->sin6.sin6_addr);
      memcpy (&p->prefix, &dest->sin6.sin6_addr, sizeof (struct in6_addr));
      return (struct prefix *) p;
    }
  return NULL;
}

/* Utility function of convert between struct prefix <=> union sockunion. */
struct prefix *
sockunion2hostprefix (const union sockunion *su, struct prefix *prefix)
{
  if (su->sa.sa_family == AF_INET)
    {
      struct prefix_ipv4 *p;

      p = prefix ? (struct prefix_ipv4 *) prefix : prefix_ipv4_new ();
      p->family = AF_INET;
      p->prefix = su->sin.sin_addr;
      p->prefixlen = IPV4_MAX_BITLEN;
      return (struct prefix *) p;
    }
  if (su->sa.sa_family == AF_INET6)
    {
      struct prefix_ipv6 *p;

      p = prefix ? (struct prefix_ipv6 *) prefix : prefix_ipv6_new ();
      p->family = AF_INET6;
      p->prefixlen = IPV6_MAX_BITLEN;
      memcpy (&p->prefix, &su->sin6.sin6_addr, sizeof (struct in6_addr));
      return (struct prefix *) p;
    }
  return NULL;
}

void
prefix2sockunion (const struct prefix *p, union sockunion *su)
{
  memset (su, 0, sizeof (*su));

  su->sa.sa_family = p->family;
  if (p->family == AF_INET)
    su->sin.sin_addr = p->u.prefix4;
  if (p->family == AF_INET6)
    memcpy (&su->sin6.sin6_addr, &p->u.prefix6, sizeof (struct in6_addr));
}

int
prefix_blen (const struct prefix *p)
{
  switch (p->family) 
    {
    case AF_INET:
      return IPV4_MAX_BYTELEN;
      break;
    case AF_INET6:
      return IPV6_MAX_BYTELEN;
      break;
    case AF_ETHERNET:
      return ETHER_ADDR_LEN;
    }
  return 0;
}

/* Generic function for conversion string to struct prefix. */
int
str2prefix (const char *str, struct prefix *p)
{
  int ret;

  /* First we try to convert string to struct prefix_ipv4. */
  ret = str2prefix_ipv4 (str, (struct prefix_ipv4 *) p);
  if (ret)
    return ret;

  /* Next we try to convert string to struct prefix_ipv6. */
  ret = str2prefix_ipv6 (str, (struct prefix_ipv6 *) p);
  if (ret)
    return ret;

  /* Next we try to convert string to struct prefix_eth. */
  ret = str2prefix_eth (str, (struct prefix_eth *) p);
  if (ret)
    return ret;

  return 0;
}

const char *
prefix2str (union prefixconstptr pu, char *str, int size)
{
  const struct prefix *p = pu.p;
  char buf[PREFIX2STR_BUFFER];

  switch (p->family)
    {
      case AF_INET:
      case AF_INET6:
        snprintf (str, size, "%s/%d",
                  inet_ntop (p->family, &p->u.prefix, buf, PREFIX2STR_BUFFER),
                  p->prefixlen);
        break;

      case AF_ETHERNET:
        if (p->u.prefix_evpn.route_type == 5)
          {
            u_char family;
            family = (p->u.prefix_evpn.flags & (IP_ADDR_V4 | IP_PREFIX_V4)) ?
              AF_INET : AF_INET6;
            snprintf (str, size, "[%d]:[%u][%s]/%d",
                      p->u.prefix_evpn.route_type,
                      p->u.prefix_evpn.eth_tag,
                      inet_ntop (family, &p->u.prefix_evpn.ip.addr,
                                 buf, PREFIX2STR_BUFFER),
                      p->prefixlen);
          }
        break;
      default:
        sprintf (str, "UNK prefix");
        break;
    }

  return str;
}

struct prefix *
prefix_new ()
{
  struct prefix *p;

  p = XCALLOC (MTYPE_PREFIX, sizeof *p);
  return p;
}

/* Free prefix structure. */
void
prefix_free (struct prefix *p)
{
  XFREE (MTYPE_PREFIX, p);
}

/* Utility function.  Check the string only contains digit
 * character.
 * FIXME str.[c|h] would be better place for this function. */
int
all_digit (const char *str)
{
  for (; *str != '\0'; str++)
    if (!isdigit ((int) *str))
      return 0;
  return 1;
}

/* Utility function to convert ipv4 prefixes to Classful prefixes */
void apply_classful_mask_ipv4 (struct prefix_ipv4 *p)
{

  u_int32_t destination;
  
  destination = ntohl (p->prefix.s_addr);
  
  if (p->prefixlen == IPV4_MAX_PREFIXLEN);
  /* do nothing for host routes */
  else if (IN_CLASSC (destination)) 
    {
      p->prefixlen=24;
      apply_mask_ipv4(p);
    }
  else if (IN_CLASSB(destination)) 
    {
      p->prefixlen=16;
      apply_mask_ipv4(p);
    }
  else 
    {
      p->prefixlen=8;
      apply_mask_ipv4(p);
    }
}

in_addr_t
ipv4_network_addr (in_addr_t hostaddr, int masklen)
{
  struct in_addr mask;

  masklen2ip (masklen, &mask);
  return hostaddr & mask.s_addr;
}

in_addr_t
ipv4_broadcast_addr (in_addr_t hostaddr, int masklen)
{
  struct in_addr mask;

  masklen2ip (masklen, &mask);
  return (masklen != IPV4_MAX_PREFIXLEN-1) ?
	 /* normal case */
         (hostaddr | ~mask.s_addr) :
	 /* special case for /31 */
         (hostaddr ^ ~mask.s_addr);
}

/* Utility function to convert ipv4 netmask to prefixes 
   ex.) "1.1.0.0" "255.255.0.0" => "1.1.0.0/16"
   ex.) "1.0.0.0" NULL => "1.0.0.0/8"                   */
int
netmask_str2prefix_str (const char *net_str, const char *mask_str,
			char *prefix_str)
{
  struct in_addr network;
  struct in_addr mask;
  u_char prefixlen;
  u_int32_t destination;
  int ret;

  ret = inet_aton (net_str, &network);
  if (! ret)
    return 0;

  if (mask_str)
    {
      ret = inet_aton (mask_str, &mask);
      if (! ret)
        return 0;

      prefixlen = ip_masklen (mask);
    }
  else 
    {
      destination = ntohl (network.s_addr);

      if (network.s_addr == 0)
	prefixlen = 0;
      else if (IN_CLASSC (destination))
	prefixlen = 24;
      else if (IN_CLASSB (destination))
	prefixlen = 16;
      else if (IN_CLASSA (destination))
	prefixlen = 8;
      else
	return 0;
    }

  sprintf (prefix_str, "%s/%d", net_str, prefixlen);

  return 1;
}

/* Utility function for making IPv6 address string. */
const char *
inet6_ntoa (struct in6_addr addr)
{
  static char buf[INET6_ADDRSTRLEN];

  inet_ntop (AF_INET6, &addr, buf, INET6_ADDRSTRLEN);
  return buf;
}


static uint8_t convertchartohexa(uint8_t * hexa, int *error)
{
  if ((*hexa == '0') || (*hexa == '1') || (*hexa == '2') ||
      (*hexa == '3') || (*hexa == '4') || (*hexa == '5') ||
      (*hexa == '6') || (*hexa == '7') || (*hexa == '8')
      || (*hexa == '9'))
    return (uint8_t) (*hexa) - '0';
  if ((*hexa == 'a') || (*hexa == 'A'))
    return 0xa;
  if ((*hexa == 'b') || (*hexa == 'B'))
    return 0xb;
  if ((*hexa == 'c') || (*hexa == 'C'))
    return 0xc;
  if ((*hexa == 'd') || (*hexa == 'D'))
    return 0xd;
  if ((*hexa == 'e') || (*hexa == 'E'))
    return 0xe;
  if ((*hexa == 'f') || (*hexa == 'F'))
    return 0xf;
  *error = -1;
  return 0;
}

/* converts to internal representation of mac address
 * returns 1 on success, 0 otherwise 
 * format accepted: AA:BB:CC:DD:EE:FF
 * if mac parameter is null, then check only
 */
int str2mac(const char *str, char *mac)
{
  unsigned int k = 0, i, j;
  uint8_t *ptr, *ptr2;
  size_t len;
  uint8_t car;
  
  if (!str)
    return 0;
  
  if (str[0] == ':' && str[1] == '\0')
    return 1;
  
  i = 0;
  ptr = (uint8_t *) str;
  while (i < 6) {
    uint8_t temp[5];
    int error = 0;
    ptr2 = (uint8_t *) strchr((const char *)ptr, ':');
    if (ptr2 == NULL) {
      /* if last occurence return ok */
      if (i != 5) {
        zlog_err("[%s]: format non recognized", mac);
        return 0;
      }
      len = strlen((char *)ptr);
    } else {
      len = ptr2 - ptr;
    }
    if (len > 5) {
      zlog_err("[%s]: format non recognized", mac);
      return 0;
    }
    memcpy(temp, ptr, len);
    for (j = 0; j < len; j++) {
      if (k >= ETHER_ADDR_LEN)
        return 0;
      if (mac)
        mac[k] = 0;
      car = convertchartohexa(&temp[j], &error);
      if (error)
        return 0;
      if (mac)
        mac[k] = car << 4;
      j++;
      if (j == len)
        return 0;
      car = convertchartohexa(&temp[j], &error) & 0xf;
      if (error)
        return 0;
      if (mac)
        mac[k] |= car & 0xf;
      k++;
      i++;
    }
    ptr = ptr2;
    if (ptr == NULL)
      break;
    ptr++;
  }
  if (mac && 0) {
    zlog_err("leave correct : %02x:%02x:%02x:%02x:%02x:%02x",
             mac[0] & 0xff, mac[1] & 0xff, mac[2] & 0xff,
             mac[3] & 0xff, mac[4] & 0xff, mac[5] & 0xff);
  }
  return 1;
}

char *mac2str(char *mac, char *buf, int size)
{
  char *ptr;
  
  if (!mac)
    return NULL;
  if (!buf)
    ptr = (char *)XMALLOC(MTYPE_TMP, ETHER_ADDR_STRLEN* sizeof(char));
  else
    {
      assert (size >= ETHER_ADDR_STRLEN);
      ptr = buf;
    }
  snprintf(ptr, (ETHER_ADDR_STRLEN),
           "%02x:%02x:%02x:%02x:%02x:%02x", (uint8_t) mac[0],
           (uint8_t) mac[1], (uint8_t) mac[2], (uint8_t) mac[3],
           (uint8_t) mac[4], (uint8_t) mac[5]);
  return ptr;
}
