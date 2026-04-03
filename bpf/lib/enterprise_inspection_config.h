/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "enterprise_config.h"

DECLARE_ENTERPRISE_CONFIG(bool, passive_inspection_enable,
			  "True if passive inspection is enabled for pod traffic")
DECLARE_ENTERPRISE_CONFIG(__u32, passive_inspection_ifindex,
			  "Ifindex receiving mirrored pod traffic for passive inspection")
