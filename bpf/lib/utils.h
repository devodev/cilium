/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>

#include "endian.h"
#include "time.h"
#include "static_data.h"

#define __min(t_x, t_y, x, y)		\
({					\
	t_x _x = (x);			\
	t_y _y = (y);			\
	(void) (&_x == &_y);		\
	_x < _y ? _x : _y;		\
})

#define __max(t_x, t_y, x, y)		\
({					\
	t_x _x = (x);			\
	t_y _y = (y);			\
	(void) (&_x == &_y);		\
	_x > _y ? _x : _y;		\
})

#define min(x, y)			\
	__min(typeof(x), typeof(y), x, y)

#define max(x, y)			\
	__max(typeof(x), typeof(y), x, y)

#define min_t(t, x, y)			\
	__min(t, t, x, y)

#define max_t(t, x, y)			\
	__max(t, t, x, y)

/* For use with compile-time constants that don't
 * have side effects on repeated evaluation.
 */
#define SIMPLE_MIN(x, y) ((x) < (y) ? (x) : (y))
