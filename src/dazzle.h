/*
  Copyright (c) 2015
  Author: Jeff Weisberg <jaw @ tcp4me.com>
  Created: 2015-Oct-06 00:36 (EDT)
  Function: lights

*/

#ifndef __dazzle_h__
#define __dazzle_h__

#define BLINK_OVERRIDE	-1
#define BLINK_OFF	0
#define BLINK_NOCARD	1
#define BLINK_ERROR	2
#define BLINK_WAIT_USER 3
#define BLINK_ACTIVE    4
#define BLINK_COLORS	5
#define BLINK_INACTIVE	BLINK_COLORS

extern void set_blinky(int);
extern int volume;

#endif /* __dazzle_h__ */

