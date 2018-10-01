/*
  Copyright (c) 2015
  Author: Jeff Weisberg <jaw @ tcp4me.com>
  Created: 2015-Oct-06 00:34 (EDT)
  Function: initialize board

*/

#include <conf.h>
#include <proc.h>
#include <gpio.h>
#include <pwm.h>
#include <adc.h>
#include <spi.h>
#include <i2c.h>
#include <ioctl.h>
#include <error.h>
#include <stm32.h>
#include <userint.h>

#include "board.h"


// T1,T2 => AF(1); T3,T4,T5 => AF(2)
void
board_init(void){

    bootmsg("board hw init");

    // enable i+d cache, prefetch=on => faster
    FLASH->ACR  |= 0x700;

    // beeper
    gpio_init( HWCF_GPIO_AUDIO,    GPIO_AF(1) | GPIO_SPEED_2MHZ );
    pwm_init(  HWCF_TIMER_AUDIO,   440, 255 );
    pwm_set(   HWCF_TIMER_AUDIO,   0 );

    // card detect
    gpio_init( HWCF_GPIO_CARDDET,  GPIO_INPUT | GPIO_PULL_UP );
    // button
    gpio_init( HWCF_GPIO_BUTTON,   GPIO_INPUT );

#ifdef HWCF_GPIO_BUTTON2
    gpio_init( HWCF_GPIO_BUTTON2,  GPIO_INPUT | GPIO_PULL_DN );
#endif

    // LEDs
    gpio_init( HWCF_GPIO_LED_1R,   GPIO_AF(2) | GPIO_SPEED_2MHZ );
    gpio_init( HWCF_GPIO_LED_1G,   GPIO_AF(2) | GPIO_SPEED_2MHZ );
    gpio_init( HWCF_GPIO_LED_1B,   GPIO_AF(2) | GPIO_SPEED_2MHZ );
    gpio_init( HWCF_GPIO_LED_2R,   GPIO_AF(1) | GPIO_SPEED_2MHZ );
    gpio_init( HWCF_GPIO_LED_2G,   GPIO_AF(1) | GPIO_SPEED_2MHZ );
    gpio_init( HWCF_GPIO_LED_2B,   GPIO_AF(1) | GPIO_SPEED_2MHZ );

    pwm_init(  HWCF_TIMER_LED_1R,  10000, 254 );
    pwm_init(  HWCF_TIMER_LED_2R,  10000, 254 );

    pwm_set(   HWCF_TIMER_LED_1R,  0x7f);	// start with lights white
    pwm_set(   HWCF_TIMER_LED_2R,  0x7f);
    pwm_set(   HWCF_TIMER_LED_1B,  0x7f);
    pwm_set(   HWCF_TIMER_LED_2B,  0x7f);
    pwm_set(   HWCF_TIMER_LED_1G,  0x7f);
    pwm_set(   HWCF_TIMER_LED_2G,  0x7f);

#if 1
    // disable jtag, swd to prevent access to running system
    gpio_init( GPIO_A13, GPIO_OUTPUT | GPIO_PUSH_PULL );
    gpio_init( GPIO_A14, GPIO_OUTPUT | GPIO_PUSH_PULL );
    gpio_init( GPIO_A15, GPIO_OUTPUT | GPIO_PUSH_PULL );
    gpio_init( GPIO_B3,  GPIO_OUTPUT | GPIO_PUSH_PULL );
    gpio_init( GPIO_B4,  GPIO_OUTPUT | GPIO_PUSH_PULL );
#endif

    bootmsg("\n");

}

