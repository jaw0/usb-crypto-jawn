/*
  Copyright (c) 2015
  Author: Jeff Weisberg <jaw @ tcp4me.com>
  Created: 2015-Oct-06 00:36 (EDT)
  Function: blinky lights

*/

#include <conf.h>
#include <proc.h>
#include <gpio.h>
#include <pwm.h>
#include <ioctl.h>
#include <stm32.h>
#include <userint.h>

#include "board.h"
#include "dazzle.h"

#define msleep(x)	usleep(x * 1000)

static int current_blink_pattern = 0;

void
debug_led(int a){

    gpio_init( HWCF_GPIO_LED_1R,  GPIO_OUTPUT | GPIO_PUSH_PULL );
    if( a ){
        gpio_set( HWCF_GPIO_LED_1R );
    }else{
        gpio_clear( HWCF_GPIO_LED_1R );
    }
}

void
set_led1_rgb(int a){
    // RGB

#ifdef REV1
    a = 0xFFFFFF - a;
#endif

    u_char r1 = (a>>16) & 0xFF;
    u_char g1 = (a>> 8) & 0xFF;
    u_char b1 =  a      & 0xFF;

    pwm_set( HWCF_TIMER_LED_1B, b1 );
    pwm_set( HWCF_TIMER_LED_1G, g1 );
    pwm_set( HWCF_TIMER_LED_1R, r1 );
}

void
set_led2_rgb(int b){
    // RGB

#ifdef REV1
    b = 0xFFFFFF - b;
#endif

    u_char r2 = (b>>16) & 0xFF;
    u_char g2 = (b>> 8) & 0xFF;
    u_char b2 =  b      & 0xFF;

    pwm_set( HWCF_TIMER_LED_2B, b2 );
    pwm_set( HWCF_TIMER_LED_2G, g2 );
    pwm_set( HWCF_TIMER_LED_2R, r2 );
}

void
set_leds_rgb(int a, int b){
    // RGB

    set_led1_rgb(a);
    set_led2_rgb(b);
}

// turquoise-ish
void
set_leds_z(int a, int b){

    set_led1_rgb( (a<<14) | (a<<8) | a );
    set_led2_rgb( (b<<14) | (b<<8) | b );

}

#ifdef KTESTING
DEFUN(testleds, "test leds")
{
    if( argc == 3 ){

        set_leds_rgb( strtol(argv[1], 0, 16), strtol(argv[2], 0, 16) );
        return 0;
    }

    // red
    set_leds_rgb( 0xFF0000, 0xFF0000 );
    sleep(1);
    // green
    set_leds_rgb( 0x00FF00, 0x00FF00 );
    sleep(1);
    // blue
    set_leds_rgb( 0x0000FF, 0x0000FF );
    sleep(1);

    // 1 red, 2 blue
    set_leds_rgb( 0xFF0000, 0x0000FF );
    sleep(1);

    set_leds_rgb( 0, 0 );

    return 0;
}

#endif

/****************************************************************/

void
set_blinky(int p){
    current_blink_pattern = p;
}

DEFUN(set_blinky, "set blink pattern")
{
    if( argc > 1 )
        current_blink_pattern = atoi(argv[1]);
    else
        printf("=> %d\n", current_blink_pattern);
    return 0;
}

static const u_char throb_slower[] = {
    0, 0, 1, 2, 4, 6, 8, 12, 16, 16,
    16, 16, 12, 8, 6, 4, 2, 1, 0, 0
};

static const u_char throb_slow[40] = {
    1, 2, 4, 8, 16,
    16, 8, 4, 2, 1,
    1, 2, 4, 8, 16,
    16, 8, 4, 2, 1,
    0, 0, 0, 0,
    0, 0, 0, 0,
    0, 0, 0, 0,
    0, 0, 0, 0,
    0, 0, 0, 0,
};
static const u_char throb_fast[15] = {
    1, 2, 4, 8, 16,
    16, 8, 4, 2, 1,
    0, 0, 0, 0, 0,
    0, 0, 0, 0, 0,
};

static int
cycle_color(int i){

    i %= 48;

    u_char v1 = (i & 0xF) << 2;
    u_char v2 = (0xF<<2) - v1;

    switch( i >> 4 ){
    case 0: // rg
        return (v2 << 16) | (v1 << 8);
    case 1: // gb
        return (v2 << 8) | (v1);
    case 2: // br
        return (v2) | (v1 << 16);
    }
}

void
blinky(void){
    short i = 0;

    while(1){
        switch( current_blink_pattern ){
        case BLINK_OVERRIDE:
            msleep(50);
            break;

        case BLINK_OFF:
            set_leds_rgb( 0, 0 );
            msleep(50);
            break;

        case BLINK_NOCARD:
            // |___|___
            set_leds_rgb( 0x7F0000, 0x7F0000 );
            msleep(25);
            set_leds_rgb( 0, 0 );
            msleep(475);
            break;

        case BLINK_ERROR:
            // X_X_X_
            set_leds_rgb( 0xFF0000, 0xFF0000 );
            msleep(125);
            set_leds_rgb( 0, 0 );
            msleep(125);
            break;

        case BLINK_WAIT_USER:
            for(i=0; i<sizeof(throb_slow); i++){
                if( current_blink_pattern != BLINK_WAIT_USER ) break;
                set_leds_z( throb_slow[i], throb_slow[sizeof(throb_slow)-i-1] );
                msleep(25);
            }
            break;

        case BLINK_ACTIVE:
            for(i=0; i<sizeof(throb_slower); i++){
                if( current_blink_pattern != BLINK_ACTIVE ) break;
                int c1 = throb_slower[i];
                int c2 = 16 - c1;

                set_led1_rgb( 0x081010 + (c1 << 9) + (c2));
                set_led2_rgb( 0x081010 + (c2 << 9) + (c1));

                msleep(25);
            }
            break;

        case BLINK_COLORS:
            for(i=0; i<48; i++){
                int c1 = cycle_color(i);
                int c2 = cycle_color(i+24);
                set_leds_rgb( c1, c2 );
                msleep(20);
            }
            break;

        default:
            msleep(250);
            break;
        }
    }
}

void
init_blinky(void){
    start_proc( 1024, blinky,  "blinky" );
}
