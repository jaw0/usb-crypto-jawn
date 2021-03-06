/*
  Copyright (c) 2015
  Author: Jeff Weisberg <jaw @ tcp4me.com>
  Created: 2015-Oct-06 00:43 (EDT)
  Function: main

*/


#include <conf.h>
#include <proc.h>
#include <gpio.h>
#include <ioctl.h>
#include <error.h>
#include <stm32.h>
#include <userint.h>
#include <usbdef.h>
#include <usbmsc.h>

#include "board.h"
#include "util.h"
#include "dazzle.h"


extern void blinky(void);

static usb_msc_iocf_t usbconf[3];

DEFVAR(int, export_help, 1, UV_TYPE_UL | UV_TYPE_CONFIG, "export the help disk")


DEFUN(save, "save all config data")
{
    save_config("fl0:config.rc");
    return 0;
}


void
onpanic(const char *msg){
    int i;

    set_blinky( BLINK_OVERRIDE );
    set_leds_rgb(  0xFF0000, 0xFF0000 );
    beep_set(200, 127);

    splhigh();
    currproc = 0;

    while(1){
        set_leds_rgb(  0xFF0000, 0 );
        beep_set(150, 127);
        for(i=0; i<5000000; i++){ asm("nop"); }

        set_leds_rgb(  0, 0xFF0000 );
        beep_set(250, 127);
        for(i=0; i<5000000; i++){ asm("nop"); }
    }
}

int
sdcard_detected(void){
    return ! gpio_get( HWCF_GPIO_CARDDET );
}

int get_button(void){
    return gpio_get( HWCF_GPIO_BUTTON );

}

#ifdef REV1
int get_button1(void){
    return gpio_get( HWCF_GPIO_BUTTON2 );

}
#else
int get_button1(void){ return 0; }
#endif

//################################################################

#ifdef KTESTING
DEFUN(testcard, "test")
{
    printf(">%x\n", sdcard_detected() );
    return 0;
}

DEFUN(testbutt, "test button")
{
    while( ! get_button() ){ pause(); }
    play(8, "a3");
    while( get_button() ){ pause(); }
    play(8, "b3");
    return 0;
}
DEFUN(testbut1, "test button")
{
    while( ! get_button1() ){ pause(); }
    play(8, "a3");
    while( get_button1() ){ pause(); }
    play(8, "b3");
    return 0;
}
#endif

//################################################################

void
main_init(void){
    cgd_init();
    config_msc();
}

void
main(void){

    run_script("fl0:config.rc");
    run_script("fl0:startup.rc");

    init_blinky();
    set_blinky(BLINK_OVERRIDE);
    printf("\nUnauthorized access prohibited.\nSystem Ready\n\n");

    // button broken?
    if( ! sdcard_detected() || ! usbconf[0].fio ){
        set_leds_rgb( 0xFF0000, 0xFF0000 );
        kprintf("no card installed\n");
        play(32, "[3 d+4>>d-4>> ]");
        set_blinky( BLINK_NOCARD );
        return;
    }

    play(8, "a>>4g4c+4");
    set_leds_rgb( 0, 0 );
    set_blinky( BLINK_COLORS );
}

/****************************************************************/

static int is_ready(void){ return 1; }
static int always_ready(void){ return 1; }
static int never_ready(void){ return 0; }
static int help_ready(void){ return export_help; }
static void activity_blink(void){ set_led2_rgb(0x7F7F00); }

extern int cgd_isready(void);
extern int ugd_isready(void);

void
config_msc(){

    usbconf[0].ready = cgd_isready;
    usbconf[0].readonly = 0;
    usbconf[0].fio = fopen("dev:cgd", "rw");
    usbconf[0].prod = "Crypto Jawn";
    usbconf[0].activity = activity_blink;

    usbconf[1].ready = help_ready;
    usbconf[1].readonly = 1;
    usbconf[1].fio = fopen("dev:ro0", "rw");
    usbconf[1].prod = "Help Docs";
    usbconf[1].activity = 0;

    usbconf[2].ready = ugd_isready;
    usbconf[2].readonly = 0;
    usbconf[2].fio = fopen("dev:ugd", "rw");
    usbconf[2].prod = "My Data";
    usbconf[2].activity = activity_blink;

    if( !usbconf[0].fio ) kprintf("cannot open dev:cgd\n");
    if( !usbconf[1].fio ) kprintf("cannot open dev:ro0\n");
    if( !usbconf[2].fio ) kprintf("cannot open dev:ugd\n");

    msc_set_conf(0, 2, usbconf);

}

