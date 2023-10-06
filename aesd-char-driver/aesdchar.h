/*
 * aesdchar.h
 *
 *  Created on: Oct 23, 2019
*      Author: Dan Walkes
 */
#ifndef AESD_CHAR_DRIVER_AESDCHAR_H_
#define AESD_CHAR_DRIVER_AESDCHAR_H_

#include "aesd-circular-buffer.h"
#include "aesd_ioctl.h"
#include <linux/mutex.h>
#include <linux/cdev.h>

#define AESD_DEBUG 1  //Remove comment on this line to enable debug

#undef PDEBUG             /* undef it, just in case */
#ifdef AESD_DEBUG
#  ifdef __KERNEL__
     /* This one if debugging is on, and kernel space */
#    define PDEBUG(fmt, args...) printk( KERN_DEBUG "aesdchar: " fmt, ## args)
#  else
     /* This one for user space */
#    define PDEBUG(fmt, args...) fprintf(stderr, fmt, ## args)
#  endif
#else
#  define PDEBUG(fmt, args...) /* not debugging: nothing */
#endif

#define AESD_CHAR_MAJOR 0
#define AESD_CHAR_NUM_DEVS 1

struct aesd_dev
{
    /**
     * TODO: Add structure(s) and locks needed to complete assignment requirements
     */
    struct aesd_circular_buffer* data;
    char* temporary_command_buffer;
    size_t current_temporary_buffer_size;
    struct mutex lock;
    struct cdev cdev;     /* Char device structure      */
};

/* Function prototypes */
int aesd_open(struct inode* inode, struct file* filp);
int aesd_release(struct inode* inode, struct file* filp);
loff_t aesd_llseek(struct file *filp, loff_t off, int whence);
ssize_t aesd_read(struct file* filp, char* __user buf, size_t count, loff_t* f_pos);
ssize_t aesd_write(struct file* filp, const char* __user buf, size_t count, loff_t* f_pos);
long int aesd_unlocked_ioctl(struct file* filp, unsigned int cmd, unsigned long seekto);
static int aesd_init_module(void);
static void aesd_cleanup_module(void);

#endif /* AESD_CHAR_DRIVER_AESDCHAR_H_ */
