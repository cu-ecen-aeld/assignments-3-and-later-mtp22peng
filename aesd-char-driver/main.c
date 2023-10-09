/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include <linux/slab.h>
#include <linux/types.h>
#include "aesdchar.h"
#include "aesd_ioctl.h"

int aesd_major = 0; // use dynamic major
int aesd_minor = 0;

MODULE_AUTHOR("ming-tsan peng"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    struct aesd_dev *dev; /* device information */

    PDEBUG("MAIN.c: Open");
    /**
     * TODO: handle open
     */

    // Get the device structure from the inode private data
    dev = container_of(inode->i_cdev, struct aesd_dev, cdev);

    // Store the device structure in the file private data
    filp->private_data = dev;

    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("MAIN.c: Release");
    /**
     * TODO: handle release
     */

    return 0;
}

loff_t aesd_llseek(struct file *filp, loff_t off, int whence)
{
    uint8_t index;
    struct aesd_dev *dev = filp->private_data;
    loff_t retval;
    loff_t buffer_size = 0;

    if (mutex_lock_interruptible(&(dev->lock)))
        return -ERESTARTSYS;

    switch (whence) {

    // Use specified offset as file position
    case SEEK_SET: 
        retval = off;
        PDEBUG("MAIN.c: SEEK_SET set the offset to %lld\n", retval);
        break;

    // Increment or decrement file position
    case SEEK_CUR: 
        retval = filp->f_pos + off;
        PDEBUG("MAIN.c: SEEK_CUR set the offset to %lld\n", retval);
        break;

    // Use EOF as file position
    case SEEK_END: 
        for (index = 0; index < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
             index++) {
            if (dev->circbuf.entry[index].buffptr) {
                buffer_size += dev->circbuf.entry[index].size;
            }
        }
        retval = buffer_size + off;
        PDEBUG("MAIN.c: SEEK_END set the offset to %lld\n", retval);
        break;

    default:
        retval = -EINVAL;
        mutex_unlock(&(dev->lock));
        return retval;
    }

    if (retval < 0) {
        PDEBUG("MAIN.c: Invalid arguments. Offset cannot be set to %lld\n", retval);
        retval = -EINVAL;
        mutex_unlock(&(dev->lock));
        return retval;
    }

    filp->f_pos = retval;
    mutex_unlock(&(dev->lock));
    return retval;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos)
{
    ssize_t ss_retval = 0;
    struct aesd_dev *s_dev_p = filp->private_data;
    struct aesd_buffer_entry *s_entry_p;
    size_t us_entry_offset;
    size_t us_rcnt;

    PDEBUG("MAIN.c: Read %zu bytes with offset %lld", count, *f_pos);
    /**
     * TODO: handle read
     */

    // Check for interrupt
    if (mutex_lock_interruptible(&(s_dev_p->lock)))
    {
        return -ERESTARTSYS;
    }

    // Read circular buffer
    s_entry_p = aesd_circular_buffer_find_entry_offset_for_fpos(&(s_dev_p->circbuf), *f_pos, &us_entry_offset);
    
    // Check if data in the buffer
    if (!s_entry_p)
    {
        ss_retval = 0;

        // Unlock the device (release the mutex)
        mutex_unlock(&(s_dev_p->lock));

        return ss_retval;
    }
    PDEBUG("MAIN.c: SUCCESS read: %s", s_entry_p->buffptr);

    // Begin copy to buf
    us_rcnt = s_entry_p->size - us_entry_offset;

    // Check if there are bytes of data that were not copied over. On success should be zero.
    if (copy_to_user(buf, &s_entry_p->buffptr[us_entry_offset], us_rcnt))
    {
        ss_retval = -EFAULT;
        mutex_unlock(&(s_dev_p->lock));
        return ss_retval;
    }
    *f_pos += us_rcnt;
    ss_retval = us_rcnt;

    // Unlock the device (release the mutex)
    mutex_unlock(&(s_dev_p->lock));
    return ss_retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                   loff_t *f_pos)
{
    ssize_t ss_retval = -EFAULT;
    struct aesd_dev *s_dev_p = filp->private_data;
    struct command_buffer *s_cmd_p = &(s_dev_p->cmd);
    struct aesd_buffer_entry s_entry;
    char *buffptr;
    const char *u8_buffptr_rtn_p;

    PDEBUG("write %zu bytes with offset %lld", count, *f_pos);
    /**
     * TODO: handle write
     */

    // Check for interrupt
    if (mutex_lock_interruptible(&(s_dev_p->lock)))
    {
        return -ERESTARTSYS;
    }

    // Copy from user space
    if (copy_from_user(&(s_cmd_p->buf[s_cmd_p->size]), buf, count))
    {
        ss_retval = -EFAULT;
        mutex_unlock(&(s_dev_p->lock));
        return ss_retval;
    }
    s_cmd_p->size += count;
    PDEBUG("MAIN.c: CMD write %zu %s", s_cmd_p->size, s_cmd_p->buf);

    // Check for new line character
    if (s_cmd_p->buf[s_cmd_p->size - 1] != '\n')
    {
        ss_retval = count;
        *f_pos += count;

        // Unlock the device (release the mutex)
        mutex_unlock(&(s_dev_p->lock));
        return ss_retval;
    }

    // Write to circular buffer 
    buffptr = kmalloc(s_cmd_p->size, GFP_KERNEL);
    if (!buffptr)
    {
        ss_retval = -ENOMEM;
        mutex_unlock(&(s_dev_p->lock));
        return ss_retval;
    }
    memcpy(buffptr, s_cmd_p->buf, s_cmd_p->size);
    PDEBUG("MAIN.c: Write CMD @ %p", buffptr);
    s_entry.buffptr = buffptr;
    s_entry.size = s_cmd_p->size;
    u8_buffptr_rtn_p = aesd_circular_buffer_add_entry(&(s_dev_p->circbuf), &s_entry);
    if (u8_buffptr_rtn_p)
    {
        PDEBUG("MAIN.c: Release CMD @ %p", u8_buffptr_rtn_p);
        kfree(u8_buffptr_rtn_p);
    }
    PDEBUG("MAIN.c: Circbuf write %zu %s", s_entry.size, s_entry.buffptr);
    s_cmd_p->size = 0;

    ss_retval = count;
    *f_pos += count;
    mutex_unlock(&(s_dev_p->lock));
    return ss_retval;
}

/**
 * Adjust the file offset (f_pos) parameter of @param filp based on the location specified by
 * @param write_cmd (the zero referenced command to locate)
 * and @param write_cmd_offset (the zero referenced offset into the command)
 * @return 0 if successful, negative if error occured:
 *      -ERESTARTSYS if mutex could not be obtained
 *      -EINVAL if @param write_cmd or @param write_cmd_offset is out of range
 */
static long aesd_adjust_file_offset(struct file *filp, unsigned int write_cmd, unsigned int write_cmd_offset)
{
    struct aesd_dev *s_dev_p = filp->private_data;
    int retval = 0;
    loff_t fpos;

    if (mutex_lock_interruptible(&(s_dev_p->lock)))
    {
        return -ERESTARTSYS;
    }

    fpos = aesd_circular_buffer_get_fpos(&(s_dev_p->circbuf), write_cmd, write_cmd_offset);
    if (fpos < 0)
    {
        retval = -EINVAL;
    }
    else
    {
        filp->f_pos = fpos;
    }

    mutex_unlock(&(s_dev_p->lock));

    PDEBUG("MAIN.c: adjust_file_offset: fpos: %lld", filp->f_pos);

    return retval;
}

long aesd_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    int retval = -ENOTTY;
    struct aesd_seekto seekto;

    PDEBUG("MAIN.c: ioctl");

    switch (cmd)
    {
    case AESDCHAR_IOCSEEKTO:
        if (copy_from_user(&seekto, (const void __user *)arg, sizeof(seekto)) != 0)
        {
            retval = -EFAULT;
        }
        else
        {
            PDEBUG("MAIN.c: ioctl AESDCHAR_IOCSEEKTO:%d,%d", seekto.write_cmd, seekto.write_cmd_offset);
            retval = aesd_adjust_file_offset(filp, seekto.write_cmd, seekto.write_cmd_offset);
        }
        break;
    default:
        retval = -ENOTTY;
    }

    return retval;
}

struct file_operations aesd_fops = {
    .owner = THIS_MODULE,
    .llseek = aesd_llseek,
    .read = aesd_read,
    .write = aesd_write,
    .unlocked_ioctl = aesd_ioctl,
    .open = aesd_open,
    .release = aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add(&dev->cdev, devno, 1);
    if (err)
    {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}

int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1, "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0)
    {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device, 0, sizeof(struct aesd_dev));

    /**
     * TODO: initialize the AESD specific portion of the device
     */
    aesd_circular_buffer_init(&(aesd_device.circbuf));
    aesd_device.cmd.size = 0;
    mutex_init(&aesd_device.lock);

    result = aesd_setup_cdev(&aesd_device);
    if (result)
    {
        unregister_chrdev_region(dev, 1);
    }

    return result;
}

void aesd_cleanup_module(void)
{
    uint8_t index;
    struct aesd_buffer_entry *entryptr;

    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    /**
     * TODO: cleanup AESD specific poritions here as necessary
     */
    AESD_CIRCULAR_BUFFER_FOREACH(entryptr, &aesd_device.circbuf, index)
    {
        if (entryptr->buffptr)
        {
            PDEBUG("MAIN.c: Cleanup module releasing CMD @ index %d @ address %p", index, entryptr->buffptr);
            kfree(entryptr->buffptr);
        }
    }

    unregister_chrdev_region(devno, 1);
}

module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
