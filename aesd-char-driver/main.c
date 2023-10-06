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
#include <linux/moduleparam.h>
#include <linux/init.h>

#include <linux/kernel.h> // supposedly for printk()
#include <linux/types.h>  // dev_t
#include <linux/errno.h>  // error codes
#include <linux/fs.h>     // file_operations
#include <linux/slab.h>   // supposedly for kmalloc(), krealloc() (we also have krealloc() in kernel space)
#include <linux/fcntl.h>  // O_ACCMODE

#include "aesdchar.h"
#include "aesd_ioctl.h"

static int aesd_char_major = AESD_CHAR_MAJOR;
static int aesd_char_minor = 0;
static int aesd_char_num_devs = AESD_CHAR_NUM_DEVS;

module_param(aesd_char_major, int, S_IRUGO);
module_param(aesd_char_minor, int, S_IRUGO);
module_param(aesd_char_num_devs, int, S_IRUGO);

MODULE_AUTHOR("Ming-tsan Peng"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev *aesd_device; // allocated and initialized in the init method
struct file_operations aesd_fops = {
    .owner = THIS_MODULE,
    .llseek = aesd_llseek,
    .read = aesd_read,
    .write = aesd_write,
    .unlocked_ioctl = aesd_unlocked_ioctl,
    .open = aesd_open,
    .release = aesd_release,
};

void print_circular_buffer_content(struct aesd_circular_buffer* buffer) {
    struct aesd_buffer_entry* entry = NULL;
    size_t index = 0;
    char tmp_buffer[512] = { 0 };

    AESD_CIRCULAR_BUFFER_FOREACH(entry, aesd_device->data, index)
    {
        if (entry)
        {
            memset(tmp_buffer, 0, sizeof(tmp_buffer));
            memcpy(tmp_buffer, entry->buffptr, (512 - entry->size) > 1 ? entry->size : 511);
            PDEBUG("Entry with %ld bytes string at %p, with contents %s", entry->size, entry->buffptr, tmp_buffer);
        }
    }

}

// char* temporary_command_buffer = NULL;
// size_t current_temporary_buffer_size  = 0;

int aesd_open(struct inode *inode, struct file *filp)
{
    struct aesd_dev *dev;
    /**
     * TODO: handle open
     */
    PDEBUG("aesd_open");
    dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
    filp->private_data = dev;
    PDEBUG("we retrieved the pointer to our aesd_device struct: %p, pointing to an area of %ld bytes", dev, sizeof(*dev));

    /* no idea if I really need to do this, but scull driver example dies, so...*/
    /* trim device length to 0 if opened as write only */
    // if ((filp->f_flags & O_ACCMODE) == O_WRONLY) {
    //     if (mutex_lock_interruptible(&dev->lock)) {
    //         return -ERESTARTSYS;
    //     }
    //     mutex_unlock(&dev->lock);
    // }
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("aesd_release");
    /**
     * TODO: handle release
     */
    return 0;
}

loff_t aesd_llseek(struct file *filp, loff_t off, int whence) {
    
    struct aesd_dev* dev = filp->private_data;
    size_t circular_buffer_length = 0;
    const char* whence_str = NULL;
    loff_t new_off = 0;
    
    if (mutex_lock_interruptible(&dev->lock)) {
        return -ERESTARTSYS;
    }
    circular_buffer_length = aesd_circular_buffer_content_length(dev->data);

    switch (whence) {
        case SEEK_SET:
            /* if (off >= 0 && off < circular_buffer_length) {
                filp->f_pos = off;
            } else {
                return -EINVAL;
            } */
            whence_str = "SEEK_SET";
            break;
        case SEEK_END:
            /* if ((circular_buffer_length + off >= 0) && (circular_buffer_length + off < circular_buffer_length)) {
                filp->f_pos = circular_buffer_length + off;
            } else {
                return -EINVAL;
            } */
            whence_str = "SEEK_END";
            break;
        case SEEK_CUR:
            /* if ((filp->f_pos + off >= 0) && (filp->f_pos + off < circular_buffer_length)) {
                filp->f_pos += off;
            } else {
                return -EINVAL;
            } */
            whence_str = "SEEK_CUR";
            break;
        default:
            whence_str = "UNSUPPORTED";
            return -EINVAL;
    }

    if (circular_buffer_length) {
        new_off = fixed_size_llseek(filp, off, whence, circular_buffer_length);
    } else {
        new_off = -EINVAL;
    }
    PDEBUG("llseek with offset %lld and whence %s, current file offset is %lld", off, whence_str, filp->f_pos);

    //offset = fixed_size_llseek(filp, off, whence, circular_buffer_length);
    //PDEBUG("aesd_llseek: buffer size is %ld and offset returned by fixed_size_llseek is %lld and new filp->f_pos is %lld", circular_buffer_length, offset, filp->f_pos);

    mutex_unlock(&dev->lock);
    return new_off;

}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos)
{
    ssize_t read_count = 0;
    ssize_t transfer_size = 0;
    ssize_t num_bytes_to_read = 0;
    struct aesd_buffer_entry* buffentry = NULL;
    struct aesd_dev* dev = filp->private_data;
    size_t entry_offset = 0;
    size_t circular_buffer_length = 0;
    /* For DEBUG purposes only */

    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);
    print_circular_buffer_content(dev->data);

    if (mutex_lock_interruptible(&dev->lock)) {
        return -ERESTARTSYS;
    }

    /* get current size of all entries in the circular buffer */
    circular_buffer_length = aesd_circular_buffer_content_length(dev->data);    // need to lock before I get this, cause a write to the buffer can change it
    num_bytes_to_read = min(circular_buffer_length - (long unsigned int)(*f_pos), count);   // consider current buffer length to calculate the actual number of bytes that will be read
    PDEBUG("aesd_read: overall circular buffer length is %ld from which we'll read %ld bytes", circular_buffer_length, num_bytes_to_read);

    if (num_bytes_to_read) {
        while (read_count < num_bytes_to_read) {
            PDEBUG("aesd_read: read loop, read so far %zu, real count %zu, *f_pos %lld", read_count, num_bytes_to_read, *f_pos);
            
            buffentry = aesd_circular_buffer_find_entry_offset_for_fpos(dev->data, *f_pos, &entry_offset);
            if (buffentry) {
                PDEBUG("Found a buffer entry for offset %lld, with size %zu and contents %s.", *f_pos, buffentry->size, buffentry->buffptr + entry_offset);
                PDEBUG("Will copy %zu bytes to %p", (num_bytes_to_read - read_count) > buffentry->size - entry_offset ? buffentry->size - entry_offset : num_bytes_to_read - read_count, buf + read_count);

                /* we will always honor read requests, even if the buffer does not contain the full set of bytes requested */
                transfer_size = (num_bytes_to_read - read_count) > buffentry->size - entry_offset ? buffentry->size - entry_offset : num_bytes_to_read - read_count;
                if (copy_to_user(buf + read_count, buffentry->buffptr + entry_offset, transfer_size)) {
                    mutex_unlock(&dev->lock);
                    return -EFAULT;
                }
                read_count += transfer_size;
                *f_pos += transfer_size;
            } else {
                /* we got to the end of the circular buffer before retrieving count bytes, so parcial read... must return */
                PDEBUG("Reached the end of the buffer before copying all requested bytes: %zu were requested, %zu were copied", num_bytes_to_read, read_count);
                break;
            }
        }
    }
    PDEBUG("Returning %ld bytes read", read_count);
    mutex_unlock(&dev->lock);
    return read_count;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos)
{
    // ssize_t retval = 0;
    char* buffer = NULL;
    struct aesd_buffer_entry buffentry = { 0 };
    struct aesd_dev* dev = filp->private_data;
    size_t idx = 0;
    size_t off = 0;
    size_t wrote_bytes = 0;

    PDEBUG("write %zu bytes with file offset %lld, but will ignore the offset", count, *f_pos);
    /**
     * TODO: handle write
     */

    /* 1. Let's check if incoming data contains a command terminator at some point... */
    while (idx + off < count)
    {
        if (buf[idx + off] == '\n')
        {
            PDEBUG("aesd_write: at least one command terminator found in this input chunk");
            /* At least one command terminator was found at position idx, so let's copy over that specific chunk into temporary buffer, add it to the circular buffer */
            /* and then resize the buffer to hold the remaining of the input (and then loop again just in case multiple command in same write)*/
            /* 1. Now let's use krealloc to allocate/reallocate that buffer to be able to also hold the current chunk of bytes being written */
            if (mutex_lock_interruptible(&dev->lock)) {
                return -ERESTARTSYS;
            }
            PDEBUG("Prior to reallocation, temporary_command_buffer was at %p with length %ld", dev->temporary_command_buffer, dev->current_temporary_buffer_size);
            buffer = krealloc(dev->temporary_command_buffer, dev->current_temporary_buffer_size + idx + 1, GFP_KERNEL);
            if (buffer)
            {
                dev->temporary_command_buffer = buffer;
                PDEBUG("aesd_write: (re)allocated %ld bytes at %p", dev->current_temporary_buffer_size + idx + 1, dev->temporary_command_buffer);

                /* 2. If everything went fine with the allocation, let's copy the incoming buffer into our kernel space buffer*/
                if (copy_from_user(dev->temporary_command_buffer + dev->current_temporary_buffer_size, buf + off, idx + 1)) {
                    mutex_unlock(&dev->lock);
                    return -EFAULT;
                }
                PDEBUG("Copied %ld bytes from position %ld of input buffer to position %ld of internal buffer", idx + 1, off, dev->current_temporary_buffer_size);
                dev->current_temporary_buffer_size += idx + 1;

                /* 3. Now push the complete contents of the temporary_command_buffer into a new position of the circular buffer */
                /* TODO */
                /* Populate the allocated circular buffer entry */
                buffentry.buffptr = dev->temporary_command_buffer;
                buffentry.size = dev->current_temporary_buffer_size;
                /* need to use filp to retrieve a pointer to the circular buffer */
                aesd_circular_buffer_add_entry(dev->data, &buffentry);
                wrote_bytes += buffentry.size;
                //*f_pos += buffentry.size;

                dev->temporary_command_buffer = NULL;
                dev->current_temporary_buffer_size = 0;
                /* now advance idx and off to keep looking for command terminators in the input buffer*/
                off = idx + 1;
                idx = 0;
                mutex_unlock(&dev->lock);
            }
            else
            {
                mutex_unlock(&dev->lock);
                printk(KERN_WARNING "Could not allocate/extend buffer to hold incoming command");
                return -ENOMEM;
            }
        }
        else
        {
            PDEBUG("aesd_write: increasing idx value, was %ld", idx);
            idx++;
        }
    }

    if (idx && idx + off == count)
    {
        /* Got to the end of the buf and found not terminator, reallocate temporary buffer, copy over contents and exit */
        PDEBUG("aesd_write: no command terminator found in this input chunk");
        if (mutex_lock_interruptible(&dev->lock)) {
            return -ERESTARTSYS;
        }
        PDEBUG("aesd_write: prior to allocation, temporary_command_buffer was at %p with length %ld", dev->temporary_command_buffer, dev->current_temporary_buffer_size);
        /* 1. Now let's use krealloc to allocate/reallocate that buffer to be able to also hold the current chunk of bytes being written */
        buffer = krealloc(dev->temporary_command_buffer, idx + dev->current_temporary_buffer_size, GFP_KERNEL);
        if (buffer)
        {
            dev->temporary_command_buffer = buffer;
            PDEBUG("aesd_write: (re)allocated %ld bytes at %p", idx + dev->current_temporary_buffer_size, dev->temporary_command_buffer);
            /* 2. If everything went fine with the allocation, let's copy the incoming buffer into our kernel space buffer*/
            if (copy_from_user(dev->temporary_command_buffer + dev->current_temporary_buffer_size, buf + off, idx)) {
                mutex_unlock(&dev->lock);
                return -EFAULT;
            }
            PDEBUG("Copied %ld bytes from position %ld of input buffer to position %ld of internal buffer", idx, off, dev->current_temporary_buffer_size);
            dev->current_temporary_buffer_size += idx;
            mutex_unlock(&dev->lock);
        }
        else
        {
            mutex_unlock(&dev->lock);
            printk(KERN_WARNING "Could not allocate/extend buffer to hold incoming command");
            return -ENOMEM;
        }
    }

    print_circular_buffer_content(dev->data);
    return wrote_bytes;
}

long int aesd_unlocked_ioctl(struct file* filp, unsigned int cmd, unsigned long seekto) {
    struct aesd_dev* dev = filp->private_data;
    struct aesd_seekto seek_data;
    ssize_t offset = 0;

    PDEBUG("On ioctl routine...");
    if (_IOC_TYPE(cmd) != AESD_IOC_MAGIC) {
        return -ENOTTY;
    }
    if (_IOC_NR(cmd) > AESDCHAR_IOC_MAXNR) {
        return -ENOTTY;
    }

    switch (cmd) {
        case AESDCHAR_IOCSEEKTO:
            if (mutex_lock_interruptible(&dev->lock)) {
                return -ERESTARTSYS;
            }
            if (copy_from_user(&seek_data, (struct aesd_seekto*)seekto, sizeof(seek_data))) {
                printk(KERN_WARNING "aesd_unlocked_ioctl: failed to copy from user data");
                mutex_unlock(&dev->lock);
                return -EFAULT;
            }
            
            offset = aesd_circular_buffer_find_fpos_at_position(dev->data, seek_data.write_cmd, seek_data.write_cmd_offset);
            PDEBUG("Found the following offset for command index %d, command offset %d: %ld", seek_data.write_cmd, seek_data.write_cmd_offset, offset);
            if (offset < 0) {
                printk(KERN_WARNING "aesd_unlocked_ioctl: offset not found in circular buffer");
                mutex_unlock(&dev->lock);
                return -EINVAL;
            }
            filp->f_pos = offset;
            mutex_unlock(&dev->lock);
            return 0;
        default:
            break;
    }

    return -EINVAL;
}

static int __init aesd_init_module(void)
{
    dev_t dev = 0;
    int result;

    PDEBUG("aesd_init_module: major=%d (module parameter provided)", aesd_char_major);

    /* this comes directly from scull code, that allows to pass major as parameter */
    if (aesd_char_major)
    {
        PDEBUG("aesd_init_module: on major provided as module parameter branch");
        dev = MKDEV(aesd_char_major, aesd_char_minor);
        result = register_chrdev_region(dev, 1, "aesdchar");
    }
    else
    {
        PDEBUG("aesd_init_module: on major dynamically allocated branch");
        result = alloc_chrdev_region(&dev, aesd_char_minor, 1, "aesdchar");
        aesd_char_major = MAJOR(dev);
    }

    if (result < 0)
    {
        printk(KERN_WARNING "Can't get major %d\n", aesd_char_major);
        return result;
    }

    PDEBUG("aesd_init_module: major in use is %d", aesd_char_major);

    /**
     * TODO: initialize the AESD specific portion of the device
     */
    /* We need to allocate memory for the circular buffer structure in the cdev struct */

    aesd_device = kmalloc(sizeof(struct aesd_dev), GFP_KERNEL);
    if (aesd_device == NULL)
    {
        printk(KERN_WARNING "Failed to allocate kernel memory to hold aesd_dev structure");
        result = -ENOMEM;
        goto failure;
    }
    PDEBUG("aesd_init_module: allocated memory to hold the aesd_device structure at address %p (%ld bytes)", aesd_device, sizeof(struct aesd_dev));
    memset(aesd_device, 0, sizeof(struct aesd_dev));
    mutex_init(&aesd_device->lock);
    aesd_device->data = kmalloc(sizeof(struct aesd_circular_buffer), GFP_KERNEL);
    if (aesd_device->data == NULL)
    {
        printk(KERN_WARNING "Failed to allocate kernel memory to hold circular buffer within aesd device structure");
        result = -ENOMEM;
        goto failure;
    }
    PDEBUG("aesd_init_module: allocated memory to hold the circular buffer structure (%ld bytes)", sizeof(struct aesd_circular_buffer));
    aesd_circular_buffer_init(aesd_device->data);
    PDEBUG("aesd_init_module: how does the circular buffer look like after initialization:");
    print_circular_buffer_content(aesd_device->data);

    cdev_init(&aesd_device->cdev, &aesd_fops);
    aesd_device->cdev.owner = THIS_MODULE;
    result = cdev_add(&aesd_device->cdev, MKDEV(aesd_char_major, 0), 1);

    if (result)
    {
        printk(KERN_WARNING "Failed to initialize cdev structure");
        goto failure;
    }
    PDEBUG("aesd_init_module: module is now active (cdev has been added)");
    return result;

failure:
    aesd_cleanup_module();
    return result;
}

static void aesd_cleanup_module(void)
{
    struct aesd_buffer_entry *entry = NULL;
    uint8_t index;
    dev_t devno = MKDEV(aesd_char_major, aesd_char_minor);

    PDEBUG("aesd_cleanup_module");

    cdev_del(&aesd_device->cdev);

    /**
     * TODO: cleanup AESD specific poritions here as necessary
     */
    if (aesd_device && aesd_device->data)
    {
        /* release memory for all circular buffer nodes */
        AESD_CIRCULAR_BUFFER_FOREACH(entry, aesd_device->data, index)
        {
            PDEBUG("Release entry with %ld bytes string", entry->size);
            /* the number of entries in the circular buffer is fixed, but it might be that not all entries have been */
            /* initialized, hence checking that the pointer are not NULL before freeing */
            /* THIS PART IS NOT YET WORKING GOOD... IT ONLY FREES 7 ENTRIES AND THEN SEGMENTS */
            if (entry && entry->buffptr)
            {
                PDEBUG("Deleting command buffer in entry");
                kfree(entry->buffptr);
            }
        }
        kfree(aesd_device->data);
        PDEBUG("aesd_cleanup_module: released memory for the circular buffer");
    }

    if (aesd_device->temporary_command_buffer)
    {
        kfree(aesd_device->temporary_command_buffer);
        PDEBUG("aesd_cleanup_module: freeing temporary command buffer");
    }

    if (aesd_device)
    {
        mutex_destroy(&aesd_device->lock);
        kfree(aesd_device);

        PDEBUG("aesd_cleanup_module: release memory for the aesd_device structure");
    }


    unregister_chrdev_region(devno, 1);
    PDEBUG("aesd_cleanup_module: module is now removed from kernel");
}

module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
