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


#include "aesd-circular-buffer.h"
#include "aesd_ioctl.h"
#include "aesdchar.h"
#include <asm/uaccess.h>
#include <linux/fs.h> // file_operations
#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/types.h>


int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Ming-tsan Peng"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;



static int aesd_setup_cdev(struct aesd_dev *dev);


int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");
    /**
     * TODO: handle open
     */


struct aesd_dev *dev;

  dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
  filp->private_data = dev;


    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    /**
     * TODO: handle release
     */








    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle read
     */

 struct aesd_dev *dev;
  struct aesd_buffer_entry *entry;
  size_t entry_offset_byte_rtn = 0;

  dev = filp->private_data;
  if (mutex_lock_interruptible(&dev->mut)) {
    return -ERESTARTSYS;
  }
  entry = aesd_circular_buffer_find_entry_offset_for_fpos(
      &dev->buffer, *f_pos, &entry_offset_byte_rtn);
  if (entry == NULL) {
    retval = 0;
    goto out;
  } else {
    retval = entry->size - entry_offset_byte_rtn;
    if (copy_to_user(buf, entry->buffptr + entry_offset_byte_rtn, retval) ==
        0) {
      *f_pos += retval;
    } else {
      PDEBUG("failed copy %lld", *f_pos);
      retval = -EFAULT;
      goto out;
    }
  }
out:
  mutex_unlock(&dev->mut);
  return retval;





}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = -ENOMEM;
    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle write
     */



struct aesd_dev *dev;

  dev = filp->private_data;


if (mutex_lock_interruptible(&dev->mut)) {
    return -ERESTARTSYS;
  }



// allocate memory for write, with written spaceso far  plus to-be-written iength of count 

dev->working_entry.buffptr = krealloc(
      dev->working_entry.buffptr, dev->working_entry.size + count, GFP_KERNEL);



if (dev->working_entry.buffptr) {
  
      


	if (copy_from_user(
            (void *)(dev->working_entry.buffptr + dev->working_entry.size), buf,
            count) == 0) {

	  
	
	//update size after copy from user "buf"
	
	
		dev->working_entry.size += count;
      retval = count;
      /**
       * TODO: cleanup AESD specific poritions here as necessary
       */
      int found_ret = 0;
      int i = 0;
      for (; i < dev->working_entry.size; i++) {
        if (dev->working_entry.buffptr[i] == '\n') {
          found_ret = 1;
          break;
        }
      }
      if (found_ret) {
        const char *buf =
            aesd_circular_buffer_add_entry(&dev->buffer, &dev->working_entry);
        dev->working_entry.size = 0;
        dev->working_entry.buffptr = 0;

        if (buf != NULL) {
          kfree(buf);
        }
      }
    } else {

      retval = -EFAULT;
      PDEBUG("Cannot copy from user");
      goto out;
    }
  } else {
    retval = -EFAULT;
    PDEBUG("Cannot allocate memory");
    goto out;
  }




out:
  mutex_unlock(&dev->mut);
  /**
   * TODO: handle write
   */



    return retval;
}










struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));

    /**
     * TODO: initialize the AESD specific portion of the device
     */

    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    /**
     * TODO: cleanup AESD specific poritions here as necessary
     */

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
