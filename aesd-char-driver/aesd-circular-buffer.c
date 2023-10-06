/**
 * @file aesd-circular-buffer.c
 * @brief Functions and data related to a circular buffer imlementation
 *
 * @author Dan Walkes
 * @date 2020-03-01
 * @copyright Copyright (c) 2020
 *
 */

#ifdef __KERNEL__
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/errno.h>
#else
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#endif

#include "aesd-circular-buffer.h"

/**
 * @param buffer the buffer to search for corresponding offset.  Any necessary locking must be performed by caller.
 * @param char_offset the position to search for in the buffer list, describing the zero referenced
 *      character index if all buffer strings were concatenated end to end
 * @param entry_offset_byte_rtn is a pointer specifying a location to store the byte of the returned aesd_buffer_entry
 *      buffptr member corresponding to char_offset.  This value is only set when a matching char_offset is found
 *      in aesd_buffer.
 * @return the struct aesd_buffer_entry structure representing the position described by char_offset, or
 * NULL if this position is not available in the buffer (not enough data is written).
 */
struct aesd_buffer_entry *aesd_circular_buffer_find_entry_offset_for_fpos(struct aesd_circular_buffer *buffer,
            size_t char_offset, size_t *entry_offset_byte_rtn )
{
    /**
    * TODO: implement per description
    */
    uint8_t entry_idx = buffer->out_offs;
    size_t accummulated_off = 0;

    if (buffer == NULL) {
        return NULL;
    }

    do {
        accummulated_off += buffer->entry[entry_idx].size;
        if (char_offset < accummulated_off) {
            *entry_offset_byte_rtn = char_offset - (accummulated_off - buffer->entry[entry_idx].size);
            return &buffer->entry[entry_idx];
        }
        entry_idx = (entry_idx + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;

    } while (entry_idx != buffer->in_offs);

    return NULL;
}

/**
* Adds entry @param add_entry to @param buffer in the location specified in buffer->in_offs.
* If the buffer was already full, overwrites the oldest entry and advances buffer->out_offs to the
* new start location.
* Any necessary locking must be handled by the caller
* Any memory referenced in @param add_entry must be allocated by and/or must have a lifetime managed by the caller.
*/
void aesd_circular_buffer_add_entry(struct aesd_circular_buffer *buffer, const struct aesd_buffer_entry *add_entry)
{
    /**
    * TODO: implement per description
    */
    struct aesd_buffer_entry* tmp_entry = NULL;

    if (buffer == NULL || add_entry == NULL) {
        return;
    }

#ifdef __KERNEL__
    printk(KERN_DEBUG "Adding new entry to the circular buffer: %p with %ld bytes", add_entry->buffptr, add_entry->size);
#endif
    if (buffer->full) {
#ifdef __KERNEL__
        printk(KERN_DEBUG "Overwriting position in circular buffer");
#endif
        // entries themselves are part of the overall structure, so we just need to free the buffer that contains the command itself
        tmp_entry = &(buffer->entry[buffer->out_offs]);
        if (tmp_entry->buffptr) {
#ifdef __KERNEL__
            kfree(tmp_entry->buffptr);
#else
            free(tmp_entry->buffptr);
#endif
        }
        buffer->out_offs = (buffer->out_offs + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    }

    /* in_offs points to the next position to populate, so simply add the new entry in that position */
    buffer->entry[buffer->in_offs].buffptr = add_entry->buffptr;
    buffer->entry[buffer->in_offs].size = add_entry->size;

    /* now we need to advance the pointer */
    buffer->in_offs = (buffer->in_offs + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;

    if (buffer->in_offs == buffer->out_offs) {
        buffer->full = true;
    }
}

/**
* Initializes the circular buffer described by @param buffer to an empty struct
*/
void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    memset(buffer,0,sizeof(struct aesd_circular_buffer));
}

size_t aesd_circular_buffer_content_length(struct aesd_circular_buffer* buffer) {
    uint8_t index = 0;
    size_t buffer_content_length = 0;

    if (buffer == NULL) {
        return 0;
    }

    index = buffer->out_offs;

    do {
        buffer_content_length += buffer->entry[index].size;
        index = (index + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    } while (index != buffer->in_offs);

    return buffer_content_length;
}

size_t aesd_circular_buffer_find_fpos_at_position(struct aesd_circular_buffer* buffer, uint8_t position, size_t cmd_offs) {

    size_t offset = 0;
    uint8_t counter = 0;
    uint8_t index = 0;

    if (buffer == NULL) {
        return -EINVAL;
    }

    index = buffer->out_offs;

    do {
        if (position == counter) {
            if (cmd_offs <= buffer->entry[index].size) {
                return offset + cmd_offs;
            } else {
                return -EINVAL;
            }
        }
        counter++;
        offset += buffer->entry[index].size;
        index = (index + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    } while (index != buffer->in_offs);

    return -EINVAL;
}
