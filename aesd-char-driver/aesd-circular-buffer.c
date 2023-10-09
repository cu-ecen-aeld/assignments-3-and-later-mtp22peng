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
#else
#include <string.h>
#endif

#include "aesd-circular-buffer.h"

long aesd_circular_buffer_get_fpos(struct aesd_circular_buffer *buffer, unsigned int cmd_index, unsigned int cmd_offset)
{
    uint8_t index;
    uint8_t cmd_index_fpos;
    long fpos = 0;

    if (cmd_index >= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED)
    {
        return -1;
    }

    cmd_index_fpos = (buffer->out_offs + cmd_index) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    if (!(buffer->full) && (cmd_index_fpos >= buffer->in_offs))
    {
        return -1;
    }

    if(cmd_offset >= buffer->entry[cmd_index_fpos].size)
    {
        return -1;
    }

    for (index = buffer->out_offs; index < cmd_index_fpos; index++)
    {
        fpos += buffer->entry[index].size;
    }
    fpos += cmd_offset;

    return fpos;
}

/**
 * @param buffer the buffer of which size is to be return
 * @return size of the @param buffer
 */
size_t aesd_circular_buffer_get_size(struct aesd_circular_buffer *buffer)
{
    uint8_t index = buffer->out_offs;
    size_t size = 0;

    if (buffer->full)
    {
        size += buffer->entry[index].size;
        index = (index + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    }

    while (index != buffer->in_offs)
    {
        size += buffer->entry[index].size;
        index = (index + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    }

    return size;
}

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
                                                                          size_t char_offset, size_t *entry_offset_byte_rtn)
{
    /**
     * TODO: implement per description
     */
    size_t cur_buf_idx;
    struct aesd_buffer_entry *entry;

    if (!buffer->full && (buffer->in_offs == buffer->out_offs))
    {
        /* Empty buffer */
        return NULL;
    }

    cur_buf_idx = buffer->out_offs;
    do
    {
        entry = &buffer->entry[cur_buf_idx];
        cur_buf_idx++;
        cur_buf_idx %= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
        if (char_offset < entry->size)
        {
            *entry_offset_byte_rtn = char_offset;
            return entry;
        }
        else
        {
            char_offset -= entry->size;
        }
    } while (cur_buf_idx != buffer->in_offs);

    return NULL;
}

/**
 * Adds entry @param add_entry to @param buffer in the location specified in buffer->in_offs.
 * If the buffer was already full, overwrites the oldest entry and advances buffer->out_offs to the
 * new start location.
 * Any necessary locking must be handled by the caller
 * Any memory referenced in @param add_entry must be allocated by and/or must have a lifetime managed by the caller.
 * @return NULL or, if an existing entry at out_offs was replaced, the value of buffptr for the entry which was replaced (for use with dynamic memory allocation/free)
 */
const char *aesd_circular_buffer_add_entry(struct aesd_circular_buffer *buffer, const struct aesd_buffer_entry *add_entry)
{
    /**
     * TODO: implement per description
     */
    const char *buffptr_rtn = NULL;

    if (buffer->full)
    {
        buffptr_rtn = buffer->entry[buffer->out_offs].buffptr;
        buffer->out_offs++;
        buffer->out_offs %= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    }
    buffer->entry[buffer->in_offs] = *add_entry;
    buffer->in_offs++;
    buffer->in_offs %= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    if (buffer->in_offs == buffer->out_offs)
    {
        buffer->full = true;
    }

    return buffptr_rtn;
}

/**
 * Initializes the circular buffer described by @param buffer to an empty struct
 */
void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    memset(buffer, 0, sizeof(struct aesd_circular_buffer));
}
