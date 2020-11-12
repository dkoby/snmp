/*
 * Jaroj 2018-2020.
 * Auxtoro estas Dmitrij Kobilin. 
 *
 * Nenia rajtigilo ekzistas.
 * Faru bone, ne faru malbone.
 */
#include <string.h>
/* */
#include "snmp_buffer.h"

/*
 *
 */
void * snmp_buffer_get(struct snmp_buffer_t *buffer)
{
    return buffer->data;
}
/*
 * Get number of used bytes.
 */
size_t snmp_buffer_size(struct snmp_buffer_t *buffer)
{
    return buffer->cnt;
}
/*
 * Get number of remain bytes.
 */
size_t snmp_buffer_remain(struct snmp_buffer_t *buffer)
{
    return (buffer->cnt < SNMP_BUFFER_SIZE) ? (SNMP_BUFFER_SIZE - buffer->cnt) : 0;
}
/*
 *
 */
void * snmp_buffer_alloc(struct snmp_buffer_t *buffer, size_t size)
{
    void *p;

    if ((buffer->cnt + size) > SNMP_BUFFER_SIZE)
        return NULL;

    p = &buffer->data[buffer->cnt];
    buffer->cnt += size;

    return p;
}
/*
 *
 */
void snmp_buffer_reset(struct snmp_buffer_t *buffer, void *p)
{
    if (p == NULL)
    {
        buffer->cnt = 0;
        return;
    }

    if (p > ((void*)buffer->data + SNMP_BUFFER_SIZE))
    {
        /* NOTREACHED */
        return;
    }

    buffer->cnt = ((size_t)p) - ((size_t)buffer->data);
}
/*
 *
 */
void snmp_buffer_free(struct snmp_buffer_t *buffer, size_t size)
{
    /* XXX */
    if (size > buffer->cnt)
    {
        buffer->cnt = 0;
        return;
    }

    buffer->cnt -= size;
}
/*
 * Move buffer one to another, reset source buffer.
 */
void snmp_buffer_move(struct snmp_buffer_t *dst, struct snmp_buffer_t *src)
{
    memcpy(dst->data, src->data, src->cnt);
    dst->cnt = src->cnt;
    src->cnt = 0;
}

