/*
 * Jaroj 2018-2023.
 * Auxtoro estas Dmitrij Kobilin. 
 *
 * Nenia rajtigilo ekzistas.
 * Faru bone, ne faru malbone.
 */
#ifndef _SNMP_BUFFER_H
#define _SNMP_BUFFER_H

#include <stdint.h>

#define SNMP_BUFFER_SIZE    2048
struct snmp_buffer_t {
    uint8_t data[SNMP_BUFFER_SIZE];
    size_t cnt;
};

void * snmp_buffer_get(struct snmp_buffer_t *buffer);
size_t snmp_buffer_size(struct snmp_buffer_t *buffer);
size_t snmp_buffer_remain(struct snmp_buffer_t *buffer);
void * snmp_buffer_alloc(struct snmp_buffer_t *buffer, size_t size);
void snmp_buffer_reset(struct snmp_buffer_t *buffer, void *p);
void snmp_buffer_free(struct snmp_buffer_t *buffer, size_t size);
void snmp_buffer_move(struct snmp_buffer_t *dst, struct snmp_buffer_t *src);

#endif

