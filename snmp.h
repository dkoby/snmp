/*
 * Jaroj 2018-2020.
 * Auxtoro estas Dmitrij Kobilin. 
 *
 * Nenia rajtigilo ekzistas.
 * Faru bone, ne faru malbone.
 */
#ifndef _SNMP_H
#define _SNMP_H

#include <stdint.h>
/* */
#include "asn.h"
#include "snmp_vars.h"
#include "snmp_buffer.h"

struct snmp_context_t {
    int version;
    enum community_t {
        COMMUNITY_R,
        COMMUNITY_RW,
    } community;
    int command;
    uint32_t requestID;

    int nonRepeaters;
    int maxRepetions;

    int error;
    int errorIndex;

    uint8_t *inputOctet;
    size_t inputLength;

    uint8_t *outBuf;
    size_t outputMaxLength;

    struct snmp_buffer_t memBuffer;
    struct snmp_buffer_t seqBuffer;

    struct snmp_context_pointers_t {
        struct asn_encode_raw_t varBindList;
        struct asn_encode_raw_t requestID;
        struct asn_encode_raw_t errorStatus;
        struct asn_encode_raw_t errorIndex;

        struct asn_encode_raw_t pdu;
        struct asn_encode_raw_t version;
        struct asn_encode_raw_t community;
    } pointers;

    int getNext;
    uint32_t inputOID[ASN_OID_MAX_LEN + 1];
};

size_t snmp_process_packet(struct snmp_context_t *context,
        uint8_t *inBuf, size_t ilen, uint8_t *outBuf, size_t maxOutLen);
int snmp_oid_length(uint32_t *oid);
void snmp_oid_copy(uint32_t *dst, uint32_t *src);

struct snmp_trap_oid_bind_t {
    uint32_t oid[ASN_OID_MAX_LEN + 1];
};

size_t snmp_make_trap(
        struct snmp_context_t *context, const uint32_t *trapOID,
        struct snmp_trap_oid_bind_t *oidList,
        uint8_t *buffer, size_t maxLen);

#define SNMP_ERROR_STATUS_NO_ERROR      0
#define SNMP_ERROR_STATUS_TOO_BIG       1
#define SNMP_ERROR_STATUS_NO_SUCH_NAME  2
#define SNMP_ERROR_STATUS_BAD_VALUE     3
#define SNMP_ERROR_STATUS_READ_ONLY     4
#define SNMP_ERROR_STATUS_GEN_ERR       5

#endif

