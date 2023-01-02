/*
 * Jaroj 2018-2023.
 * Auxtoro estas Dmitrij Kobilin. 
 *
 * Nenia rajtigilo ekzistas.
 * Faru bone, ne faru malbone.
 */
#ifndef _SNMP_VARS_H
#define _SNMP_VARS_H

#include <stdint.h>
#include "asn.h"

#if 0
    #define CONST_OID const
#else
    #define CONST_OID
#endif

struct snmp_var_bind_t {
    CONST_OID uint32_t *oid;
    const uint32_t *indexMin;
    const uint32_t *indexMax;
    int (*haveOID)(const struct snmp_var_bind_t *bind, uint32_t *inputOID);
    int (*varGet)(const struct snmp_var_bind_t *bind, uint32_t *inputOID, struct asn_token_t *outSyntax);
    int (*varSet)(const struct snmp_var_bind_t *bind, uint32_t *inputOID, struct asn_token_t *inSyntax, struct asn_token_t *outSyntax);
    int (*getData)(void *data, void *buffer);
    void *context;
};

#include "snmp.h"

extern struct snmp_var_bind_t snmpVarBind[];

void snmp_vars_init();

struct snmp_trapExtArg_t {
    const uint32_t *trapSource;
    const uint32_t *trapInfo;
    int index;
};

#define TRAP_EVENT_FUNC_DEF(name) void name(void *trapEventArg, void *trapArg)

TRAP_EVENT_FUNC_DEF(snmpTrapTest);

extern CONST_OID uint32_t dot_test_trap[];

#endif

