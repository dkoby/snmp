/*
 * Jaroj 2018-2020.
 * Auxtoro estas Dmitrij Kobilin. 
 *
 * Nenia rajtigilo ekzistas.
 * Faru bone, ne faru malbone.
 */
#include <stdint.h>
#include <string.h>
/* */
#include <btorder.h>
#include <debug.h>
#include <encoding.h>
#include <mdboard.h>
#include <nplib.h>
#include <os.h>
#include <stimer.h>
#include <util.h>
/* */
#include "snmp_vars.h"
/* */
#include "snmp.h"

#if 0
    #define DEBUG(level, fmt, ...) \
        debugPrint(level, "[SNMP AGENT]: " fmt, __VA_ARGS__)
    #define DEBUG_BUFFER(level, buf, len) \
        debugPrintBuffer(level, buf, len)
    #define TOKEN_PRINT(token) asn_token_print(token)
#else
    #define DEBUG(level, fmt, ...)
    #define DEBUG_BUFFER(level, buf, len)
    #define TOKEN_PRINT(token)
#endif

#define DEF_GET_FUNC(name) \
    static int name(const struct snmp_var_bind_t *bind, uint32_t *inputOID, struct asn_token_t *outSyntax)
#define DEF_SET_FUNC(name) \
    static int name(const struct snmp_var_bind_t *bind, uint32_t *inputOID, struct asn_token_t *inSyntax, struct asn_token_t *outSyntax)
#define DEF_HAVE_OID_FUNC(name) \
    static int name(const struct snmp_var_bind_t *bind, uint32_t *inputOID)

#define DOT_PREFIX  1, 3, 6, 1, 4, 1
#define DOT_MICRAN                  DOT_PREFIX, 19707
#define     DOT_MD                                   DOT_MICRAN, 15
/* <== */
#define         DOT_MD11RU_PLUS_4S                       DOT_MD, 1
#define             DOT_CONFIGURATION                             DOT_MD11RU_PLUS_4S, 1
#define                 DOT_SERVICE                                                      DOT_CONFIGURATION, 100
#define                     DOT_NP_ADDRESS                                                                     DOT_SERVICE, 1, 0
#define             DOT_TRAPS                                     DOT_MD11RU_PLUS_4S, 200
#define                 DOT_TRAP_SOURCE                                                  DOT_TRAPS, 100
#define                     DOT_TEST_TRAP                                                              DOT_TRAP_SOURCE, 1

static const uint32_t iso_org_dod_internet_mgmt_mib2_system_sysDescr[]    = {1, 3, 6, 1, 2, 1, 1, 1, 0, ASN_OID_SENTINEL};
static const uint32_t iso_org_dod_internet_mgmt_mib2_system_sysObjectID[] = {1, 3, 6, 1, 2, 1, 1, 2, 0, ASN_OID_SENTINEL};
static const uint32_t iso_org_dod_internet_mgmt_mib2_system_sysUpTime  [] = {1, 3, 6, 1, 2, 1, 1, 3, 0, ASN_OID_SENTINEL};
static const uint32_t dot_md11ruPlus4S[]                                  = {DOT_MD11RU_PLUS_4S, ASN_OID_SENTINEL};
static const uint32_t dot_npAddress[]                                     = {DOT_NP_ADDRESS, ASN_OID_SENTINEL};
       const uint32_t dot_test_trap[]                                     = {DOT_AUAU_TRAP, ASN_OID_SENTINEL};

#define _GE_PORT_NUM    (GE_COUNT + GE_COUNT_BI16)
#define _FE_PORT_NUM    (FE_COUNT + FE_COUNT_BI16)
#define _STM_PORT_NUM   STM_COUNT

static const uint32_t trunkIndexMin[]     = {            1, ASN_OID_SENTINEL};
static const uint32_t trunkIndexMax[]     = {    PPU_COUNT, ASN_OID_SENTINEL};
static const uint32_t e1ChannelMin[]      = {            1, ASN_OID_SENTINEL};
static const uint32_t e1ChannelMax[]      = {E1_CHAN_COUNT, ASN_OID_SENTINEL};
static const uint32_t transitChannelMin[] = {            1, ASN_OID_SENTINEL};
static const uint32_t transitChannelMax[] = {     TR_COUNT, ASN_OID_SENTINEL};
static const uint32_t geChannelMin[]      = {            1, ASN_OID_SENTINEL};
static const uint32_t geChannelMax[]      = { _GE_PORT_NUM, ASN_OID_SENTINEL};
static const uint32_t feChannelMin[]      = {            1, ASN_OID_SENTINEL};
static const uint32_t feChannelMax[]      = { _FE_PORT_NUM, ASN_OID_SENTINEL};
static const uint32_t stmChannelMin[]     = {            1, ASN_OID_SENTINEL};
static const uint32_t stmChannelMax[]     = { _STM_PORT_NUM, ASN_OID_SENTINEL};

//#define STRING_ENCODER_WRKMEM_SIZE    1024
//static uint8_t encoderWrkMem[STRING_ENCODER_WRKMEM_SIZE]; /* NOTE not thread safe, TODO extern (shared) */

static int oid2Index1(uint32_t *inputOID, int *index, int min, int max)
{
    int oidLength;
    int _index;

    oidLength = snmp_oid_length(inputOID);

    _index = inputOID[oidLength - 1] - 1;

    if (_index < min || _index >= max)
        return SNMP_ERROR_STATUS_NO_SUCH_NAME;

    *index = _index;
    return SNMP_ERROR_STATUS_NO_ERROR;
}
DEF_GET_FUNC(getTableIndex1)
{
    int oidLength;
    int index;

    oidLength = snmp_oid_length(inputOID);
    index = inputOID[oidLength - 1];

    if (!asn_encode_integer(outSyntax, index))
        return SNMP_ERROR_STATUS_TOO_BIG;

    return SNMP_ERROR_STATUS_NO_ERROR;
}
DEF_GET_FUNC(getTrunkAlarm)
{
    int oidLength;
    int trunk;
    int value;

    if (oid2Index1(inputOID, &trunk, 0, PPU_COUNT) != SNMP_ERROR_STATUS_NO_ERROR)
        return SNMP_ERROR_STATUS_NO_SUCH_NAME;

    oidLength = snmp_oid_length(inputOID);

    switch (inputOID[oidLength - 2])
    {
        case _TRUNK_ALARM_AUAU:
            value = (fpgabmu.rc_state.sync_ppu >> trunk) & 0x01;
            break;
        case _TRUNK_ALARM_AUTRU:
            value = fpgabmu_get_md_ppu_chanstate(trunk);
            break;
        case _TRUNK_ALARM_TRURCERROR:
            value = ppu[trunk].data.rcerror;
            break;
        case _TRUNK_ALARM_TRUERROR:
            value = ppu[trunk].data.ppuerror;
            break;
        default:
            return SNMP_ERROR_STATUS_NO_SUCH_NAME;
    }

    if (!asn_encode_integer(outSyntax, value))
        return SNMP_ERROR_STATUS_TOO_BIG;

    return SNMP_ERROR_STATUS_NO_ERROR;
}
DEF_GET_FUNC(getE1State)
{
    int oidLength;
    int index;
    int value;

    if (oid2Index1(inputOID, &index, 0, E1_CHAN_COUNT) != SNMP_ERROR_STATUS_NO_ERROR)
        return SNMP_ERROR_STATUS_NO_SUCH_NAME;

    oidLength = snmp_oid_length(inputOID);
    switch (inputOID[oidLength - 2])
    {
        case _E1_STATE:
            value = (e1state.value >> (index * 2)) & 0x03;
            break;
        default:
            return SNMP_ERROR_STATUS_NO_SUCH_NAME;
    }

    if (!asn_encode_integer(outSyntax, value))
        return SNMP_ERROR_STATUS_TOO_BIG;

    return SNMP_ERROR_STATUS_NO_ERROR;
}
DEF_GET_FUNC(getTransitState)
{
    int oidLength;
    int index;
    int value;

    if (oid2Index1(inputOID, &index, 0, TR_COUNT) != SNMP_ERROR_STATUS_NO_ERROR)
        return SNMP_ERROR_STATUS_NO_SUCH_NAME;

    oidLength = snmp_oid_length(inputOID);
    switch (inputOID[oidLength - 2])
    {
        case _TRANSIT_STATE:
            value = 0;
            if (fpgabmu.tr_state.error & (1 << index))
                value = 0x03;
            else if (fpgabmu.tr_state.sync & (1 << index))
                value = 0x01;
            break;
        default:
            return SNMP_ERROR_STATUS_NO_SUCH_NAME;
    }

    if (!asn_encode_integer(outSyntax, value))
        return SNMP_ERROR_STATUS_TOO_BIG;

    return SNMP_ERROR_STATUS_NO_ERROR;
}
DEF_HAVE_OID_FUNC(haveGE)
{
    int index;
    int boardHaveGEPort[_GE_PORT_NUM];

    if (oid2Index1(inputOID, &index, 0, _GE_PORT_NUM) != SNMP_ERROR_STATUS_NO_ERROR)
        return SNMP_ERROR_STATUS_NO_SUCH_NAME;

    memset(boardHaveGEPort, 0, sizeof(int) * _GE_PORT_NUM);
    boardHaveGEPort[0] = BOARD_HAVE_4G() || BOARD_HAVE_2G();
    boardHaveGEPort[1] = BOARD_HAVE_4G() || BOARD_HAVE_2G();
    boardHaveGEPort[2] = BOARD_HAVE_4G();
    boardHaveGEPort[3] = BOARD_HAVE_4G();
    boardHaveGEPort[4] = BI24_TYPE_16E4ETH();

    if (!boardHaveGEPort[index])
        return SNMP_ERROR_STATUS_NO_SUCH_NAME;

    return SNMP_ERROR_STATUS_NO_ERROR;
}
DEF_GET_FUNC(getGeLink)
{
    int oidLength;
    int index;
    int value;

    if (oid2Index1(inputOID, &index, 0, _GE_PORT_NUM) != SNMP_ERROR_STATUS_NO_ERROR)
        return SNMP_ERROR_STATUS_NO_SUCH_NAME;

    oidLength = snmp_oid_length(inputOID);
    switch (inputOID[oidLength - 2])
    {
        case _GE_LINK:
            if (index < GE_COUNT)
                value = (gestate.ge_link.link >> index) & 0x01;
            else
                value = gestate.ge_link_bi16;
            break;
        default:
            return SNMP_ERROR_STATUS_NO_SUCH_NAME;
    }

    if (!asn_encode_integer(outSyntax, value))
        return SNMP_ERROR_STATUS_TOO_BIG;

    return SNMP_ERROR_STATUS_NO_ERROR;
}
DEF_HAVE_OID_FUNC(haveFE)
{
    int index;

    if (oid2Index1(inputOID, &index, 0, _FE_PORT_NUM) != SNMP_ERROR_STATUS_NO_ERROR)
        return SNMP_ERROR_STATUS_NO_SUCH_NAME;

    if (index >= FE_COUNT && !BI24_TYPE_16E4ETH())
        return SNMP_ERROR_STATUS_NO_SUCH_NAME;

    return SNMP_ERROR_STATUS_NO_ERROR;
}
DEF_GET_FUNC(getFeLink)
{
    int oidLength;
    int index;
    int value;

    if (oid2Index1(inputOID, &index, 0, FE_COUNT + FE_COUNT_BI16) != SNMP_ERROR_STATUS_NO_ERROR)
        return SNMP_ERROR_STATUS_NO_SUCH_NAME;

    oidLength = snmp_oid_length(inputOID);
    switch (inputOID[oidLength - 2])
    {
        case _FE_LINK:
            if (index < FE_COUNT)
                value = fpgabmu.fe_control.fe[index].link;
            else
                value = fpgabi24.fe_control.fe[index - FE_COUNT].link;
            break;
        default:
            return SNMP_ERROR_STATUS_NO_SUCH_NAME;
    }

    if (!asn_encode_integer(outSyntax, value))
        return SNMP_ERROR_STATUS_TOO_BIG;

    return SNMP_ERROR_STATUS_NO_ERROR;
}
DEF_HAVE_OID_FUNC(haveSTM)
{
    int index;
    int boardHaveSTMPort[_GE_PORT_NUM];

    if (oid2Index1(inputOID, &index, 0, _STM_PORT_NUM) != SNMP_ERROR_STATUS_NO_ERROR)
        return SNMP_ERROR_STATUS_NO_SUCH_NAME;

    memset(boardHaveSTMPort, 0, sizeof(int) * _STM_PORT_NUM);
    boardHaveSTMPort[0] = BOARD_HAVE_4S();
    boardHaveSTMPort[1] = BOARD_HAVE_4S();
    boardHaveSTMPort[2] = BOARD_HAVE_4S() || BOARD_HAVE_2S();
    boardHaveSTMPort[3] = BOARD_HAVE_4S() || BOARD_HAVE_2S();

    if (!boardHaveSTMPort[index])
        return SNMP_ERROR_STATUS_NO_SUCH_NAME;

    return SNMP_ERROR_STATUS_NO_ERROR;
}
DEF_GET_FUNC(getStmPortState)
{
    int oidLength;
    int index;
    int value;

    if (oid2Index1(inputOID, &index, 0, _STM_PORT_NUM) != SNMP_ERROR_STATUS_NO_ERROR)
        return SNMP_ERROR_STATUS_NO_SUCH_NAME;

    oidLength = snmp_oid_length(inputOID);
    switch (inputOID[oidLength - 2])
    {
        case _STM_PORTSTATE:
            if (fpgabmu.sfp_state.sfp_notpresent_ge & (1 << index))
                value = 255;
            else
                value = fpga_bmu_get_sfp_port_state(index);
            break;
        default:
            return SNMP_ERROR_STATUS_NO_SUCH_NAME;
    }

    if (!asn_encode_integer(outSyntax, value))
        return SNMP_ERROR_STATUS_TOO_BIG;

    return SNMP_ERROR_STATUS_NO_ERROR;
}

DEF_GET_FUNC(getOID)
{
    if (bind->context == NULL)
        return SNMP_ERROR_STATUS_GEN_ERR;

    if (!asn_encode_object_identifier(outSyntax, (uint32_t *)bind->context))
        return SNMP_ERROR_STATUS_TOO_BIG;

    return SNMP_ERROR_STATUS_NO_ERROR;
}
DEF_GET_FUNC(getOctetString)
{
    if (bind->oid == dot_e1StateIntegral)
    {
        int i;
        uint64_t value;

        value = 0;
        for (i = 0; i < E1_CHAN_COUNT; i++)
        {
            if (pconfig->e1control.value & (0x03ull << (i * 2)))
            {
                if (e1state.value & (0x02ull << (i * 2)))
                    value |= 0x02ull << (i * 2);
                else if (e1state.value & (0x01ull << (i * 2)))
                    value |= 0x01ull << (i * 2);
            }
        }
#define _E1INT_BYTE_STRING_LENGTH   ((E1_CHAN_COUNT * 2) / 8)
        util_swapb2((uint8_t*)&value, _E1INT_BYTE_STRING_LENGTH);

        if (!asn_encode_octet_string(outSyntax, (uint8_t*)&value, _E1INT_BYTE_STRING_LENGTH))
            return SNMP_ERROR_STATUS_TOO_BIG;
    } else {
        if (bind->context == NULL)
            return SNMP_ERROR_STATUS_GEN_ERR;
        if (!asn_encode_octet_string0(outSyntax, (uint8_t *)bind->context))
            return SNMP_ERROR_STATUS_TOO_BIG;
    }

    return SNMP_ERROR_STATUS_NO_ERROR;
}
DEF_GET_FUNC(getUpTime)
{
    outSyntax->class_ = ASN1_IDENTIFIER_CLASS_APPLICATION;
    outSyntax->tag    = 3;
    if (!asn_encode_integer_idn(outSyntax, stimer_gettime() / 10))
        return SNMP_ERROR_STATUS_TOO_BIG;
    return SNMP_ERROR_STATUS_NO_ERROR;
}

DEF_GET_FUNC(getInteger)
{
    int value;
    if (bind->oid == dot_npAddress) {
        value = SELFADDR;
    } else if (bind->oid == dot_qpskState) {
        if (BER_QPSK->ber1s < BER_QPSK_ERROR_THRESH)
            value = 1;
        else
            value = 0;
    } else if (bind->oid == dot_ethernetState) {
        value = eth_getLinkState();
    } else if (bind->oid == dot_usbState) {
        value = usb_getLinkState();
    } else {
        return SNMP_ERROR_STATUS_NO_SUCH_NAME;
    }

    if (!asn_encode_integer(outSyntax, value))
        return SNMP_ERROR_STATUS_TOO_BIG;

    return SNMP_ERROR_STATUS_NO_ERROR;
}
DEF_SET_FUNC(setInteger)
{
    if (bind->oid == dot_npAddress) {
        int value;
        if (!(
            inSyntax->class_ == ASN1_IDENTIFIER_CLASS_UNIVERSAL &&
            inSyntax->tag == ASN1_IDENTIFIER_TAG_INTEGER
            && inSyntax->constructed == 0
            ))
        {
            return SNMP_ERROR_STATUS_BAD_VALUE;
        }

        value = inSyntax->content.integer;
        if (value < NP_ADDR_MIN || value > NP_ADDR_MAX)
            return SNMP_ERROR_STATUS_BAD_VALUE;

        config_write_npaddr(value);
    } else {
        return SNMP_ERROR_STATUS_NO_SUCH_NAME;
    }

    return getInteger(bind, inputOID, outSyntax);
}


/*
 * NOTE This table must be sorted by OID in ascending order.
 */
struct snmp_var_bind_t snmpVarBind[] = {
    {iso_org_dod_internet_mgmt_mib2_system_sysDescr      , NULL              , NULL              , NULL        , getOctetString             , NULL                       , NULL, "MD1-1RU+4S SNMP agent"},
    {iso_org_dod_internet_mgmt_mib2_system_sysObjectID   , NULL              , NULL              , NULL        , getOID                     , NULL                       , NULL, (void*)dot_md11ruPlus4S},
    {iso_org_dod_internet_mgmt_mib2_system_sysUpTime     , NULL              , NULL              , NULL        , getUpTime                  , NULL                       , NULL, NULL},
    {dot_npAddress                                       , NULL              , NULL              , NULL        , getInteger                 , setInteger                 , NULL, NULL},
    {NULL, NULL, NULL, NULL, NULL, NULL, NULL},
};

#define TRAP_OID_LIST_SIZE  32
#define TRAP_BUFFER_SIZE    512

static struct snmp_trap_oid_bind_t trapOIDList[TRAP_OID_LIST_SIZE];
static uint8_t trapBuffer[TRAP_BUFFER_SIZE];
static struct snmp_context_t trapContext;
static BASE_TYPE trapMutex;
#define TRAP_MUTEX   (1 << 0)

/*
 * ARGS
 *     trapEventArg   From event function.
 *     trapArg        From event table.
 */
TRAP_EVENT_FUNC_DEF(snmpTrapTest)
{
    uint32_t trunk;
    size_t rlen;
    struct snmp_trap_oid_bind_t *oidList;
    uint32_t *trapInfo;
    const uint32_t *trapSource;

    trapSource = (const uint32_t *)trapEventArg;

    trapOIDList[0].oid[0] = ASN_OID_SENTINEL; /* NOTE reset list */
    oidList = trapOIDList;

    /* NOTE List must not exceed TRAP_OID_LIST_SIZE */
    {
        int oidLength;

        /* dot_npAddress */
        snmp_oid_copy(oidList->oid, (uint32_t *)dot_npAddress);
        oidList++;

#if 0
        snmp_oid_copy(oidList->oid, trapInfo);
        oidLength = snmp_oid_length(oidList->oid);
        oidList->oid[oidLength + 0] = trunk;
        oidList->oid[oidLength + 1] = ASN_OID_SENTINEL;
        oidList++;
#endif
    }

    oidList->oid[0] = ASN_OID_SENTINEL;

    rlen = snmp_make_trap(&trapContext, trapSource,
            trapOIDList, trapBuffer, TRAP_BUFFER_SIZE);
    if (rlen)
        snmp_agent_addTrap(trapBuffer, rlen);
}

