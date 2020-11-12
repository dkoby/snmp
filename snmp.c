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
#include <debug.h>
#include <util.h>
#include "asn.h"
#include "snmp.h"
#include "snmp_buffer.h"

#if 0
    #define DEBUG(level, fmt, ...) \
        debugPrint(level, "[SNMP AGENT]: " fmt, __VA_ARGS__)
    #define DEBUG_BUFFER(level, buf, len) \
        debugPrintBuffer(level, buf, len)
    #define TOKEN_PRINT(token) asn_token_print(token)
//    #define OID_PRINT(oid) asn_oid_print(oid)
#else
    #define DEBUG(level, fmt, ...)
    #define DEBUG_BUFFER(level, buf, len)
    #define TOKEN_PRINT(token)
//    #define OID_PRINT(oid)
#endif

#define COMMUNITY_STR_R     "public"
#define COMMUNITY_STR_RW    "private"
#define COMMUNITY_STR_TRAP  COMMUNITY_STR_R

#define PDU_GET_REQUEST          0x00
#define PDU_GET_NEXT_REQUEST     0x01
#define PDU_GET_RESPONSE         0x02
#define PDU_SET_REQUEST          0x03
#define PDU_GET_BULK_REQUEST     0x05
#define PDU_V2_TRAP              0x07

#define SNMP_VERSION1    0
#define SNMP_VERSION2    1

static size_t _process_request(struct snmp_context_t *context);
static int _process_vars(struct snmp_context_t *context);

#if 0
static void _oidPrint(uint32_t *oid)
{
    while (*oid != ASN_OID_SENTINEL)
    {
        dprint("d*.", *oid);
        oid++;
    }
    dprint("sn", "");
}

#define OID_PRINT(oid) _oidPrint(oid)
#else
#define OID_PRINT(oid)
#endif

/*
 *
 */
int _getToken(struct asn_token_t *token, uint8_t *inputOctet, size_t inputLength)
{
    size_t tlen;

    asn_token_init(token, inputOctet, inputLength);
    tlen = asn_token_get(token);
    if (tlen == 0 || tlen > inputLength)
        return -1;

    return 0;
}
/*
 * RETURN
 *     0 on success, -1 on error
 */
int _getSequence(struct asn_token_t *token, uint8_t *inputOctet, size_t inputLength)
{
    if (_getToken(token, inputOctet, inputLength) < 0)
        return -1;
    if (!(
        token->class_ == ASN1_IDENTIFIER_CLASS_UNIVERSAL &&
        token->tag == ASN1_IDENTIFIER_TAG_SEQ_SEQOF &&
        token->constructed))
    {
        return -1;
    }

    return 0;
}
/*
 * RETURN
 *     0 on success, -1 on error
 */
int _getInteger(struct asn_token_t *token,
        uint8_t *inputOctet, size_t inputLength)
{
    if (_getToken(token, inputOctet, inputLength) < 0)
        return -1;
    if (!(
        token->class_ == ASN1_IDENTIFIER_CLASS_UNIVERSAL &&
        token->tag == ASN1_IDENTIFIER_TAG_INTEGER &&
        !token->constructed))
    {
        return -1;
    }

    return 0;
}
/*
 * RETURN
 *     0 on success, -1 on error
 */
int _getOctetString(struct asn_token_t *token,
        uint8_t *inputOctet, size_t inputLength)
{
    if (_getToken(token, inputOctet, inputLength) < 0)
        return -1;
    if (!(
        token->class_ == ASN1_IDENTIFIER_CLASS_UNIVERSAL &&
        token->tag == ASN1_IDENTIFIER_TAG_OCTET_STRING &&
        !token->constructed))
    {
        return -1;
    }

    return 0;
}
/*
 * RETURN
 *     0 on success, -1 on error
 */
int _getObjectIdentifier(struct asn_token_t *token,
        uint8_t *inputOctet, size_t inputLength)
{
    if (_getToken(token, inputOctet, inputLength) < 0)
        return -1;
    if (!(
        token->class_ == ASN1_IDENTIFIER_CLASS_UNIVERSAL &&
        token->tag == ASN1_IDENTIFIER_TAG_OBJECT_IDENTIFIER &&
        !token->constructed))
    {
        return -1;
    }

    return 0;
}
/*
 * RETURN
 *     Packet length of response (zero if nothing to send on response).
 */
size_t snmp_process_packet(struct snmp_context_t *context,
        uint8_t *inBuf, size_t ilen, uint8_t *outBuf, size_t maxOutLen)
{
    struct asn_token_t token;

    DEBUG(DLEVEL_NOISE, "=== Input (%u) ===", ilen);
    DEBUG_BUFFER(DLEVEL_NOISE, inBuf, ilen);

    context->inputOctet  = inBuf;
    context->inputLength = ilen;
    context->outBuf = outBuf;
    context->outputMaxLength = maxOutLen;

    /*
     * Message ::=
     *         SEQUENCE {
     *              version        -- version-1 for this RFC
     *                 INTEGER {
     *                     version-1(0)
     *                 },
     *             community      -- community name
     *                 OCTET STRING,
     *             data           -- e.g., PDUs if trivial
     *                 ANY        -- authentication is being used
     *         }    
     */

    /* SEQUENCE */
    if (_getSequence(&token, context->inputOctet, context->inputLength) < 0)
        goto noresponse;
    context->inputOctet  = token.content.raw;
    context->inputLength = token.content.length;

    /* version */
    if (_getInteger(&token,
                context->inputOctet, context->inputLength) < 0)
        goto noresponse;
    context->version = token.content.integer;
    /* Only version 1 and version 2 of SNMP is supported. */
    if (context->version != SNMP_VERSION1 && context->version != SNMP_VERSION2)
        goto noresponse;
    context->inputOctet  += token.tlen;
    context->inputLength -= token.tlen;

    /* community */
    if (_getOctetString(&token,
                context->inputOctet, context->inputLength) < 0)
        goto noresponse;
    if (strncmp((const char *)token.content.raw, COMMUNITY_STR_R, token.content.length) == 0)
        context->community = COMMUNITY_R;
    else if (strncmp((const char *)token.content.raw, COMMUNITY_STR_RW, token.content.length) == 0)
        context->community = COMMUNITY_RW;
    else
        goto noresponse;
    context->inputOctet  += token.tlen;
    context->inputLength -= token.tlen;

    return _process_request(context);
noresponse:
    return 0;
}
/*
 * RETURN
 *     Packet length of response (zero if nothing to send on response).
 */
static size_t _process_request(struct snmp_context_t *context)
{
    struct asn_token_t token;
    int path;
    size_t rlen;

    rlen = 0;

    context->nonRepeaters = 0;
    context->maxRepetions = 0;

    memset(&context->pointers, 0, sizeof(struct snmp_context_pointers_t));

    /*
     *    PDUs ::=
     *            CHOICE {
     *                get-request
     *                    GetRequest-PDU,
     *                get-next-request
     *                    GetNextRequest-PDU,
     *                get-response
     *                    GetResponse-PDU,
     *                set-request
     *                    SetRequest-PDU,
     *                trap
     *                    Trap-PDU
     *            }
     *
     */

    if (_getToken(&token,
                context->inputOctet, context->inputLength) < 0)
        goto noresponse;
    if (!(token.class_ == ASN1_IDENTIFIER_CLASS_CONTEXT &&
          token.constructed))
        goto noresponse;
    context->command = token.tag;
    switch (context->command)
    {
        case PDU_GET_BULK_REQUEST:
            /* NOTE no BULK request in version 1 of SNMP. */
            if (context->version == SNMP_VERSION1)
                goto noresponse;
        case PDU_GET_REQUEST:
        case PDU_GET_NEXT_REQUEST:
        case PDU_SET_REQUEST:
            break;
        default:
            goto noresponse;
    }
    context->inputOctet  = token.content.raw;
    context->inputLength = token.content.length;

    /*
     *
     *    PDU ::=
     *            SEQUENCE {
     *                request-id
     *                    INTEGER,
     *                error-status      -- sometimes ignored
     *                    INTEGER {
     *                        noError(0),
     *                        tooBig(1),
     *                        noSuchName(2),
     *                        badValue(3),
     *                        readOnly(4),
     *                        genErr(5)
     *                    },
     *                error-index       -- sometimes ignored
     *                   INTEGER,
     *                variable-bindings -- values are sometimes ignored
     *                    VarBindList
     *            }
     *
     */

    /* request-id */
    if (_getInteger(&token,
                context->inputOctet, context->inputLength) < 0)
        goto noresponse;
    context->requestID = token.content.integer;
    context->inputOctet  += token.tlen;
    context->inputLength -= token.tlen;

    if (context->command == PDU_GET_BULK_REQUEST)
    {
        /* non-repeaters */
        if (_getInteger(&token,
                    context->inputOctet, context->inputLength) < 0)
            goto noresponse;
        context->nonRepeaters = token.content.integer;
        context->inputOctet  += token.tlen;
        context->inputLength -= token.tlen;

        /* max-repetions */
        if (_getInteger(&token,
                    context->inputOctet, context->inputLength) < 0)
            goto noresponse;
        context->maxRepetions = token.content.integer;
        context->inputOctet  += token.tlen;
        context->inputLength -= token.tlen;
    } else {
        /* error-status */
        if (_getInteger(&token,
                    context->inputOctet, context->inputLength) < 0)
            goto noresponse;
        if (token.content.integer != SNMP_ERROR_STATUS_NO_ERROR)
            goto noresponse;
        context->inputOctet  += token.tlen;
        context->inputLength -= token.tlen;

        /* error-index */
        if (_getInteger(&token,
                    context->inputOctet, context->inputLength) < 0)
            goto noresponse;
        context->inputOctet  += token.tlen;
        context->inputLength -= token.tlen;
    }

    /*
     *
     *   VarBindList ::=
     *            SEQUENCE OF
     *               VarBind
     */


    /* VarBindList */

    /* SEQUENCE */
    if (_getSequence(&token, context->inputOctet, context->inputLength) < 0)
        goto noresponse;
    context->inputOctet  = token.content.raw;
    context->inputLength = token.content.length;

    /*
     * Reset buffers.
     */
    snmp_buffer_reset(&context->memBuffer, NULL);
    snmp_buffer_reset(&context->seqBuffer, NULL);

    /*
     * Process VarBind one by one.
     */
    do /* while(0) */
    {
        context->error = SNMP_ERROR_STATUS_NO_ERROR;
        context->errorIndex = 0;

        context->error = _process_vars(context);
        if (context->error != SNMP_ERROR_STATUS_NO_ERROR)
        {
            if (context->error == SNMP_ERROR_STATUS_TOO_BIG)
                context->errorIndex = 0;
            break;
        }
        context->errorIndex = 0;

        if (context->error != SNMP_ERROR_STATUS_NO_ERROR)
            break;

#if 0
        DEBUG(DLEVEL_NOISE, "=== BindListBuffer (%u) ===", snmp_buffer_size(&context->seqBuffer));
        DEBUG_BUFFER(DLEVEL_NOISE, snmp_buffer_get(&context->seqBuffer), snmp_buffer_size(&context->seqBuffer));
#else

#endif

        snmp_buffer_reset(&context->memBuffer, NULL);
        /*
         * seqBuffer
         *     VarBind
         *     VarBind
         *     VarBind
         *     ...
         *
         *  memBuffer
         */


        /*
         * Encode VarBindList sequence. 
         */
        {
            uint8_t *buf;
            size_t blen;
            struct asn_encode_raw_t rlist[2];

            blen = snmp_buffer_remain(&context->memBuffer);
            if (!blen)
                goto noresponse;
            buf = snmp_buffer_alloc(&context->memBuffer, blen);
            if (!buf)
                goto noresponse;

            rlist[0].data = snmp_buffer_get(&context->seqBuffer);
            rlist[0].size = snmp_buffer_size(&context->seqBuffer);
            rlist[1].data = NULL;

            asn_token_init(&token, buf, blen);
            if (!asn_encode_sequence_raw(&token, rlist))
            {
                context->error = SNMP_ERROR_STATUS_TOO_BIG;
                break;
            }
            DEBUG(DLEVEL_NOISE, "%s", "varBindList");
            TOKEN_PRINT(&token);
            snmp_buffer_reset(&context->memBuffer, buf + token.tlen);
            context->pointers.varBindList.data = buf;
            context->pointers.varBindList.size = token.tlen;
        }

        /*
         * memBuffer
         *     VarBindList    pointers->varBindList
         */
    } while(0);

    /*
     * Two time path - second path if response too big.
     */
    rlen = 0;
    for (path = 0; path < 2; path++)
    {
        snmp_buffer_reset(&context->seqBuffer, NULL);
        /*
         * seqBuffer
         *
         * memBuffer
         *     VarBindList (if no error).
         */

        if (context->error != SNMP_ERROR_STATUS_NO_ERROR)
        {
            uint8_t *buf;
            size_t blen;
            struct asn_encode_raw_t rlist[0];

            rlist[0].data = NULL;

            snmp_buffer_reset(&context->memBuffer, NULL);
            /*
             * seqBuffer
             *
             * memBuffer
             *
             */

            blen = snmp_buffer_remain(&context->memBuffer);
            if (!blen)
                goto noresponse;
            buf = snmp_buffer_alloc(&context->memBuffer, blen);
            if (!buf)
                goto noresponse;
            asn_token_init(&token, buf, blen);
            if (!asn_encode_sequence_raw(&token, rlist))
                goto noresponse;
            snmp_buffer_reset(&context->memBuffer, buf + token.tlen);
            context->pointers.varBindList.data = buf;
            context->pointers.varBindList.size = token.tlen;
            /*
             * memBuffer
             *     VarBindList (zero length SEQUENCE)    pointers->varBindList
             */
        }

        /*
         * Construct PDU.
         *
         *    PDU ::=
         *            SEQUENCE {
         *                request-id
         *                    INTEGER,
         *                error-status      -- sometimes ignored
         *                    INTEGER {
         *                        noError(0),
         *                        tooBig(1),
         *                        noSuchName(2),
         *                        badValue(3),
         *                        readOnly(4),
         *                        genErr(5)
         *                    },
         *                error-index       -- sometimes ignored
         *                   INTEGER,
         *                variable-bindings -- values are sometimes ignored
         *                    VarBindList
         *            }
         */

        /* request-id */
        {
            uint8_t *buf;
            size_t blen;

            blen = snmp_buffer_remain(&context->memBuffer);
            if (!blen)
                goto noresponse;
            buf = snmp_buffer_alloc(&context->memBuffer, blen);
            if (!buf)
                goto noresponse;

            asn_token_init(&token, buf, blen);
            if (!asn_encode_integer(&token, context->requestID))
                goto noresponse;
            TOKEN_PRINT(&token);
            snmp_buffer_reset(&context->memBuffer, buf + token.tlen);
            context->pointers.requestID.data = buf;
            context->pointers.requestID.size = token.tlen;
            /*
             * memBuffer
             *     VarBindList    pointers->varBindList
             *     request-id     pointers->requestID;
             */
        }
        /* error-status */
        {
            uint8_t *buf;
            size_t blen;

            blen = snmp_buffer_remain(&context->memBuffer);
            if (!blen)
                goto noresponse;
            buf = snmp_buffer_alloc(&context->memBuffer, blen);
            if (!buf)
                goto noresponse;

            asn_token_init(&token, buf, blen);
            if (!asn_encode_integer(&token, context->error))
                goto noresponse;
            TOKEN_PRINT(&token);
            snmp_buffer_reset(&context->memBuffer, buf + token.tlen);
            context->pointers.errorStatus.data = buf;
            context->pointers.errorStatus.size = token.tlen;
            /*
             * memBuffer
             *     VarBindList    pointers->varBindList
             *     request-id     pointers->requestID;
             *     error-status   pointers->errorStatus;
             */
        }
        /* error-index */
        {
            uint8_t *buf;
            size_t blen;

            blen = snmp_buffer_remain(&context->memBuffer);
            if (!blen)
                goto noresponse;
            buf = snmp_buffer_alloc(&context->memBuffer, blen);
            if (!buf)
                goto noresponse;

            asn_token_init(&token, buf, blen);
            if (!asn_encode_integer(&token, context->errorIndex))
                goto noresponse;
            TOKEN_PRINT(&token);
            snmp_buffer_reset(&context->memBuffer, buf + token.tlen);
            context->pointers.errorIndex.data = buf;
            context->pointers.errorIndex.size = token.tlen;
            /*
             * memBuffer
             *     VarBindList    pointers->varBindList
             *     request-id     pointers->requestID;
             *     error-status   pointers->errorStatus;
             *     error-index    pointers->errorIndex;
             */
        }

    //    DEBUG(DLEVEL_NOISE, "=== PDU (%u) ===", snmp_buffer_size(&context->memBuffer));
    //    DEBUG_BUFFER(DLEVEL_NOISE, snmp_buffer_get(&context->memBuffer), snmp_buffer_size(&context->memBuffer));

        snmp_buffer_reset(&context->seqBuffer, NULL);
        /*
         * seqBuffer
         *
         * memBuffer
         *     VarBindList    pointers->varBindList
         *     request-id     pointers->requestID;
         *     error-status   pointers->errorStatus;
         *     error-index    pointers->errorIndex;
         */

        {
            uint8_t *buf;
            size_t blen;
            struct asn_encode_raw_t rlist[5];
            int command;

            switch (context->command)
            {
                case PDU_GET_BULK_REQUEST:
                case PDU_GET_REQUEST:
                case PDU_GET_NEXT_REQUEST:
                case PDU_SET_REQUEST:
                    command = PDU_GET_RESPONSE;
                    break;
                default:
                    goto noresponse;
            }

            memcpy(&rlist[0], &context->pointers.requestID, sizeof(struct asn_encode_raw_t));
            memcpy(&rlist[1], &context->pointers.errorStatus, sizeof(struct asn_encode_raw_t));
            memcpy(&rlist[2], &context->pointers.errorIndex, sizeof(struct asn_encode_raw_t));
            memcpy(&rlist[3], &context->pointers.varBindList, sizeof(struct asn_encode_raw_t));
            rlist[4].data = NULL;

            blen = snmp_buffer_remain(&context->seqBuffer);
            if (!blen)
                goto noresponse;
            buf = snmp_buffer_alloc(&context->seqBuffer, blen);
            if (!buf)
                goto noresponse;

            asn_token_init(&token, buf, blen);
            if (!asn_encode_raw(&token,
                        ASN1_IDENTIFIER_CLASS_CONTEXT, command, 1, rlist))
            {
                context->error = SNMP_ERROR_STATUS_TOO_BIG;
                continue;
            }
            TOKEN_PRINT(&token);
            snmp_buffer_reset(&context->seqBuffer, buf + token.tlen);
            /*
             * seqBuffer
             *     PDU
             *
             * memBuffer
             *     VarBindList    pointers->varBindList
             *     request-id     pointers->requestID;
             *     error-status   pointers->errorStatus;
             *     error-index    pointers->errorIndex;
             */
            snmp_buffer_move(&context->memBuffer, &context->seqBuffer);
            context->pointers.pdu.data = buf;
            context->pointers.pdu.size = token.tlen;
            /*
             * seqBuffer
             *
             * memBuffer
             *     PDU            pointers->pdu;
             *
             */
        }

        /* 
         * Construct response.
         *
         * Message ::=
         *         SEQUENCE {
         *              version        -- version-1 for this RFC
         *                 INTEGER {
         *                     version-1(0)
         *                 },
         *             community      -- community name
         *                 OCTET STRING,
         *             data           -- e.g., PDUs if trivial
         *                 ANY        -- authentication is being used
         *         }    
         */

        /* version */
        {
            uint8_t *buf;
            size_t blen;

            blen = snmp_buffer_remain(&context->memBuffer);
            if (!blen)
                goto noresponse;
            buf = snmp_buffer_alloc(&context->memBuffer, blen);
            if (!buf)
                goto noresponse;

            asn_token_init(&token, buf, blen);
            if (!asn_encode_integer(&token, context->version))
                goto noresponse;
            TOKEN_PRINT(&token);
            snmp_buffer_reset(&context->memBuffer, buf + token.tlen);
            context->pointers.version.data = buf;
            context->pointers.version.size = token.tlen;
            /*
             * seqBuffer
             *
             * memBuffer
             *     PDU            pointers->pdu;
             *     version        pointers->version;
             */
        }
        /* community */
        {
            uint8_t *buf;
            size_t blen;
            char *cstring;

            switch (context->community)
            {
                case COMMUNITY_R:  cstring = COMMUNITY_STR_R; break;
                case COMMUNITY_RW: cstring = COMMUNITY_STR_RW; break;
                default:
                    goto noresponse;
            }

            blen = snmp_buffer_remain(&context->memBuffer);
            if (!blen)
                goto noresponse;
            buf = snmp_buffer_alloc(&context->memBuffer, blen);
            if (!buf)
                goto noresponse;

            asn_token_init(&token, buf, blen);
            if (!asn_encode_raw1(&token, ASN1_IDENTIFIER_CLASS_UNIVERSAL, ASN1_IDENTIFIER_TAG_OCTET_STRING, 0,
                    cstring, strlen(cstring)))
                goto noresponse;
            TOKEN_PRINT(&token);
            snmp_buffer_reset(&context->memBuffer, buf + token.tlen);
            context->pointers.community.data = buf;
            context->pointers.community.size = token.tlen;
            /*
             * seqBuffer
             *
             * memBuffer
             *     PDU            pointers->pdu;
             *     version        pointers->version;
             *     community      pointers->community;
             */
        }

        /*
         * Message
         */
        do
        {
            uint8_t *buf;
            size_t blen;
            struct asn_encode_raw_t rlist[4];

            memcpy(&rlist[0], &context->pointers.version, sizeof(struct asn_encode_raw_t));
            memcpy(&rlist[1], &context->pointers.community, sizeof(struct asn_encode_raw_t));
            memcpy(&rlist[2], &context->pointers.pdu, sizeof(struct asn_encode_raw_t));
            rlist[3].data = NULL;

            blen = context->outputMaxLength;
            buf = context->outBuf;
            asn_token_init(&token, buf, blen);
            if (!asn_encode_sequence_raw(&token, rlist))
            {
                context->error = SNMP_ERROR_STATUS_TOO_BIG;
                break;
            }
            TOKEN_PRINT(&token);
            rlen = token.tlen;
        } while (0);

        DEBUG(DLEVEL_NOISE, "%s", "Message READY");
        if (context->error == SNMP_ERROR_STATUS_NO_ERROR)
            break;
    } /* Two time path - second path if response too big. */

    return rlen;
noresponse:
    return 0;
}

static int _oid_compare(uint32_t *oid1, uint32_t *oid2);
static void _oid_incr(uint32_t *oid, const uint32_t *listOID,
        const uint32_t *indexMin, const uint32_t *indexMax);
static int _getInputVarBind(struct snmp_context_t *context,
        struct asn_token_t *inNameToken, struct asn_token_t *inValueToken);
static const struct snmp_var_bind_t * _findVarBind(struct snmp_context_t *context);
static int _encodeVarBind(struct snmp_context_t *context, struct snmp_var_bind_t *bind, struct asn_token_t *inValueToken);

/*
 * RETURN
 *     SNMP_ERROR_STATUS_
 */
static int _process_vars(struct snmp_context_t *context)
{
    int error;
    int items;

    items = 0;

    /*
     * seqBuffer
     *     VarBind
     *     VarBind
     *     VarBind
     *     ...
     * memBuffer
     *
     */
    snmp_buffer_reset(&context->memBuffer, NULL);

    while (context->inputLength)
    {
        struct asn_token_t inNameToken;
        struct asn_token_t inValueToken;
        int repeat;

#if 1
        /*
         * non-repeaters, tells the agent how many Oid's in the
         * request should be treated as Get request variables.
         *
         * max-repetitions, telling the agent how many GetNext operations to
         * perform on each request variable (that is not covered by the
         * non-repeaters option) and return the values in a single reply.
         */
        repeat = 1;
        context->getNext = 0;
        if (context->command == PDU_GET_BULK_REQUEST)
        {
            if (context->nonRepeaters)
            {
                context->nonRepeaters--;
            } else {
                context->getNext = 1;
                if (context->maxRepetions)
                    repeat = context->maxRepetions;
            }
        } else if (context->command == PDU_GET_NEXT_REQUEST) {
            context->getNext = 1;
        }
#else
        repeat = 1;
        #warning GET_BULK_REQUEST not fully implemented.
#endif
        /*
         * Get var name and syntax.
         */
        if (!_getInputVarBind(context, &inNameToken, &inValueToken))
        {
            error = SNMP_ERROR_STATUS_GEN_ERR;
            goto done;
        }

        snmp_oid_copy(context->inputOID, inNameToken.content.oid);

        while (repeat--)
        {
            const struct snmp_var_bind_t *bind;

            bind = _findVarBind(context);
            if (!bind && context->version == SNMP_VERSION1)
            {
                error = SNMP_ERROR_STATUS_NO_SUCH_NAME;
                goto done;
            }

            error = _encodeVarBind(context, (struct snmp_var_bind_t *)bind, &inValueToken);
            if (error != SNMP_ERROR_STATUS_NO_ERROR)
                goto done;

            items++;
            if (!bind)
                break;
        }

        context->errorIndex++;
    }

    error = SNMP_ERROR_STATUS_NO_ERROR;
done:
    /* NOTE XXX Is this correct, especially with SetVar? */
    if (items > 0 && (error == SNMP_ERROR_STATUS_TOO_BIG || error == SNMP_ERROR_STATUS_NO_SUCH_NAME))
        error = SNMP_ERROR_STATUS_NO_ERROR;
    snmp_buffer_reset(&context->memBuffer, NULL);
    return error;
}
/*
 *
 */
static int _getInputVarBind(struct snmp_context_t *context,
        struct asn_token_t *inNameToken, struct asn_token_t *inValueToken)
{
    struct asn_token_t sequence;

    /*
     *    VarBind ::=
     *            SEQUENCE {
     *                name
     *                    ObjectName,
     *                value
     *                    ObjectSyntax
     *            }
     */

    /* SEQUENCE */
    if (_getSequence(&sequence , context->inputOctet, context->inputLength) < 0)
    {
        return 0;
    }
    context->inputOctet  += sequence.tlen;
    context->inputLength -= sequence.tlen;

    /* ObjectName */
    if (_getObjectIdentifier(inNameToken,
                sequence.content.raw, sequence.content.length) < 0)
    {
        return 0;
    }

    /* ObjectSyntax */
    if (_getToken(inValueToken,
                sequence.content.raw + inNameToken->tlen,
                sequence.content.length - inNameToken->tlen) < 0)
    {
        return 0;
    }

    return 1;
}
/*
 *
 */
static const struct snmp_var_bind_t * _findVarBind(struct snmp_context_t *context)
{
    const struct snmp_var_bind_t *bind;

    if (context->inputOID[0] == ASN_OID_SENTINEL)
        return NULL;

    for (bind = snmpVarBind; bind->oid != NULL; bind++)
    {
        if (bind->indexMin && bind->indexMax)
        {
            int match;
            static uint32_t indexMin[ASN_OID_MAX_LEN + 1];
            static uint32_t indexMax[ASN_OID_MAX_LEN + 1];

//            if (snmp_oid_length(context->inputOID) >
//                    snmp_oid_length((uint32_t*)bind->oid) +
//                    snmp_oid_length((uint32_t*)bind->indexMin))
//            {
//                dprint("sn", "CONTINUE");
//                /* NOTE */
//                continue;
//            }

            snmp_oid_copy(indexMin, (uint32_t*)bind->oid);
            snmp_oid_copy(indexMax, (uint32_t*)bind->oid);

            snmp_oid_copy(&indexMin[snmp_oid_length(indexMin)], (uint32_t*)bind->indexMin);
            snmp_oid_copy(&indexMax[snmp_oid_length(indexMax)], (uint32_t*)bind->indexMax);

#if 0
            dprint("s_dn", "INPUT", snmp_oid_length(context->inputOID));
            _oidPrint(context->inputOID);
            dprint("sn", "MIN");
            _oidPrint(indexMin);
            dprint("sn", "MAX");
            _oidPrint(indexMax);
#endif

            match = 0;
            while (1) {
                match = 0;
#if 0
                dprint("s_dn", "LOOP GET", context->getNext);
                _oidPrint(context->inputOID);
#endif
                if (context->getNext) {
                    int cmp;
                    cmp = _oid_compare(context->inputOID, indexMin); 
                    if (cmp < 0)
                    {
                        snmp_oid_copy(context->inputOID, indexMin);
#if 0
                        dprint("sn", "LESS THEN MIN, COPIED");
                        _oidPrint(context->inputOID);
#endif
                        match = 1;
                    } else {
                        cmp = _oid_compare(context->inputOID, indexMax); 
                        if (cmp < 0)
                        {
#if 0
                            dprint("sn", "COMPARED");
                            _oidPrint(context->inputOID);
#endif
                            _oid_incr(context->inputOID, bind->oid, indexMin, indexMax);
#if 0
                            dprint("sn", "INCREMENTED");
                            _oidPrint(context->inputOID);
#endif
                            match = 1;
                        }
                    }
                } else {
                    if (_oid_compare(context->inputOID, indexMin) >= 0 &&
                        _oid_compare(context->inputOID, indexMax) <= 0)
                    {
                        match = 1;
                    }
                }

                if (!match)
                    break;
                if (bind->haveOID == NULL)
                    break;
                if (bind->haveOID(bind, context->inputOID) == SNMP_ERROR_STATUS_NO_SUCH_NAME
                        && context->getNext)
                {
                    continue;
                } else {
                    break;
                }
            }
            if (match)
                break;
        } else {
            if (context->getNext)
            {
                if (_oid_compare((uint32_t*)bind->oid, context->inputOID) > 0)
                {
                    snmp_oid_copy(context->inputOID, (uint32_t*)bind->oid);
                    break;
                }
            } else {
                if (_oid_compare((uint32_t*)bind->oid, context->inputOID) == 0)
                    break;
            }
        }
    }

    /*
     * Not found.
     */
    if (bind->oid == NULL)
        return NULL;

    return bind;
}
/*
 *
 */
static int _encodeVarBind(struct snmp_context_t *context, struct snmp_var_bind_t *bind, struct asn_token_t *inValueToken)
{
    snmp_buffer_reset(&context->memBuffer, NULL);
    /*
     *  memBuffer
     *
     *  seqBuffer
     *     ....
     */

    /*
     * Encode name.
     */
    {
        struct asn_token_t token;
        uint8_t *buf;
        size_t blen;

        blen = snmp_buffer_remain(&context->memBuffer);
        if (!blen)
            return SNMP_ERROR_STATUS_TOO_BIG;
        buf = snmp_buffer_alloc(&context->memBuffer, blen);
        if (!buf)
        {
            DEBUG(DLEVEL_WARNING, "%s", "Failed to allocate buffer");
            return SNMP_ERROR_STATUS_TOO_BIG;
        }
        asn_token_init(&token, buf, blen);
        if (!asn_encode_object_identifier(&token, context->inputOID))
            return SNMP_ERROR_STATUS_TOO_BIG;
        snmp_buffer_reset(&context->memBuffer, buf + token.tlen);
    }

    /*
     * Encode value.
     */
    {
        uint8_t *buf;
        size_t blen;
        int error;

        struct asn_token_t token;

        error = SNMP_ERROR_STATUS_NO_ERROR;

        blen = snmp_buffer_remain(&context->memBuffer);
        if (!blen)
            return SNMP_ERROR_STATUS_TOO_BIG;
        buf = snmp_buffer_alloc(&context->memBuffer, blen);
        if (!buf)
        {
            DEBUG(DLEVEL_WARNING, "%s", "Failed to allocate buffer");
            return SNMP_ERROR_STATUS_TOO_BIG;
        }
        asn_token_init(&token, buf, blen);
        if (bind)
        {
            if (context->command == PDU_SET_REQUEST)
            {
                if (bind->varSet == NULL)
                {
                    return SNMP_ERROR_STATUS_READ_ONLY;
                }
                error = bind->varSet(bind, context->inputOID, inValueToken, &token);
            } else {
                error = bind->varGet(bind, context->inputOID, &token);
            }
            if (error != SNMP_ERROR_STATUS_NO_ERROR)
                return error;
            snmp_buffer_reset(&context->memBuffer, buf + token.tlen);
        } else {
            token.class_ = ASN1_IDENTIFIER_CLASS_CONTEXT;
            /* XXX */
            if (context->getNext)
                token.tag = 2; /* SNMP_TYPE_endOfMibView */
            else
                token.tag = 1; /* SNMP_TYPE_noSuchInstance */
            if (!asn_encode_null_idn(&token))
            {
                error = SNMP_ERROR_STATUS_TOO_BIG;
                return error;
            }
            snmp_buffer_reset(&context->memBuffer, buf + token.tlen);
        }
    }

    /*
     *  memBuffer
     *     VarBind
     *  seqBuffer
     *     ....
     */

    /*
     * Encode sequence.
     */
    {
        uint8_t *buf;
        size_t blen;
        struct asn_token_t token;
        struct asn_encode_raw_t rlist[2];
        int varBindSize;

        varBindSize = snmp_buffer_size(&context->memBuffer);
#if 1
        {
            uint32_t used;

            used = snmp_buffer_size(&context->seqBuffer);
            #define SNMP_VARBINDLIST_MAX_SIZE    768 /* XXX */
            #warning Limiting SNMP VarBindList to 768 bytes
            if (used + varBindSize >= SNMP_VARBINDLIST_MAX_SIZE)
                return SNMP_ERROR_STATUS_TOO_BIG;
        }
#endif

        rlist[0].data = snmp_buffer_get(&context->memBuffer);
        rlist[0].size = varBindSize;
        rlist[1].data = NULL;

        blen = snmp_buffer_remain(&context->seqBuffer);
        if (!blen)
            return SNMP_ERROR_STATUS_TOO_BIG;
        buf = snmp_buffer_alloc(&context->seqBuffer, blen);
        if (!buf)
            return SNMP_ERROR_STATUS_TOO_BIG;

        asn_token_init(&token, buf, blen);
        if (!asn_encode_sequence_raw(&token, rlist))
            return SNMP_ERROR_STATUS_TOO_BIG;
        snmp_buffer_reset(&context->seqBuffer, buf + token.tlen);
    }

    snmp_buffer_reset(&context->memBuffer, NULL);
    /*
     *  memBuffer
     *
     *  seqBuffer
     *     ....
     *     VarBind (sequence)
     */


    return SNMP_ERROR_STATUS_NO_ERROR;
}

/*
 * RETURN
 *     An integer less than, equal to, or greater than zero if oid1,
 *     respectively, to be less than, to match, or be greater than oid2.
 */
static int _oid_compare(uint32_t *oid1, uint32_t *oid2)
{
    while (1)
    {
        if (*oid1 == ASN_OID_SENTINEL)
        {
            if (*oid2 == ASN_OID_SENTINEL)
                return 0;
            else
                return -1;
        } else if (*oid2 == ASN_OID_SENTINEL) {
            if (*oid1 == ASN_OID_SENTINEL)
                return 0;
            else
                return 1;
        } else if (*oid1 > *oid2) {
            return 1;
        } else if (*oid1 < *oid2) {
            return -1;
        }

        oid1++;
        oid2++;
    }

    return 0;
}
/*
 *
 */
int snmp_oid_length(uint32_t *oid)
{
    int len;

    len = 0;
    while (*oid++ != ASN_OID_SENTINEL)
        len++;
    return len;
}
/*
 *
 */
void snmp_oid_copy(uint32_t *dst, uint32_t *src)
{
    while (*src != ASN_OID_SENTINEL)
        *dst++ = *src++;
    *dst = ASN_OID_SENTINEL;
}
/*
 *
 */
static void _oid_incr(uint32_t *oid, const uint32_t *listOID,
        const uint32_t *indexMin, const uint32_t *indexMax)
{
    uint32_t oidLength;

    oidLength = snmp_oid_length(oid);
#if 0
    if (oidLength < snmp_oid_length((uint32_t*)indexMin) ||
        _oid_compare(oid, (uint32_t*)indexMin) < 0)
    {
        snmp_oid_copy(oid, (uint32_t*)listOID);
        snmp_oid_copy(&oid[oidLength], (uint32_t*)&indexMin[oidLength]);
    } else
#endif
    {
        int offset;

        offset = oidLength - 1;
        while (++oid[offset] > indexMax[offset])
        {
            oid[offset] = indexMin[offset];
            offset--;
        }
    }
}

static int _getOID(const struct snmp_var_bind_t *bind, uint32_t *inputOID, struct asn_token_t *outSyntax)
{
    if (bind->context == NULL)
        return SNMP_ERROR_STATUS_GEN_ERR;

    if (!asn_encode_object_identifier(outSyntax, (uint32_t *)bind->context))
        return SNMP_ERROR_STATUS_TOO_BIG;

    return SNMP_ERROR_STATUS_NO_ERROR;
}

/*
 *
 */
size_t snmp_make_trap(
        struct snmp_context_t *context, const uint32_t *trapOID,
        struct snmp_trap_oid_bind_t *oidList,
        uint8_t *buffer, size_t maxLen)
{
    struct asn_token_t token;
    int rlen;

    context->error = SNMP_ERROR_STATUS_NO_ERROR;
    context->outBuf = buffer;
    context->outputMaxLength = maxLen;
    context->version = 1; /* v2 */
    context->errorIndex = 0;

    rlen = 0;

    snmp_buffer_reset(&context->memBuffer, NULL);
    snmp_buffer_reset(&context->seqBuffer, NULL);
    /*
     * seqBuffer
     *
     * memBuffer
     *
     */

    /* VarBindList */
    {
        context->command = PDU_GET_REQUEST; /* NOTE */

        /* sysUpTime */
        {
            static const uint32_t sysUpTimeOID[] = {1, 3, 6, 1, 2, 1, 1, 3, 0, ASN_OID_SENTINEL};
            int error;
            const struct snmp_var_bind_t *bind;

            snmp_oid_copy(context->inputOID, (uint32_t*)sysUpTimeOID);
            bind = _findVarBind(context);
            if (!bind)
                goto noresponse;
            error = _encodeVarBind(context, (struct snmp_var_bind_t *)bind, NULL);
            if (error != SNMP_ERROR_STATUS_NO_ERROR)
                goto noresponse;
        }
        /* snmpTrapOID */
        {
            int error;
            static const uint32_t snmpTrapOID[] = {1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0, ASN_OID_SENTINEL};
            struct snmp_var_bind_t bind;

            memset(&bind, 0, sizeof(struct snmp_var_bind_t));
            bind.oid = snmpTrapOID;
            bind.varGet = _getOID;
            bind.context = (void*)trapOID;

            snmp_oid_copy(context->inputOID, (uint32_t*)snmpTrapOID);
            error = _encodeVarBind(context, &bind, NULL);
            if (error != SNMP_ERROR_STATUS_NO_ERROR)
                goto noresponse;
        }
        /* other variables */
        if (oidList)
        {
            while (oidList->oid[0] != ASN_OID_SENTINEL)
            {
                const struct snmp_var_bind_t *bind;

                snmp_oid_copy(context->inputOID, oidList->oid);
                oidList++;

                bind = _findVarBind(context);
                if (!bind)
                    continue; /* XXX skip unknown bindings */

                if (_encodeVarBind(context, (struct snmp_var_bind_t*)bind, NULL) != SNMP_ERROR_STATUS_NO_ERROR)
                    goto noresponse;
            }
        }

        snmp_buffer_reset(&context->memBuffer, NULL);
        /*
         * seqBuffer
         *     VarBind
         *     VarBind
         *     VarBind
         *     ...
         *
         * memBuffer
         *
         */

        /*
         * Encode VarBindList sequence. 
         */
        {
            uint8_t *buf;
            size_t blen;
            struct asn_encode_raw_t rlist[2];

            blen = snmp_buffer_remain(&context->memBuffer);
            if (!blen)
                goto noresponse;
            buf = snmp_buffer_alloc(&context->memBuffer, blen);
            if (!buf)
                goto noresponse;

            rlist[0].data = snmp_buffer_get(&context->seqBuffer);
            rlist[0].size = snmp_buffer_size(&context->seqBuffer);
            rlist[1].data = NULL;

            asn_token_init(&token, buf, blen);
            if (!asn_encode_sequence_raw(&token, rlist))
                goto noresponse;
            DEBUG(DLEVEL_NOISE, "%s", "varBindList");
            TOKEN_PRINT(&token);
            snmp_buffer_reset(&context->memBuffer, buf + token.tlen);
            context->pointers.varBindList.data = buf;
            context->pointers.varBindList.size = token.tlen;
        }

        snmp_buffer_reset(&context->seqBuffer, NULL);
        /*
         * seqBuffer
         *
         * memBuffer
         *     VarBindList    pointers->varBindList
         */
    }

    /*
     * seqBuffer
     *
     * memBuffer
     *     VarBindList    pointers->varBindList
     */


    /* PDU */
    {
        /* request-id */
        {
            uint8_t *buf;
            size_t blen;

            blen = snmp_buffer_remain(&context->memBuffer);
            if (!blen)
                goto noresponse;
            buf = snmp_buffer_alloc(&context->memBuffer, blen);
            if (!buf)
                goto noresponse;

            asn_token_init(&token, buf, blen);
            if (!asn_encode_integer(&token, util_rand()))
                goto noresponse;
            TOKEN_PRINT(&token);
            snmp_buffer_reset(&context->memBuffer, buf + token.tlen);
            context->pointers.requestID.data = buf;
            context->pointers.requestID.size = token.tlen;
            /*
             * memBuffer
             *     VarBindList    pointers->varBindList
             *     request-id     pointers->requestID;
             */
        }
        /* error-status */
        {
            uint8_t *buf;
            size_t blen;

            blen = snmp_buffer_remain(&context->memBuffer);
            if (!blen)
                goto noresponse;
            buf = snmp_buffer_alloc(&context->memBuffer, blen);
            if (!buf)
                goto noresponse;

            asn_token_init(&token, buf, blen);
            if (!asn_encode_integer(&token, context->error))
                goto noresponse;
            TOKEN_PRINT(&token);
            snmp_buffer_reset(&context->memBuffer, buf + token.tlen);
            context->pointers.errorStatus.data = buf;
            context->pointers.errorStatus.size = token.tlen;
            /*
             * memBuffer
             *     VarBindList    pointers->varBindList
             *     request-id     pointers->requestID;
             *     error-status   pointers->errorStatus;
             */
        }
        /* error-index */
        {
            uint8_t *buf;
            size_t blen;

            blen = snmp_buffer_remain(&context->memBuffer);
            if (!blen)
                goto noresponse;
            buf = snmp_buffer_alloc(&context->memBuffer, blen);
            if (!buf)
                goto noresponse;

            asn_token_init(&token, buf, blen);
            if (!asn_encode_integer(&token, context->errorIndex))
                goto noresponse;
            TOKEN_PRINT(&token);
            snmp_buffer_reset(&context->memBuffer, buf + token.tlen);
            context->pointers.errorIndex.data = buf;
            context->pointers.errorIndex.size = token.tlen;
            /*
             * memBuffer
             *     VarBindList    pointers->varBindList
             *     request-id     pointers->requestID;
             *     error-status   pointers->errorStatus;
             *     error-index    pointers->errorIndex;
             */
        }

        snmp_buffer_reset(&context->seqBuffer, NULL);
        /*
         * seqBuffer
         *
         * memBuffer
         *     VarBindList    pointers->varBindList
         *     request-id     pointers->requestID;
         *     error-status   pointers->errorStatus;
         *     error-index    pointers->errorIndex;
         */
        {
            uint8_t *buf;
            size_t blen;
            struct asn_encode_raw_t rlist[5];
            int command;

            command = PDU_V2_TRAP;

            memcpy(&rlist[0], &context->pointers.requestID, sizeof(struct asn_encode_raw_t));
            memcpy(&rlist[1], &context->pointers.errorStatus, sizeof(struct asn_encode_raw_t));
            memcpy(&rlist[2], &context->pointers.errorIndex, sizeof(struct asn_encode_raw_t));
            memcpy(&rlist[3], &context->pointers.varBindList, sizeof(struct asn_encode_raw_t));
            rlist[4].data = NULL;

            blen = snmp_buffer_remain(&context->seqBuffer);
            if (!blen)
                goto noresponse;
            buf = snmp_buffer_alloc(&context->seqBuffer, blen);
            if (!buf)
                goto noresponse;

            asn_token_init(&token, buf, blen);
            if (!asn_encode_raw(&token,
                        ASN1_IDENTIFIER_CLASS_CONTEXT, command, 1, rlist))
            {
                goto noresponse;
            }
            snmp_buffer_reset(&context->seqBuffer, buf + token.tlen);
            /*
             * seqBuffer
             *     PDU
             *
             * memBuffer
             *     VarBindList    pointers->varBindList
             *     request-id     pointers->requestID;
             *     error-status   pointers->errorStatus;
             *     error-index    pointers->errorIndex;
             */
            snmp_buffer_move(&context->memBuffer, &context->seqBuffer);
            context->pointers.pdu.data = buf;
            context->pointers.pdu.size = token.tlen;
            /*
             * seqBuffer
             *
             * memBuffer
             *     PDU            pointers->pdu;
             *
             */
        }
    }

    /* 
     * Construct response.
     *
     * Message ::=
     *         SEQUENCE {
     *              version        -- version-1 for this RFC
     *                 INTEGER {
     *                     version-1(0)
     *                 },
     *             community      -- community name
     *                 OCTET STRING,
     *             data           -- e.g., PDUs if trivial
     *                 ANY        -- authentication is being used
     *         }    
     */

    /* version */
    {
        uint8_t *buf;
        size_t blen;

        blen = snmp_buffer_remain(&context->memBuffer);
        if (!blen)
            goto noresponse;
        buf = snmp_buffer_alloc(&context->memBuffer, blen);
        if (!buf)
            goto noresponse;

        asn_token_init(&token, buf, blen);
        if (!asn_encode_integer(&token, context->version))
            goto noresponse;
        TOKEN_PRINT(&token);
        snmp_buffer_reset(&context->memBuffer, buf + token.tlen);
        context->pointers.version.data = buf;
        context->pointers.version.size = token.tlen;
        /*
         * seqBuffer
         *
         * memBuffer
         *     version        pointers->version;
         */
    }
    /* community */
    {
        uint8_t *buf;
        size_t blen;
        char *cstring;

        cstring = COMMUNITY_STR_TRAP;
        blen = snmp_buffer_remain(&context->memBuffer);
        if (!blen)
            goto noresponse;
        buf = snmp_buffer_alloc(&context->memBuffer, blen);
        if (!buf)
            goto noresponse;

        asn_token_init(&token, buf, blen);
        if (!asn_encode_raw1(&token, ASN1_IDENTIFIER_CLASS_UNIVERSAL, ASN1_IDENTIFIER_TAG_OCTET_STRING, 0,
                cstring, strlen(cstring)))
            goto noresponse;
        TOKEN_PRINT(&token);
        snmp_buffer_reset(&context->memBuffer, buf + token.tlen);
        context->pointers.community.data = buf;
        context->pointers.community.size = token.tlen;
        /*
         * seqBuffer
         *
         * memBuffer
         *     version        pointers->version;
         *     community      pointers->community;
         */
    }

    /*
     * Message
     */
    {
        uint8_t *buf;
        size_t blen;
        struct asn_encode_raw_t rlist[4];

        memcpy(&rlist[0], &context->pointers.version, sizeof(struct asn_encode_raw_t));
        memcpy(&rlist[1], &context->pointers.community, sizeof(struct asn_encode_raw_t));
        memcpy(&rlist[2], &context->pointers.pdu, sizeof(struct asn_encode_raw_t));
        rlist[3].data = NULL;

        blen = context->outputMaxLength;
        buf = context->outBuf;
        asn_token_init(&token, buf, blen);
        if (!asn_encode_sequence_raw(&token, rlist))
        {
            context->error = SNMP_ERROR_STATUS_TOO_BIG;
            goto noresponse;
        }
        TOKEN_PRINT(&token);
        rlen = token.tlen;
    } while (0);

    return rlen;
noresponse:
    return 0;
}

/*
 *    ObjectSyntax ::=
 *        CHOICE {
 *            simple
 *                SimpleSyntax,
 *
 *            application-wide
 *                ApplicationSyntax
 *        }
 *
 *    --------------
 *    SMI (RFC 1155)
 *    --------------
 *
 *    SimpleSyntax ::=
 *        CHOICE {
 *            number
 *                INTEGER,
 *    
 *            string
 *                OCTET STRING,
 *    
 *            object
 *                OBJECT IDENTIFIER,
 *    
 *            empty
 *                NULL
 *        }
 *    
 *    ApplicationSyntax ::=
 *        CHOICE {
 *            address
 *                NetworkAddress,
 *    
 *            counter
 *                Counter,
 *    
 *            gauge
 *                Gauge,
 *    
 *            ticks
 *                TimeTicks,
 *    
 *            arbitrary
 *                Opaque
 *    -- other application-wide types, as they are
 *    -- defined, will be added here
 *        }
 *    
 *    
 *    -- application-wide types
 *    
 *    NetworkAddress ::=
 *        CHOICE {
 *            internet
 *                IpAddress
 *        }
 *    
 *    IpAddress ::=
 *        [APPLICATION 0]          -- in network-byte order
 *            IMPLICIT OCTET STRING (SIZE (4))
 *    
 *    Counter ::=
 *        [APPLICATION 1]
 *            IMPLICIT INTEGER (0..4294967295)
 *    
 *    Gauge ::=
 *        [APPLICATION 2]
 *            IMPLICIT INTEGER (0..4294967295)
 *    
 *    TimeTicks ::=
 *        [APPLICATION 3]
 *            IMPLICIT INTEGER (0..4294967295)
 *    
 *    Opaque ::=
 *        [APPLICATION 4]          -- arbitrary ASN.1 value,
 *            IMPLICIT OCTET STRING   --   "double-wrapped"
 *
 *    ----------------
 *    SMIv2 (RFC 2578)
 *    ----------------
 *
 *    SimpleSyntax ::=
 *        CHOICE {
 *            -- INTEGERs with a more restrictive range
 *            -- may also be used
 *            integer-value               -- includes Integer32
 *                INTEGER (-2147483648..2147483647),
 *    
 *            -- OCTET STRINGs with a more restrictive size
 *            -- may also be used
 *            string-value
 *                OCTET STRING (SIZE (0..65535)),
 *    
 *            objectID-value
 *                OBJECT IDENTIFIER
 *        }
 *    
 *    ApplicationSyntax ::=
 *        CHOICE {
 *            ipAddress-value
 *                IpAddress,
 *    
 *            counter-value
 *                Counter32,
 *    
 *            timeticks-value
 *                TimeTicks,
 *    
 *            arbitrary-value
 *                Opaque,
 *    
 *            big-counter-value
 *                Counter64,
 *    
 *            unsigned-integer-value  -- includes Gauge32
 *                Unsigned32
 *        }
 *    
 *        -- (this is a tagged type for historical reasons)
 *        IpAddress ::=
 *            [APPLICATION 0]
 *                IMPLICIT OCTET STRING (SIZE (4))
 *    
 *        -- this wraps
 *        Counter32 ::=
 *            [APPLICATION 1]
 *                IMPLICIT INTEGER (0..4294967295)
 *    
 *        -- this doesn't wrap
 *        Gauge32 ::=
 *            [APPLICATION 2]
 *                IMPLICIT INTEGER (0..4294967295)
 *    
 *        -- an unsigned 32-bit quantity
 *        -- indistinguishable from Gauge32
 *        Unsigned32 ::=
 *            [APPLICATION 2]
 *                IMPLICIT INTEGER (0..4294967295)
 *    
 *        -- hundredths of seconds since an epoch
 *        TimeTicks ::=
 *            [APPLICATION 3]
 *                IMPLICIT INTEGER (0..4294967295)
 *    
 *        -- for backward-compatibility only
 *        Opaque ::=
 *            [APPLICATION 4]
 *                IMPLICIT OCTET STRING
 *    
 *        -- for counters that wrap in less than one hour with only 32 bits
 *        Counter64 ::=
 *            [APPLICATION 6]
 *                IMPLICIT INTEGER (0..18446744073709551615)
 */

