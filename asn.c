/*
 * Jaroj 2018-2023.
 * Auxtoro estas Dmitrij Kobilin. 
 *
 * Nenia rajtigilo ekzistas.
 * Faru bone, ne faru malbone.
 */
#include <string.h>
/* */
#include "asn.h"

#if 0
    #define DEBUG_THIS

    #define DEBUG(level, fmt, ...) \
        debugPrint(level, fmt, __VA_ARGS__)
    #define DEBUG_BUFFER(level, buf, len) \
        debugPrintBuffer(level, buf, len)
    #define TOKEN_PRINT(token) asn_token_print(token)

#else
    #define DEBUG(level, fmt, ...)
    #define DEBUG_BUFFER(level, buf, len)
    #define TOKEN_PRINT(token)

    #define asn_oid_print(oid)
#endif

#define ASN1_IDENTIFIER_CONSTRUCTED       (0x01 << 5)


static int _decodeIdentifier(struct asn_token_t *token);
static int _decodeLength(struct asn_token_t *token);
static int _decodeInteger(struct asn_token_t *token);
static int _decodeObjectIdentifier(struct asn_token_t *token);

/*
 *
 */
void asn_token_init(struct asn_token_t *token, uint8_t *octet, size_t maxSize)
{
    token->input             = octet;
    token->octet             = octet;
    token->maxSize           = maxSize;
    token->tlen              = 0;
    token->constructed       = 0;
    token->class_            = ASN1_IDENTIFIER_CLASS_UNIVERSAL;
    token->content.length    = 0;
    token->content.raw       = NULL;

    token->content.oid[0] = ASN_OID_SENTINEL;
}

/*
 *
 * RETURN
 *     size of token in bytes, zero on error.
 */
size_t asn_token_get(struct asn_token_t *token)
{
    if (!_decodeIdentifier(token))
        goto error;

    if (!_decodeLength(token))
        goto error;

    if (token->content.length > token->maxSize)
        goto error;

    token->content.raw = token->octet;
    token->tlen += token->content.length;

    if (token->class_ == ASN1_IDENTIFIER_CLASS_UNIVERSAL)
    {
        if (!token->constructed)
        {
            if (token->tag == ASN1_IDENTIFIER_TAG_INTEGER)
            {
                if (!_decodeInteger(token))
                    goto error;
            } else if (token->tag == ASN1_IDENTIFIER_TAG_OBJECT_IDENTIFIER) {
                if (!_decodeObjectIdentifier(token))
                    goto error;
            } else if (token->tag == ASN1_IDENTIFIER_TAG_NULL) {
                if (token->content.length != 0)
                    goto error;
            }
        }
    }

    DEBUG(DLEVEL_NOISE, "%s", "<< GET TOKEN >>");
    TOKEN_PRINT(token);
    return token->tlen;
error:
    return 0;
}
#ifdef DEBUG_THIS
/*
 *
 */
void asn_oid_print(uint32_t *oid)
{
    static char s[ASN_OID_MAX_LEN * 10 + 1];
    char *p;
    int n;

    p = s;
    for (; *oid != ASN_OID_SENTINEL; oid++)
    {
        n = sprintf(p, "%u.", (unsigned int)*oid);
        if (n < 0)
            break;
        p += n;
    }
    DEBUG(DLEVEL_NOISE, "** OID       %s", s);
}
/*
 *
 */
void asn_token_print(struct asn_token_t *token)
{
    DEBUG(DLEVEL_NOISE, "%s", "<< ASN TOKEN >>");

    DEBUG(DLEVEL_NOISE, "%s", "RAW: ");
    DEBUG_BUFFER(DLEVEL_NOISE, token->input, token->tlen);

    DEBUG(DLEVEL_NOISE, "class        %u", token->class_ >> 6);
    switch (token->class_)
    {
        case ASN1_IDENTIFIER_CLASS_UNIVERSAL  : DEBUG(DLEVEL_NOISE, "             %s", "CLASS UNIVERSAL  "); break;
        case ASN1_IDENTIFIER_CLASS_APPLICATION: DEBUG(DLEVEL_NOISE, "             %s", "CLASS APPLICATION"); break;
        case ASN1_IDENTIFIER_CLASS_CONTEXT    : DEBUG(DLEVEL_NOISE, "             %s", "CLASS CONTEXT    "); break;
        case ASN1_IDENTIFIER_CLASS_PRIVATE    : DEBUG(DLEVEL_NOISE, "             %s", "CLASS PRIVATE    "); break;
        default:
            DEBUG(DLEVEL_NOISE, "%s", "    TAG UNKNOWN");
    }

    DEBUG(DLEVEL_NOISE, "constructed  %u", token->constructed);
    DEBUG(DLEVEL_NOISE, "tag          %u", token->tag);
    if (token->class_ == ASN1_IDENTIFIER_CLASS_UNIVERSAL)
    {
        switch (token->tag)
        {
            case ASN1_IDENTIFIER_TAG_INTEGER           : DEBUG(DLEVEL_NOISE, "             %s", "TAG INTEGER          "); break;
            case ASN1_IDENTIFIER_TAG_BIT_STRING        : DEBUG(DLEVEL_NOISE, "             %s", "TAG BIT_STRING       "); break;
            case ASN1_IDENTIFIER_TAG_OCTET_STRING      : DEBUG(DLEVEL_NOISE, "             %s", "TAG OCTET_STRING     "); break;
            case ASN1_IDENTIFIER_TAG_NULL              : DEBUG(DLEVEL_NOISE, "             %s", "TAG NULL             "); break;
            case ASN1_IDENTIFIER_TAG_OBJECT_IDENTIFIER : DEBUG(DLEVEL_NOISE, "             %s", "TAG OBJECT_IDENTIFIER"); break;
            case ASN1_IDENTIFIER_TAG_SEQ_SEQOF         : DEBUG(DLEVEL_NOISE, "             %s", "TAG SEQ_SEQOF        "); break;
            default:
                DEBUG(DLEVEL_NOISE, "%s", "    TAG UNKNOWN");
        }

        if (!token->constructed)
        {
            if (token->tag == ASN1_IDENTIFIER_TAG_INTEGER)
            {
                DEBUG(DLEVEL_NOISE, "** integer   %lld", token->content.integer);
            } else if (token->tag == ASN1_IDENTIFIER_TAG_OBJECT_IDENTIFIER) {
                asn_oid_print(token->content.oid);
            }
        }
    }
    DEBUG(DLEVEL_NOISE, "tlen         %u", token->tlen);
    DEBUG(DLEVEL_NOISE, "clen         %u", token->content.length);
    if (token->content.raw)
    {
        DEBUG(DLEVEL_NOISE, "%s", "content");
        DEBUG_BUFFER(DLEVEL_NOISE, token->content.raw, token->content.length);
    }
}
#endif

/*
 * RETURN
 *     1 on success, 0 on error.
 */
static int _decodeIdentifier(struct asn_token_t *token)
{
    if (token->maxSize < 1)
        return 0;

    token->class_ = *token->octet & ASN1_IDENTIFIER_CLASS_MASK;
    token->constructed = (*token->octet & ASN1_IDENTIFIER_CONSTRUCTED) ? 1 : 0;

    token->tag = 0;
    if ((*token->octet & ASN1_IDENTIFIER_TAG_MASK) != 0x1f)
    {
        token->tag = (*token->octet & ASN1_IDENTIFIER_TAG_MASK);

        token->octet++;
        token->tlen++;
        token->maxSize--;
    } else {
        token->octet++;
        token->tlen++;
        token->maxSize--;

        /* XXX tag limit to 32-bits */

        while (1)
        {
            uint8_t octet;

            if (token->maxSize < 1)
                return 0;

            token->tag <<= 7;
            token->tag |= (*token->octet & 0x7f);

            octet = *token->octet;

            token->octet++;
            token->tlen++;
            token->maxSize--;

            if (!(octet & 0x80))
                break;
        }
    }

    return 1;
}
/*
 * Decode finite length.
 *
 * RETURN
 *     1 on success, 0 on error.
 */
static int _decodeLength(struct asn_token_t *token)
{
    if (token->maxSize < 1)
        return 0;

    if (!(*token->octet & 0x80)) {
        token->content.length = *token->octet & 0x7f;
        token->octet++;
        token->tlen++;
        token->maxSize--;
    } else {
        size_t noct;

        noct = *token->octet & 0x7f;

        token->octet++;
        token->tlen++;
        token->maxSize--;

        while (noct--)
        {
            if (token->maxSize < 1)
                return 0;

            token->content.length <<= 8;
            token->content.length |= *token->octet;

            token->octet++;
            token->tlen++;
            token->maxSize--;
        }
    }

    return 1;
}
/*
 *
 */
static int _decodeInteger(struct asn_token_t *token)
{
    size_t len;
    uint8_t *octet;
    size_t width;
    int negative;

    width = token->content.length;
    if (width == 0 || width > 8 /* XXX more wide integer not supported */)
        return 0;

    token->content.integer = 0;

    len = width;
    octet = token->content.raw;

    negative = 0;
    if (*octet & 0x80)
        negative = 1;

    while (len--)
    {
        token->content.integer <<= 8;
        token->content.integer |= (*octet);

        octet++;
    }

    if (negative && width < 8 /* XXX */)
        token->content.integer *= -1;

    return 1;
}
/*
 *
 */
static int _decodeObjectIdentifier(struct asn_token_t *token)
{
    size_t len;
    uint8_t *octet;
    size_t noct;
    uint32_t oid;
    size_t oidLength;

    len = token->content.length;
    octet = token->content.raw;

    oid = 0;
    oidLength = 0;
    noct = 0;
    while (len--)
    {
        if (noct == 0)
        {
            token->content.oid[oidLength++] = *octet / 40;
            token->content.oid[oidLength++] = *octet % 40;
        } else {
            oid <<= 7;
            oid |= (*octet & 0x7f);

            if (!(*octet & 0x80))
            {
                token->content.oid[oidLength++] = oid;
                if (oidLength >= ASN_OID_MAX_LEN)
                {
                    token->content.oid[oidLength] = ASN_OID_SENTINEL;
#if 0
                    break;
#else
                    return 0;
#endif
                }

                token->content.oid[oidLength] = ASN_OID_SENTINEL;

                oid = 0;
            }
        }

        octet++;
        noct++;
    }

    return 1;
}

/*
 * RETURN
 *     1 on success, 0 on error.
 */
int asn_encode_identifier(struct asn_token_t *token)
{
    if (token->maxSize < 1)
        return 0;
    *token->octet = token->class_;
    if (token->constructed)
        *token->octet |= ASN1_IDENTIFIER_CONSTRUCTED;

    if (token->tag < 31)
    {
        *token->octet |= token->tag;

        token->octet++;
        token->tlen++;
        token->maxSize--;
    } else {
        int noct;
        uint32_t tag;

        *token->octet |= ASN1_IDENTIFIER_TAG_MASK;

        token->octet++;
        token->tlen++;
        token->maxSize--;

        tag = token->tag;
        noct = 0;
        while (tag)
        {
            tag >>= 7;
            noct++;
        }

        if (token->maxSize < noct)
            return 0;

        while (noct)
        {
            *token->octet = (token->tag >> (7 * (noct - 1))) & 0x7f;
            if (noct > 1)
                *token->octet |= 0x80;

            token->octet++;
            token->tlen++;
            token->maxSize--;
            noct--;
        }
    }

    return 1;
}
/*
 * RETURN
 *     1 on success, 0 on error.
 */
int asn_encode_length(struct asn_token_t *token, size_t length)
{
    if (token->maxSize < 1)
        return 0;

    if (length < 128)
    {
        *token->octet = length;

        token->octet++;
        token->tlen++;
        token->maxSize--;
    } else {
        size_t len;
        int noct;

        len = length;
        noct = 0;
        while (len)
        {
            len >>= 8;
            noct++;
        }

        if (noct > 127)
            return 0;

        *token->octet = 0x80 | noct;

        token->octet++;
        token->tlen++;
        token->maxSize--;

        if (token->maxSize < noct)
            return 0;

        while (noct)
        {
            *token->octet = (length >> (8 * (noct - 1))) & 0xff;

            token->octet++;
            token->tlen++;
            token->maxSize--;
            noct--;
        }
    }

    return 1;
}
/*
 * RETURN
 *     1 on success, 0 on error.
 */
int asn_encode_octet_string0(struct asn_token_t *token, uint8_t *string)
{
    return asn_encode_octet_string(token, string, strlen((char*)string));
}
/*
 * RETURN
 *     1 on success, 0 on error.
 */
int asn_encode_octet_string(struct asn_token_t *token, uint8_t *string, size_t length)
{
    token->tag = ASN1_IDENTIFIER_TAG_OCTET_STRING;

    return asn_encode_octet_string_idn(token, string, length);
}
/*
 *
 */
int asn_encode_octet_string_idn(struct asn_token_t *token, uint8_t *string, size_t length)
{
    if (!asn_encode_identifier(token))
        return 0;
    if (!asn_encode_length(token, length))
        return 0;

    if (token->maxSize < length)
        return 0;

    token->content.raw    = token->octet;
    token->content.length = length;

    memcpy(token->content.raw, string, token->content.length);

    token->tlen += length;

    return 1;


}
/*
 * XXX not tested well.
 */
int asn_encode_bit_string(struct asn_token_t *token, uint8_t *data, size_t nbits)
{
    int length;
    int shift;
    uint8_t *buf;

    token->class_ = ASN1_IDENTIFIER_CLASS_UNIVERSAL;
    token->tag = ASN1_IDENTIFIER_TAG_BIT_STRING;
    if (!asn_encode_identifier(token))
        return 0;

    shift = (nbits % 8);

    /* +1 for number of unused bits */
    length = nbits / 8 + (shift ? 1 : 0);
    if (!asn_encode_length(token, 1 + length))
        return 0;
    if (token->maxSize < (1 + length))
        return 0;

    token->tlen += 1 + length;
    token->content.raw    = token->octet;
    token->content.length = length + 1;

    buf = token->content.raw;
    *buf++ = shift;
    while (length--)
    {
        *buf = *data;
        if (length == 0)
            *buf <<= shift;
        buf++;
        data++;
    }

    return 1;
}

/*
 * RETURN
 *     1 on success, 0 on error.
 */
int asn_encode_null(struct asn_token_t *token)
{
    token->class_ = ASN1_IDENTIFIER_CLASS_UNIVERSAL;
    token->tag    = ASN1_IDENTIFIER_TAG_NULL;
    return asn_encode_null_idn(token);
}
int asn_encode_null_idn(struct asn_token_t *token)
{
    if (!asn_encode_identifier(token))
        return 0;
    if (!asn_encode_length(token, 0))
        return 0;
    return 1;
}
/*
 * RETURN
 *     1 on success, 0 on error.
 */
int asn_encode_object_identifier(struct asn_token_t *token, uint32_t *oid)
{
    int path;
    int clen;

    token->tag = ASN1_IDENTIFIER_TAG_OBJECT_IDENTIFIER;
    if (!asn_encode_identifier(token))
        return 0;

    /* At least path of two. */
    if (oid[0] == ASN_OID_SENTINEL || oid[1] == ASN_OID_SENTINEL)
        return 0;

    /*
     * Two times. One to calculate length - two for place data.
     */
    clen = 1;
    for (path = 0; path < 2; path++)
    {
        uint32_t *poid;

        poid = &oid[2];
        while (*poid != ASN_OID_SENTINEL)
        {
            uint32_t value;
            int noct;

            value = *poid;
            if (value == 0)
            {
                noct = 1;
            } else {
                noct = 0;
                while (value)
                {
                    value >>= 7;
                    noct++;
                }
            }

            if (path == 0)
                clen += noct;

            if (token->maxSize < noct)
                return 0;

            if (path == 1)
            {
                while (noct)
                {
                    *token->octet = ((*poid) >> (7 * (noct - 1))) & 0x7f;
                    if (noct > 1)
                        *token->octet |= 0x80;

                    token->octet++;
                    token->tlen++;
                    token->maxSize--;

                    noct--;
                }
            }

            poid++;
        }

        if (path == 0)
        {
            if (!asn_encode_length(token, clen))
                return 0;

            if (token->maxSize < 1)
                return 0;

            token->content.length = clen;
            token->content.raw = token->octet;

            *token->octet = oid[0] * 40 + oid[1];
            token->octet++;
            token->tlen++;
            token->maxSize--;
        }
    }

    return 1;
}
/*
 * RETURN
 *     1 on success, 0 on error.
 */
int asn_encode_sequence_tokens(struct asn_token_t *token, struct asn_token_t **ts)
{
    struct asn_token_t **pts;
    size_t clen;

    token->tag = ASN1_IDENTIFIER_TAG_SEQ_SEQOF;
    token->constructed = 1;
    if (!asn_encode_identifier(token))
        return 0;

    pts = ts;
    clen = 0;
    while (*pts)
    {
        clen += (*pts)->tlen;
        pts++;
    }

    if (clen > token->maxSize)
        return 0;

    if (!asn_encode_length(token, clen))
        return 0;

    token->content.raw = token->octet;
    pts = ts;
    while (*pts)
    {
        if ((*pts)->tlen > token->maxSize)
            return 0;

        memcpy(&token->content.raw[token->content.length], (*pts)->input, (*pts)->tlen);

        token->tlen           += (*pts)->tlen;
        token->content.length += (*pts)->tlen;
        token->maxSize        -= (*pts)->tlen;

        pts++;
    }

    return 1;
}
/*
 * RETURN
 *     1 on success, 0 on error.
 */
int asn_encode_sequence_raw(struct asn_token_t *token, struct asn_encode_raw_t *list)
{
    return asn_encode_raw(token, ASN1_IDENTIFIER_CLASS_UNIVERSAL, ASN1_IDENTIFIER_TAG_SEQ_SEQOF, 1, list);
}
/*
 *
 */
int asn_encode_sequence_raw1(struct asn_token_t *token, void *data, size_t size)
{
    struct asn_encode_raw_t list[2];

    list[0].data = data;
    list[0].size = size;
    list[1].data = NULL;

    return asn_encode_sequence_raw(token, list);
}
/*
 *
 */
int asn_encode_raw1(struct asn_token_t *token,
        uint8_t class_, uint32_t tag, int constructed, void *data, size_t size)
{
    struct asn_encode_raw_t list[2];

    list[0].data = data;
    list[0].size = size;
    list[1].data = NULL;

    return asn_encode_raw(token, class_, tag, constructed, list);
}
/*
 *
 */
int asn_encode_raw(struct asn_token_t *token,
        uint8_t class_, uint32_t tag, int constructed, struct asn_encode_raw_t *list)
{
    struct asn_encode_raw_t *plist;
    size_t size;

    token->class_ = class_;
    token->tag = tag;
    token->constructed = constructed;
    if (!asn_encode_identifier(token))
        return 0;

    plist = list;
    size = 0;
    while (plist->data)
    {
        size += plist->size;
        plist++;
    }

    if (!asn_encode_length(token, size))
        return 0;

    if (size > token->maxSize)
        return 0;

    {
        uint8_t *src, *dst;

        plist = list;
        token->content.raw    = token->octet;
        token->content.length = size;
        token->tlen          += size;
        token->maxSize       -= size;

        dst = token->content.raw;
        while (plist->data)
        {
            src = plist->data;

            memcpy(dst, src, plist->size);
            dst += plist->size;
            plist++;
        }
    }

    return 1;
}
/*
 *
 */
int asn_encode_integer_idn(struct asn_token_t *token, int64_t integer)
{
    int noct;
    uint64_t value;

    if (!asn_encode_identifier(token))
        return 0;

    if (integer == 0)
    {
        noct = 1;
    } else {
        noct = 0;
        value = integer;
        do
        {
            uint8_t octet;

            octet = value & 0xff;

            value >>= 8;
            noct++;

            if (integer > 0)
            {
                if (value == 0 && (octet & 0x80))
                    noct++;
            }
        } while (value);
    }

    /*
     * Reduce signed integer size.
     */
    if (integer < 0 && noct > 1)
    {
        int width; 

        width = noct;
        value = integer;
        while (width > 1)
        {
            uint8_t octetH;
            uint8_t octetL;

            octetH = value >> (8 * (width - 1));
            octetL = value >> (8 * (width - 2));

            if ((octetH & 0xff) == 0xff && (octetL & 0x80))
                noct--;
            width--;
        }
    }

    if (!asn_encode_length(token, noct))
        return 0;

    if (token->maxSize < noct)
        return 0;

    token->content.raw    = token->octet;
    token->content.length = noct;

    value = integer;
    while (noct)
    {
        *token->octet = (value >> (8 * (noct - 1))) & 0xff;

        token->octet++;
        token->tlen++;
        token->maxSize--;
        noct--;
    }

    return 1;
}
/*
 *
 */
int asn_encode_integer(struct asn_token_t *token, int64_t integer)
{
    token->class_ = ASN1_IDENTIFIER_CLASS_UNIVERSAL;
    token->tag    = ASN1_IDENTIFIER_TAG_INTEGER;

    return asn_encode_integer_idn(token, integer);
}

