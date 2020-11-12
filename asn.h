/*
 * Jaroj 2018-2020.
 * Auxtoro estas Dmitrij Kobilin. 
 *
 * Nenia rajtigilo ekzistas.
 * Faru bone, ne faru malbone.
 */
#ifndef _ASN_H
#define _ASN_H

#include <stdlib.h>
#include <stdint.h>

/*
 * ARGS
 *     inBuf
 *     n
 *     arg
 *
 * RETURN
 *     NULL if no characters remain.
 *
 */
//typedef uint8_t* (*asnGetOctetsFunc)(uint8_t *, size_t n, void *);

#define ASN_OID_MAX_LEN    32 /* XXX */
#define ASN_OID_SENTINEL   0xffffffff /* XXX */

struct asn_token_t {
    uint8_t *input;
    uint8_t *octet;
    size_t maxSize;

    size_t tlen;      /* Whole token length. */

    struct {
        uint8_t constructed: 1;
    };
    uint8_t class_; 
    uint32_t tag;

    /*
     * Decoded data, data to encode.
     */
    struct {
        union {
            int64_t integer;
        };
        uint8_t *raw;
        size_t length;
        uint32_t oid[ASN_OID_MAX_LEN + 1];
    } content;
};

void asn_token_init(struct asn_token_t *token, uint8_t *octet, size_t maxSize);
size_t asn_token_get(struct asn_token_t *token);

void asn_oid_print(uint32_t *oid);
void asn_token_print(struct asn_token_t *token);

int asn_encode_identifier(struct asn_token_t *token);
int asn_encode_length(struct asn_token_t *token, size_t length);
int asn_encode_octet_string0(struct asn_token_t *token, uint8_t *string);
int asn_encode_octet_string(struct asn_token_t *token, uint8_t *string, size_t length);
int asn_encode_octet_string_idn(struct asn_token_t *token, uint8_t *string, size_t length);
int asn_encode_bit_string(struct asn_token_t *token, uint8_t *data, size_t nbits);
int asn_encode_null(struct asn_token_t *token);
int asn_encode_null_idn(struct asn_token_t *token);
int asn_encode_object_identifier(struct asn_token_t *token, uint32_t *oid);
int asn_encode_sequence_tokens(struct asn_token_t *token, struct asn_token_t **ts);
int asn_encode_integer_idn(struct asn_token_t *token, int64_t integer);
int asn_encode_integer(struct asn_token_t *token, int64_t integer);
struct asn_encode_raw_t {
    void *data;
    size_t size;
};

int asn_encode_raw(struct asn_token_t *token,
        uint8_t class_, uint32_t tag, int constructed, struct asn_encode_raw_t *list);
int asn_encode_raw1(struct asn_token_t *token,
        uint8_t class_, uint32_t tag, int constructed, void *data, size_t size);
int asn_encode_sequence_raw(struct asn_token_t *token, struct asn_encode_raw_t *list);
int asn_encode_sequence_raw1(struct asn_token_t *token, void *data, size_t size);

#define ASN1_IDENTIFIER_TAG_MASK              (0x1f << 0)
#define ASN1_IDENTIFIER_TAG_INTEGER               2
#define ASN1_IDENTIFIER_TAG_BIT_STRING            3
#define ASN1_IDENTIFIER_TAG_OCTET_STRING          4
#define ASN1_IDENTIFIER_TAG_NULL                  5
#define ASN1_IDENTIFIER_TAG_OBJECT_IDENTIFIER     6
#define ASN1_IDENTIFIER_TAG_SEQ_SEQOF            16

#define ASN1_IDENTIFIER_CLASS_SHIFT       6
#define ASN1_IDENTIFIER_CLASS_MASK        (0x03 << ASN1_IDENTIFIER_CLASS_SHIFT)

#define ASN1_IDENTIFIER_CLASS_UNIVERSAL   (0x00 << ASN1_IDENTIFIER_CLASS_SHIFT)
#define ASN1_IDENTIFIER_CLASS_APPLICATION (0x01 << ASN1_IDENTIFIER_CLASS_SHIFT)
#define ASN1_IDENTIFIER_CLASS_CONTEXT     (0x02 << ASN1_IDENTIFIER_CLASS_SHIFT)
#define ASN1_IDENTIFIER_CLASS_PRIVATE     (0x03 << ASN1_IDENTIFIER_CLASS_SHIFT)

#endif

