/* ecrypt-sync.h */

/* 
 * Header file for synchronous stream ciphers without authentication
 * mechanism.
 * 
 * *** Please only edit parts marked with "[edit]". ***
 */

#ifndef ECRYPT_SYNC
#define ECRYPT_SYNC

#include "ecrypt-portable.h"
#include "rename_functions.h"

/* RABBIT */
/* ------------------------------------------------------------------------- */

/* Cipher parameters */

/* 
 * The name of your cipher.
 */
#define RABBIT_NAME "Rabbit Stream Cipher"

/*
 * Specify which key and IV sizes are supported by your cipher. A user
 * should be able to enumerate the supported sizes by running the
 * following code:
 *
 * for (i = 0; ECRYPT_KEYSIZE(i) <= ECRYPT_MAXKEYSIZE; ++i)
 *   {
 *     keysize = ECRYPT_KEYSIZE(i);
 *
 *     ...
 *   }
 *
 * All sizes are in bits.
 */

#define RABBIT_MAXKEYSIZE 128
#define RABBIT_KEYSIZE(i) (128 + (i)*32)

#define RABBIT_MAXIVSIZE 64
#define RABBIT_IVSIZE(i) (64 + (i)*64)

/* ------------------------------------------------------------------------- */

/* Data structures */

/* 
 * ECRYPT_ctx is the structure containing the representation of the
 * internal state of your cipher. 
 */

typedef struct
{
   u32 x[8];
   u32 c[8];
   u32 carry;
} RABBIT_ctx2;

typedef struct
{
  /* 
   * Put here all state variable needed during the encryption process.
   */
   RABBIT_ctx2 master_ctx;
   RABBIT_ctx2 work_ctx;
} RABBIT_ctx;

/* ------------------------------------------------------------------------- */

/* Mandatory functions */

/*
 * Key and message independent initialization. This function will be
 * called once when the program starts (e.g., to build expanded S-box
 * tables).
 */
void ECRYPT_init(void);

/*
 * Key setup. It is the user's responsibility to select the values of
 * keysize and ivsize from the set of supported values specified
 * above.
 */
void RABBIT_keysetup(
  RABBIT_ctx* ctx, 
  const u8* key, 
  u32 keysize,                /* Key size in bits. */ 
  u32 ivsize);                /* IV size in bits. */ 

/*
 * IV setup. After having called ECRYPT_keysetup(), the user is
 * allowed to call ECRYPT_ivsetup() different times in order to
 * encrypt/decrypt different messages with the same key but different
 * IV's.
 */
void RABBIT_ivsetup(
  RABBIT_ctx* ctx, 
  const u8* iv);

/*
 * Encryption/decryption of arbitrary length messages.
 *
 * For efficiency reasons, the API provides two types of
 * encrypt/decrypt functions. The ECRYPT_encrypt_bytes() function
 * (declared here) encrypts byte strings of arbitrary length, while
 * the ECRYPT_encrypt_blocks() function (defined later) only accepts
 * lengths which are multiples of ECRYPT_BLOCKLENGTH.
 * 
 * The user is allowed to make multiple calls to
 * ECRYPT_encrypt_blocks() to incrementally encrypt a long message,
 * but he is NOT allowed to make additional encryption calls once he
 * has called ECRYPT_encrypt_bytes() (unless he starts a new message
 * of course). For example, this sequence of calls is acceptable:
 *
 * ECRYPT_keysetup();
 *
 * ECRYPT_ivsetup();
 * ECRYPT_encrypt_blocks();
 * ECRYPT_encrypt_blocks();
 * ECRYPT_encrypt_bytes();
 *
 * ECRYPT_ivsetup();
 * ECRYPT_encrypt_blocks();
 * ECRYPT_encrypt_blocks();
 *
 * ECRYPT_ivsetup();
 * ECRYPT_encrypt_bytes();
 * 
 * The following sequence is not:
 *
 * ECRYPT_keysetup();
 * ECRYPT_ivsetup();
 * ECRYPT_encrypt_blocks();
 * ECRYPT_encrypt_bytes();
 * ECRYPT_encrypt_blocks();
 */

/*
 * By default ECRYPT_encrypt_bytes() and ECRYPT_decrypt_bytes() are
 * defined as macros which redirect the call to a single function
 * ECRYPT_process_bytes(). If you want to provide separate encryption
 * and decryption functions, please undef
 * ECRYPT_HAS_SINGLE_BYTE_FUNCTION.
 */
#define RABBIT_HAS_SINGLE_BYTE_FUNCTION
#ifdef RABBIT_HAS_SINGLE_BYTE_FUNCTION

#define RABBIT_encrypt_bytes(ctx, plaintext, ciphertext, msglen)   \
  RABBIT_process_bytes(0, ctx, plaintext, ciphertext, msglen)

#define RABBIT_decrypt_bytes(ctx, ciphertext, plaintext, msglen)   \
  RABBIT_process_bytes(1, ctx, ciphertext, plaintext, msglen)

void RABBIT_process_bytes(
  int action,                 /* 0 = encrypt; 1 = decrypt; */
  RABBIT_ctx* ctx, 
  const u8* input, 
  u8* output, 
  u32 msglen);                /* Message length in bytes. */ 

#else

void RABBIT_encrypt_bytes(
  RABBIT_ctx* ctx, 
  const u8* plaintext, 
  u8* ciphertext, 
  u32 msglen);                /* Message length in bytes. */ 

void RABBIT_decrypt_bytes(
  RABBIT_ctx* ctx, 
  const u8* ciphertext, 
  u8* plaintext, 
  u32 msglen);                /* Message length in bytes. */ 

#endif

/* ------------------------------------------------------------------------- */

/* Optional features */

/* 
 * For testing purposes it can sometimes be useful to have a function
 * which immediately generates keystream without having to provide it
 * with a zero plaintext. If your cipher cannot provide this function
 * (e.g., because it is not strictly a synchronous cipher), please
 * reset the ECRYPT_GENERATES_KEYSTREAM flag.
 */

#define RABBIT_GENERATES_KEYSTREAM
#ifdef RABBIT_GENERATES_KEYSTREAM

void RABBIT_keystream_bytes(
  RABBIT_ctx* ctx,
  u8* keystream,
  u32 length);                /* Length of keystream in bytes. */

#endif

/* ------------------------------------------------------------------------- */

/* Optional optimizations */

/* 
 * By default, the functions in this section are implemented using
 * calls to functions declared above. However, you might want to
 * implement them differently for performance reasons.
 */

/*
 * All-in-one encryption/decryption of (short) packets.
 *
 * The default definitions of these functions can be found in
 * "ecrypt-sync.c". If you want to implement them differently, please
 * undef the ECRYPT_USES_DEFAULT_ALL_IN_ONE flag.
 */
#define RABBIT_USES_DEFAULT_ALL_IN_ONE

/*
 * Undef ECRYPT_HAS_SINGLE_PACKET_FUNCTION if you want to provide
 * separate packet encryption and decryption functions.
 */
#define RABBIT_HAS_SINGLE_PACKET_FUNCTION
#ifdef RABBIT_HAS_SINGLE_PACKET_FUNCTION

#define RABBIT_encrypt_packet(                                        \
    ctx, iv, plaintext, ciphertext, mglen)                            \
  RABBIT_process_packet(0,                                            \
    ctx, iv, plaintext, ciphertext, mglen)

#define RABBIT_decrypt_packet(                                        \
    ctx, iv, ciphertext, plaintext, mglen)                            \
  RABBIT_process_packet(1,                                            \
    ctx, iv, ciphertext, plaintext, mglen)

void RABBIT_process_packet(
  int action,                 /* 0 = encrypt; 1 = decrypt; */
  RABBIT_ctx* ctx, 
  const u8* iv,
  const u8* input, 
  u8* output, 
  u32 msglen);

#else

void RABBIT_encrypt_packet(
  RABBIT_ctx* ctx, 
  const u8* iv,
  const u8* plaintext, 
  u8* ciphertext, 
  u32 msglen);

void RABBIT_decrypt_packet(
  RABBIT_ctx* ctx, 
  const u8* iv,
  const u8* ciphertext, 
  u8* plaintext, 
  u32 msglen);

#endif

/*
 * Encryption/decryption of blocks.
 * 
 * By default, these functions are defined as macros. If you want to
 * provide a different implementation, please undef the
 * ECRYPT_USES_DEFAULT_BLOCK_MACROS flag and implement the functions
 * declared below.
 */

#define RABBIT_BLOCKLENGTH 16

#undef RABBIT_USES_DEFAULT_BLOCK_MACROS
#ifdef RABBIT_USES_DEFAULT_BLOCK_MACROS

#define RABBIT_encrypt_blocks(ctx, plaintext, ciphertext, blocks)  \
  RABBIT_encrypt_bytes(ctx, plaintext, ciphertext,                 \
    (blocks) * RABBIT_BLOCKLENGTH)

#define RABBIT_decrypt_blocks(ctx, ciphertext, plaintext, blocks)  \
  RABBIT_decrypt_bytes(ctx, ciphertext, plaintext,                 \
    (blocks) * RABBIT_BLOCKLENGTH)

#ifdef RABBIT_GENERATES_KEYSTREAM

#define RABBIT_keystream_blocks(ctx, keystream, blocks)            \
  RABBIT_keystream_bytes(ctx, keystream,                           \
    (blocks) * RABBIT_BLOCKLENGTH)

#endif

#else

/*
 * Undef ECRYPT_HAS_SINGLE_BLOCK_FUNCTION if you want to provide
 * separate block encryption and decryption functions.
 */
#define RABBIT_HAS_SINGLE_BLOCK_FUNCTION
#ifdef RABBIT_HAS_SINGLE_BLOCK_FUNCTION

#define RABBIT_encrypt_blocks(ctx, plaintext, ciphertext, blocks)     \
  RABBIT_process_blocks(0, ctx, plaintext, ciphertext, blocks)

#define RABBIT_decrypt_blocks(ctx, ciphertext, plaintext, blocks)     \
  RABBIT_process_blocks(1, ctx, ciphertext, plaintext, blocks)

void RABBIT_process_blocks(
  int action,                 /* 0 = encrypt; 1 = decrypt; */
  RABBIT_ctx* ctx, 
  const u8* input, 
  u8* output, 
  u32 blocks);                /* Message length in blocks. */

#else

void RABBIT_encrypt_blocks(
  RABBIT_ctx* ctx, 
  const u8* plaintext, 
  u8* ciphertext, 
  u32 blocks);                /* Message length in blocks. */ 

void RABBIT_decrypt_blocks(
  RABBIT_ctx* ctx, 
  const u8* ciphertext, 
  u8* plaintext, 
  u32 blocks);                /* Message length in blocks. */ 

#endif

#ifdef RABBIT_GENERATES_KEYSTREAM

void RABBIT_keystream_blocks(
  RABBIT_ctx* ctx,
  u8* keystream,
  u32 blocks);                /* Keystream length in blocks. */ 

#endif

#endif

/*
 * If your cipher can be implemented in different ways, you can use
 * the ECRYPT_VARIANT parameter to allow the user to choose between
 * them at compile time (e.g., gcc -DECRYPT_VARIANT=3 ...). Please
 * only use this possibility if you really think it could make a
 * significant difference and keep the number of variants
 * (ECRYPT_MAXVARIANT) as small as possible (definitely not more than
 * 10). Note also that all variants should have exactly the same
 * external interface (i.e., the same ECRYPT_BLOCKLENGTH, etc.). 
 */
#define RABBIT_MAXVARIANT 1

#ifndef RABBIT_VARIANT
#define RABBIT_VARIANT 1
#endif

#if (RABBIT_VARIANT > RABBIT_MAXVARIANT)
#error this variant does not exist
#endif

/* ------------------------------------------------------------------------- */

/* SALSA */
/* ------------------------------------------------------------------------- */

/* Cipher parameters */

/* 
 * The name of your cipher.
 */
#define SALSA_NAME "Salsa20 stream cipher"    /* [edit] */ 

/*
 * Specify which key and IV sizes are supported by your cipher. A user
 * should be able to enumerate the supported sizes by running the
 * following code:
 *
 * for (i = 0; ECRYPT_KEYSIZE(i) <= ECRYPT_MAXKEYSIZE; ++i)
 *   {
 *     keysize = ECRYPT_KEYSIZE(i);
 *
 *     ...
 *   }
 *
 * All sizes are in bits.
 */

#define SALSA_MAXKEYSIZE 256                 /* [edit] */
#define SALSA_KEYSIZE(i) (128 + (i)*128)     /* [edit] */

#define SALSA_MAXIVSIZE 64                   /* [edit] */
#define SALSA_IVSIZE(i) (64 + (i)*64)        /* [edit] */

/* ------------------------------------------------------------------------- */

/* Data structures */

/* 
 * ECRYPT_ctx is the structure containing the representation of the
 * internal state of your cipher. 
 */

typedef struct
{
    u32 input[16]; /* could be compressed */
    /* 
     * [edit]
     *
     * Put here all state variable needed during the encryption process.
     */
} SALSA_ctx;

/* ------------------------------------------------------------------------- */

/* Mandatory functions */

/*
 * Key and message independent initialization. This function will be
 * called once when the program starts (e.g., to build expanded S-box
 * tables).
 */
void SALSA_init();

/*
 * Key setup. It is the user's responsibility to select the values of
 * keysize and ivsize from the set of supported values specified
 * above.
 */
void SALSA_keysetup(
                    SALSA_ctx* ctx, 
                    const u8* key, 
                    u32 keysize,                /* Key size in bits. */ 
                    u32 ivsize);                /* IV size in bits. */ 

/*
 * IV setup. After having called ECRYPT_keysetup(), the user is
 * allowed to call ECRYPT_ivsetup() different times in order to
 * encrypt/decrypt different messages with the same key but different
 * IV's.
 */
void SALSA_ivsetup(
                   SALSA_ctx* ctx, 
                   const u8* iv);

/*
 * Encryption/decryption of arbitrary length messages.
 *
 * For efficiency reasons, the API provides two types of
 * encrypt/decrypt functions. The ECRYPT_encrypt_bytes() function
 * (declared here) encrypts byte strings of arbitrary length, while
 * the ECRYPT_encrypt_blocks() function (defined later) only accepts
 * lengths which are multiples of ECRYPT_BLOCKLENGTH.
 * 
 * The user is allowed to make multiple calls to
 * ECRYPT_encrypt_blocks() to incrementally encrypt a long message,
 * but he is NOT allowed to make additional encryption calls once he
 * has called ECRYPT_encrypt_bytes() (unless he starts a new message
 * of course). For example, this sequence of calls is acceptable:
 *
 * ECRYPT_keysetup();
 *
 * ECRYPT_ivsetup();
 * ECRYPT_encrypt_blocks();
 * ECRYPT_encrypt_blocks();
 * ECRYPT_encrypt_bytes();
 *
 * ECRYPT_ivsetup();
 * ECRYPT_encrypt_blocks();
 * ECRYPT_encrypt_blocks();
 *
 * ECRYPT_ivsetup();
 * ECRYPT_encrypt_bytes();
 * 
 * The following sequence is not:
 *
 * ECRYPT_keysetup();
 * ECRYPT_ivsetup();
 * ECRYPT_encrypt_blocks();
 * ECRYPT_encrypt_bytes();
 * ECRYPT_encrypt_blocks();
 */

void SALSA_encrypt_bytes(
                         SALSA_ctx* ctx, 
                         const u8* plaintext, 
                         u8* ciphertext, 
                         u32 msglen);                /* Message length in bytes. */ 

void SALSA_decrypt_bytes(
                         SALSA_ctx* ctx, 
                         const u8* ciphertext, 
                         u8* plaintext, 
                         u32 msglen);                /* Message length in bytes. */ 

/* ------------------------------------------------------------------------- */

/* Optional features */

/* 
 * For testing purposes it can sometimes be useful to have a function
 * which immediately generates keystream without having to provide it
 * with a zero plaintext. If your cipher cannot provide this function
 * (e.g., because it is not strictly a synchronous cipher), please
 * reset the ECRYPT_GENERATES_KEYSTREAM flag.
 */

#define SALSA_GENERATES_KEYSTREAM
#ifdef SALSA_GENERATES_KEYSTREAM

void SALSA_keystream_bytes(
                           SALSA_ctx* ctx,
                           u8* keystream,
                           u32 length);                /* Length of keystream in bytes. */

#endif

/* ------------------------------------------------------------------------- */

/* Optional optimizations */

/* 
 * By default, the functions in this section are implemented using
 * calls to functions declared above. However, you might want to
 * implement them differently for performance reasons.
 */

/*
 * All-in-one encryption/decryption of (short) packets.
 *
 * The default definitions of these functions can be found in
 * "ecrypt-sync.c". If you want to implement them differently, please
 * undef the ECRYPT_USES_DEFAULT_ALL_IN_ONE flag.
 */
#define SALSA_USES_DEFAULT_ALL_IN_ONE        /* [edit] */

void SALSA_encrypt_packet(
                          SALSA_ctx* ctx, 
                          const u8* iv,
                          const u8* plaintext, 
                          u8* ciphertext, 
                          u32 msglen);

void SALSA_decrypt_packet(
                          SALSA_ctx* ctx, 
                          const u8* iv,
                          const u8* ciphertext, 
                          u8* plaintext, 
                          u32 msglen);

/*
 * Encryption/decryption of blocks.
 * 
 * By default, these functions are defined as macros. If you want to
 * provide a different implementation, please undef the
 * ECRYPT_USES_DEFAULT_BLOCK_MACROS flag and implement the functions
 * declared below.
 */

#define SALSA_BLOCKLENGTH 64                  /* [edit] */

#define SALSA_USES_DEFAULT_BLOCK_MACROS      /* [edit] */
#ifdef SALSA_USES_DEFAULT_BLOCK_MACROS

#define SALSA_encrypt_blocks(ctx, plaintext, ciphertext, blocks)  \
SALSA_encrypt_bytes(ctx, plaintext, ciphertext,                 \
(blocks) * SALSA_BLOCKLENGTH)

#define SALSA_decrypt_blocks(ctx, ciphertext, plaintext, blocks)  \
SALSA_decrypt_bytes(ctx, ciphertext, plaintext,                 \
(blocks) * SALSA_BLOCKLENGTH)

#ifdef SALSA_GENERATES_KEYSTREAM

#define SALSA_keystream_blocks(ctx, keystream, blocks)            \
SALSA_AE_keystream_bytes(ctx, keystream,                        \
(blocks) * SALSA_BLOCKLENGTH)

#endif

#else

void SALSA_encrypt_blocks(
                          SALSA_ctx* ctx, 
                          const u8* plaintext, 
                          u8* ciphertext, 
                          u32 blocks);                /* Message length in blocks. */ 

void SALSA_decrypt_blocks(
                          SALSA_ctx* ctx, 
                          const u8* ciphertext, 
                          u8* plaintext, 
                          u32 blocks);                /* Message length in blocks. */ 

#ifdef SALSA_GENERATES_KEYSTREAM

void SALSA_keystream_blocks(
                            SALSA_AE_ctx* ctx,
                            const u8* keystream,
                            u32 blocks);                /* Keystream length in blocks. */ 

#endif

#endif

/* ------------------------------------------------------------------------- */

#endif
