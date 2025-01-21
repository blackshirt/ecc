module xecc

// Wrapper of digest and signing related of the C opaque and functions.
//
@[typedef]
struct C.EVP_MD {}

@[typedef]
struct C.EVP_MD_CTX {}

fn C.EVP_MD_free(md &C.EVP_MD)

fn C.EVP_sha256() &C.EVP_MD
fn C.EVP_sha384() &C.EVP_MD
fn C.EVP_sha512() &C.EVP_MD
fn C.EVP_sha3_256() &C.EVP_MD
fn C.EVP_sha3_384() &C.EVP_MD
fn C.EVP_sha3_512() &C.EVP_MD
fn C.EVP_shake128() &C.EVP_MD
fn C.EVP_shake256() &C.EVP_MD

fn C.EVP_MD_CTX_new() &C.EVP_MD_CTX
fn C.EVP_MD_CTX_free(ctx &C.EVP_MD_CTX)
fn C.EVP_MD_CTX_set_pkey_ctx(ctx &C.EVP_MD_CTX, pctx &C.EVP_PKEY_CTX)

// int EVP_DigestSign(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen);
fn C.EVP_DigestSign(ctx &C.EVP_MD_CTX, sig &u8, siglen &usize, tbs &u8, tbslen int) int

// int EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
fn C.EVP_DigestSignInit(ctx &C.EVP_MD_CTX, pctx &&C.EVP_PKEY_CTX, tipe &C.EVP_MD, e voidptr, pkey &C.EVP_PKEY) int

// int EVP_DigestSignUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);
fn C.EVP_DigestSignUpdate(ctx &C.EVP_MD_CTX, d voidptr, cnt int) int

// int EVP_DigestSignFinal(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen);
fn C.EVP_DigestSignFinal(ctx &C.EVP_MD_CTX, sig &u8, siglen &usize) int

// int EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
fn C.EVP_DigestVerifyInit(ctx &C.EVP_MD_CTX, pctx &&C.EVP_PKEY_CTX, tipe &C.EVP_MD, e voidptr, pkey &C.EVP_PKEY) int

// int EVP_DigestVerifyUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);
fn C.EVP_DigestVerifyUpdate(ctx &C.EVP_MD_CTX, d voidptr, cnt int) int

// int EVP_DigestVerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen);
fn C.EVP_DigestVerifyFinal(ctx &C.EVP_MD_CTX, sig &u8, siglen int) int

// int EVP_DigestVerify(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen);
fn C.EVP_DigestVerify(ctx &C.EVP_MD_CTX, sig &u8, siglen int, tbs &u8, tbslen int) int
