#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <oqs/oqs.h>

#define NONCE_LEN 16
#define KEY_LEN   32
#define PSN_LEN   32

/* ===================== Utility ===================== */

static int random_bytes(unsigned char *buf, int len) {
    return RAND_bytes(buf, len) == 1 ? 0 : -1;
}

static void print_hex(const char *label, const unsigned char *buf, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; i++)
        printf("%02X", buf[i]);
    printf("\n");
}

/* ===================== HASH / HMAC / KDF ===================== */

static void hash(const unsigned char *input, int len, unsigned char *output) {
    SHA256(input, len, output);
}

static void compute_hmac(const unsigned char *key, int keylen,
                         const unsigned char *data, int datalen,
                         unsigned char *out) {
    unsigned int len;
    HMAC(EVP_sha256(), key, keylen, data, datalen, out, &len);
}

static void kdf(const unsigned char *input, int len, unsigned char *output) {
    hash(input, len, output);
}

/* ===================== PUF + FE (Simulated) ===================== */

/* Gen(PUF) -> (sigma, helper data) */
static void FE_Gen(const unsigned char *puf, unsigned char *sigma, unsigned char *hd) {
    hash(puf, 32, sigma);
    memcpy(hd, puf, 32);   /* helper data (simulated) */
}

/* Rep(PUF, hd) -> sigma */
static void FE_Rep(const unsigned char *puf, const unsigned char *hd, unsigned char *sigma) {
    (void)hd;
    hash(puf, 32, sigma);
}

/* ===================== Entities ===================== */

typedef struct {
    OQS_KEM *kem;
    uint8_t *pk;
    uint8_t *sk;
} Entity;

/* ===================== MAIN ===================== */

int main(void) {
    int ok = 1;

    printf("=== Protocol Simulation Start ===\n");

    /* ---------- INIT KYBER ---------- */
    Entity O, R;   /* O = Vehicle (OBU), R = RSU */

    O.kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    R.kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (!O.kem || !R.kem) {
        fprintf(stderr, "KEM not available in this liboqs build\n");
        return 1;
    }

    O.pk = malloc(O.kem->length_public_key);
    O.sk = malloc(O.kem->length_secret_key);
    R.pk = malloc(R.kem->length_public_key);
    R.sk = malloc(R.kem->length_secret_key);

    OQS_KEM_keypair(O.kem, O.pk, O.sk);
    OQS_KEM_keypair(R.kem, R.pk, R.sk);

    /* ---------- PUF ENROLLMENT ---------- */
    unsigned char puf[32], sigma[32], hd[32];
    random_bytes(puf, 32);
    FE_Gen(puf, sigma, hd);

    /* ---------- REGISTRATION ---------- */
    unsigned char PSN[PSN_LEN];
    hash(puf, 32, PSN);   /* simplified PSN */

    /* RSU stores sigma and PSN for this vehicle */
    unsigned char AuthK_R[32];
    {
        unsigned char in[68];
        memcpy(in, sigma, 32);
        memcpy(in + 32, PSN, 32);
        memcpy(in + 64, "RSU1", 4);
        hash(in, 68, AuthK_R);
    }

    /* ---------- STEP 1/2: Vehicle request (M1) ---------- */
    unsigned char sigma_rec[32];
    FE_Rep(puf, hd, sigma_rec);   /* ideal (noise-free) PUF re-evaluation */

    unsigned char auth_input[68];
    memcpy(auth_input, sigma_rec, 32);
    memcpy(auth_input + 32, PSN, 32);
    memcpy(auth_input + 64, "RSU1", 4);

    unsigned char AuthK_O[32];
    hash(auth_input, 68, AuthK_O);

    unsigned char nO[NONCE_LEN];
    random_bytes(nO, NONCE_LEN);

    uint8_t *ctOR = malloc(R.kem->length_ciphertext);
    uint8_t KO_R[KEY_LEN];
    OQS_KEM_encaps(R.kem, ctOR, KO_R, R.pk);

    unsigned char M1[32];
    compute_hmac(AuthK_O, 32, ctOR, (int)R.kem->length_ciphertext, M1);

    printf("Vehicle -> RSU: M1 sent\n");

    /* ---------- STEP 3: RSU response (M2) ---------- */
    unsigned char M1_chk[32];
    compute_hmac(AuthK_R, 32, ctOR, (int)R.kem->length_ciphertext, M1_chk);
    if (memcmp(M1, M1_chk, 32) != 0) ok = 0;   /* RSU verifies M1 */

    uint8_t KO_R_dec[KEY_LEN];
    OQS_KEM_decaps(R.kem, KO_R_dec, ctOR, R.sk);

    uint8_t *ctRO = malloc(O.kem->length_ciphertext);
    uint8_t KR_O[KEY_LEN];
    OQS_KEM_encaps(O.kem, ctRO, KR_O, O.pk);

    unsigned char nR[NONCE_LEN];
    random_bytes(nR, NONCE_LEN);

    unsigned char sess_input[128];
    memcpy(sess_input,       KO_R_dec, 32);
    memcpy(sess_input + 32,  KR_O,     32);
    memcpy(sess_input + 64,  PSN,      32);
    memcpy(sess_input + 96,  nO,       16);
    memcpy(sess_input + 112, nR,       16);

    unsigned char Ksess_R[32];
    kdf(sess_input, 128, Ksess_R);

    printf("RSU -> Vehicle: M2 sent\n");

    /* ---------- STEP 4: Vehicle final (M3) ---------- */
    uint8_t KR_O_dec[KEY_LEN];
    OQS_KEM_decaps(O.kem, KR_O_dec, ctRO, O.sk);

    unsigned char sess_input2[128];
    memcpy(sess_input2,       KO_R,      32);
    memcpy(sess_input2 + 32,  KR_O_dec,  32);
    memcpy(sess_input2 + 64,  PSN,       32);
    memcpy(sess_input2 + 96,  nO,        16);
    memcpy(sess_input2 + 112, nR,        16);

    unsigned char Ksess_O[32];
    kdf(sess_input2, 128, Ksess_O);

    unsigned char M3[32], M3_chk[32];
    compute_hmac(Ksess_O, 32, nR, NONCE_LEN, M3);
    compute_hmac(Ksess_R, 32, nR, NONCE_LEN, M3_chk);   /* RSU verifies M3 */
    if (memcmp(M3, M3_chk, 32) != 0) ok = 0;

    /* ---------- PRINT VALUES ---------- */
    print_hex("KO_R (Vehicle)", KO_R,     KEY_LEN);
    print_hex("KO_R (RSU)   ",  KO_R_dec, KEY_LEN);
    print_hex("KR_O (RSU)   ",  KR_O,     KEY_LEN);
    print_hex("KR_O (Vehicle)", KR_O_dec, KEY_LEN);
    print_hex("nO", nO, NONCE_LEN);
    print_hex("nR", nR, NONCE_LEN);
    print_hex("Vehicle Session Key", Ksess_O, 32);
    print_hex("RSU Session Key    ", Ksess_R, 32);

    /* ---------- VERIFY ---------- */
    if (ok && memcmp(Ksess_O, Ksess_R, 32) == 0)
        printf("SUCCESS: Session keys match!\n");
    else
        printf("FAIL: Keys mismatch!\n");

    printf("=== Protocol Complete ===\n");

    /* ---------- CLEANUP ---------- */
    free(ctOR); free(ctRO);
    free(O.pk); free(O.sk); free(R.pk); free(R.sk);
    OQS_KEM_free(O.kem);
    OQS_KEM_free(R.kem);

    return 0;
}