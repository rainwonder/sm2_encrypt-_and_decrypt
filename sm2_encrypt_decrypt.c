
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/ossl_typ.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sm2.h>
#include <openssl/opensslconf.h>
#include <openssl/obj_mac.h>

char *buf2hexstr(const unsigned char *buffer, long len)
{
    static const char hexdig[] = "0123456789ABCDEF";
    char *tmp, *q;
    const unsigned char *p;
    int i;

    if (len == 0)
    {
        return OPENSSL_zalloc(1);
    }

    if ((tmp = OPENSSL_malloc(len * 2 +1)) == NULL) {
 
        return NULL;
    }
    q = tmp;
    for (i = 0, p = buffer; i < len; i++, p++) {
        *q++ = hexdig[(*p >> 4) & 0xf];
        *q++ = hexdig[*p & 0xf];
    }
    q[0] = 0;

    return tmp;
}

int  sm2_keypair( char **hexstr_priv,  char **hexstr_pub)
{
	EC_POINT *pub_key = NULL;
	EC_KEY *ec_key = NULL;
	unsigned char* pubkey =NULL;
	BN_CTX *ctx =NULL;
	int len = 0;
	const BIGNUM * pri;
	int ok = 0;
	if(!(ec_key = EC_KEY_new_by_curve_name(NID_sm2))) {
		return ok;
	}
	///Creates a new ec private (and optional a new public) key.
	if ( 0 == EC_KEY_generate_key(ec_key)) {
		printf("EC_KEY_generate_key\n");
		return ok;
	}
	
	if ( 0 == (len = EC_KEY_key2buf(ec_key,POINT_CONVERSION_UNCOMPRESSED,&pubkey, ctx))) {
		printf("err\n");
		return ok;
	}
	
	pri = EC_KEY_get0_private_key((const EC_KEY *)ec_key); 
	*hexstr_pub   = buf2hexstr (pubkey, len);
	*hexstr_priv = BN_bn2hex((const BIGNUM *)pri);
	printf("public_key:%s\n", *hexstr_pub);
	printf("prikey_key:%s\n", *hexstr_priv);

	EC_KEY_free (ec_key);
	ok = 1;
	return ok;

}
unsigned char * sm2_sign(const char *userid,
							const char *privkey_hexstr,
							const char *message)
{
	size_t msg_len = strlen(message);
	int ok = -1;
	BIGNUM *priv = NULL;
	EC_POINT *pt = NULL;
	EC_KEY *key = NULL;
	ECDSA_SIG *sig = NULL;
	EC_GROUP *group = NULL;
	unsigned char *outbuf = NULL;
	BIGNUM* sig_r;
	BIGNUM* sig_s;

	BN_hex2bn(&priv, privkey_hexstr);
	///Creates a new EC_KEY object using a named curve as underlying
	if(!(key = EC_KEY_new_by_curve_name(NID_sm2))) {
		return ok;
	}
	/// EC_GROUP object of a EC_KEY object
	group = EC_KEY_get0_group ((const EC_KEY * )key);
	

	/// Creates a new EC_POINT object for the specified EC_GROUP
	pt = EC_POINT_new(group);

	/// Computes EC_POINT public key
	EC_POINT_mul(group, pt, priv, NULL, NULL, NULL);
	///Sets the  keys of a EC_KEY object.
	EC_KEY_set_private_key(key, priv);
	EC_KEY_set_public_key(key, pt);
	
	sig = SM2_do_sign((const EC_KEY*) key, 
					(const EVP_MD *)EVP_sm3(), userid, (const uint8_t *)message, msg_len);
	int siglen = i2d_ECDSA_SIG((const ECDSA_SIG *)sig, (unsigned char **)&outbuf);

	unsigned char *outbuf_hex = buf2hexstr (outbuf, siglen);
	printf("sign:%s\n",outbuf_hex);
clean_up:

	if ( sig)
	{
		ECDSA_SIG_free(sig);
	}

	if (key)
	{
	    EC_KEY_free(key);
	}

	if (outbuf)
	{
		free(outbuf);

	}
	if(outbuf_hex)
	{
		return outbuf_hex;
	}
	return NULL;
}
int sm2_verify(const char *userid, const char *pubkey_hexstr, const char *souredata,const char* sign)
{
	printf("sign_key:%s\n",souredata);
	long sign_len = strlen(sign);
	long msg_len = strlen(souredata);
	int ok = -1;
	BIGNUM *priv = NULL;
	EC_POINT *pt = NULL;
	EC_KEY *key = NULL;
	ECDSA_SIG *sig = NULL;
	EC_GROUP *group = NULL;
	unsigned char x[65] = {0};
	unsigned char y[65]= {0};
	BIGNUM *bx = NULL;
	BIGNUM *by = NULL;
	BIGNUM* sig_r;
	BIGNUM* sig_s;
	memcpy(x, pubkey_hexstr+2, sizeof(x) -1);
	memcpy(y, pubkey_hexstr + 66, sizeof(y) -1);
	BN_hex2bn(&bx, (const char *)x);
	BN_hex2bn(&by, (const char *)y);
	///Creates a new EC_KEY object using a named curve as underlying
	if(!(key = EC_KEY_new_by_curve_name(NID_sm2))) {
		printf("EC_GROUP_new_by_curve_name faild\n");
		goto clean_up;
	}
	#if 0
    pt = EC_POINT_new(group);
	if (0 == EC_POINT_set_affine_coordinates_GF2m(group,pt,bx,by,NULL)){
		printf("EC_KEY_set_public_key_affine_coordinates\n");
		goto clean_up;
	}
	EC_KEY_set_public_key (key, pt);
	#endif
	///Sets a public key from affine coordinates performing
	if (0 == EC_KEY_set_public_key_affine_coordinates(key, bx, by)){
		printf("EC_KEY_set_public_key_affine_coordinates\n");
		goto clean_up;
	}
	
	unsigned char* buf = OPENSSL_hexstr2buf (sign, &sign_len);
	d2i_ECDSA_SIG((ECDSA_SIG **)&sig,(const unsigned char **) &buf, sign_len);

	if  (NULL == sig)
	{
		printf("Ed2i_ECDSA_SIG\n");
		goto clean_up;
	}
	ok  = SM2_do_verify((const EC_KEY*) key, 
					(const EVP_MD *)EVP_sm3(), sig, userid, (const uint8_t *)souredata, msg_len);


clean_up:

	BN_free(bx);
	BN_free(by);
	if ( sig)
	{
		ECDSA_SIG_free(sig);
	}
	if (key)
	{
	    EC_KEY_free(key);
	}
	

	return ok ;

}
int sm2_encrypt( const char *pubkey_hex,
                    const char *message, uint8_t **out_hex)
{
    const size_t msg_len = strlen(message);
    BIGNUM *priv = NULL;
    EC_KEY *key = NULL;
    EC_POINT *pt = NULL;
	EC_GROUP *group = NULL;

	BIGNUM *kx = NULL;
	BIGNUM *ky = NULL;
    size_t ctext_len = 0;
    uint8_t *ctext = NULL;
    char x[65] = {0};
    char y[65]= {0};
    memcpy(x, pubkey_hex + 2, sizeof(x) -1);
    memcpy(y, pubkey_hex + 2 + 64, sizeof(y) -1);
    BN_hex2bn(&kx, (const char *)x);
    BN_hex2bn(&ky, (const char *)y);
    int rc = 0;
	if(!(key = EC_KEY_new_by_curve_name(NID_sm2))) {
		printf("EC_GROUP_new_by_curve_name faild\n");
		goto done;
	}
		///Sets a public key from affine coordinates performing
    if (0 == EC_KEY_set_public_key_affine_coordinates(key, kx, ky)){
		printf("EC_KEY_set_public_key_affine_coordinates\n");
		goto done;
	}
    
	 BN_free(kx);
	 BN_free(ky);

    ctext_len = SM2_ciphertext_size(key, EVP_sm3(), msg_len);
	printf("ctext_len:%d\n", ctext_len);
    ctext = OPENSSL_zalloc(ctext_len);
	
    if (ctext == NULL)
        goto done;
	
    rc = SM2_encrypt(key, EVP_sm3(),
                     (const uint8_t *)message, msg_len, ctext, &ctext_len);
	*out_hex = buf2hexstr(ctext, ctext_len);
done:
	
   	if (ctext)
   	{
   		OPENSSL_free(ctext);
   	}
	if (key)
	{
		EC_KEY_free(key);
	}
	return rc;
    	
 }
int sm2_decrypt(const char *privkey_hex,const char *message,char **plain_text)
{
	
	BIGNUM *priv = NULL;
	EC_KEY *key = NULL;
	EC_POINT *pt = NULL;
	EC_GROUP *group = NULL;
	size_t ctext_len = 0;
	size_t ptext_len = 0;
	uint8_t *ctext = NULL;
	uint8_t *recovered = NULL;
	char *temp = NULL;
	size_t recovered_len;
	int rc = 0;
	
	const size_t msg_len = strlen(message);
	char *message_hex = OPENSSL_hexstr2buf(message, NULL);
	BN_hex2bn(&priv, privkey_hex);
	if(!(group = EC_GROUP_new_by_curve_name(NID_sm2)))
	{
		goto done;
	}
	BN_hex2bn(&priv, privkey_hex);
	key = EC_KEY_new();
	EC_KEY_set_group(key, group);
	EC_KEY_set_private_key(key, priv);

	pt = EC_POINT_new(group);
	EC_POINT_mul(group, pt, priv, NULL, NULL, NULL);
	EC_KEY_set_public_key(key, pt);
	
	BN_free(priv);
	EC_POINT_free(pt);
	ptext_len = SM2_plaintext_size(key, EVP_sm3(), msg_len/2);
	recovered_len = ptext_len;
	recovered = OPENSSL_zalloc(ptext_len);
	
	if (recovered == NULL)
		goto done;
	
	rc = SM2_decrypt(key, EVP_sm3(), message_hex, msg_len/2, recovered, &recovered_len);

	temp = (char*)malloc(recovered_len +1);
	if (!temp )
	{
		printf("malloc falid\n", temp);
		rc = -1;
		return rc;
	}
	
	memset(temp, 0, recovered_len +1);
	memcpy(temp, recovered, recovered_len);
	*plain_text = temp;
	rc = 1;
 done:
	OPENSSL_free(recovered);
  
	EC_KEY_free(key);
	return rc;
}

int main()
{	const char * userid = "123456";
	const char *message = "test";
	char * en_str = NULL;
	char * de_str = NULL;
	char* priv_key = NULL;
	char* pub_key = NULL;
	unsigned char* sign_key = NULL;
	sm2_keypair(&priv_key, &pub_key);
	sign_key = sm2_sign (userid, priv_key, message);
	if (sign_key != NULL) {
		int ret = sm2_verify (userid, pub_key, message, sign_key);
		if (1 == ret ) {
			printf("sm2_verify success \n");
		}else {
			printf("sm2_verify fail \n");
		}
	}
	sm2_encrypt(pub_key, message, &en_str);
	printf("en_str:%s\n", en_str);
	sm2_decrypt(priv_key, en_str, &de_str);
	printf("de_str:%s\n", de_str);
	return 0;
	
}
