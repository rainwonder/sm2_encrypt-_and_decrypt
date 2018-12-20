#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <openssl/sm2.h>

static int sm2_encrypt( const char *privkey_hex,
                    const char *message,     uint8 **out_hex)
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
    char  x[64];
    char  y[64];
    memcpy(x, privkey_hex, sizeof(x));
    memcpy(y, privkey_hex+64,sizeof(y));
    BN_hex2bn(&kx, (const char *)x);
    BN_hex2bn(&ky, (const char *)y);
    int rc = 0;
    BN_hex2bn(&priv, privkey_hex);

		if(!(group = EC_GROUP_new_by_curve_name(NID_sm2)))
		{
			goto done;
		}
	
    key = EC_KEY_new();
    EC_KEY_set_group(key, group);

    pt = EC_POINT_new(group);
    if(!EC_POINT_set_affine_coordinates_GF2m(group, pt, kx, ky, NULL))
		{	
			goto done;
    }
	
    EC_KEY_set_public_key(key, pt);
	
    BN_free(priv);
	BN_free(kx);
	BN_free(ky);
    EC_POINT_free(pt);

    ctext_len = SM2_ciphertext_size(key, EVP_sm3(), msg_len);
    ctext = OPENSSL_zalloc(ctext_len);
	
    if (ctext == NULL)
        goto done;
	
    rc = SM2_encrypt(key, EVP_sm3(),
                     (const uint8_t *)message, msg_len, ctext, &ctext_len);
	
    printf("ctext_len:%d, %d\n",ctext_len,msg_len);
    for(int i = 0;i < ctext_len;i++ )
    	printf("%02x",ctext[i]);
    printf("\nctext_len:%d\n",ctext_len);
	
	*out_hex = OPENSSL_buf2hexstr(ctext, ctext_len);
	
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
static int sm2_decrypt(const char *privkey_hex,const char *message,char **plain_text)
{
    
    BIGNUM *priv = NULL;
    EC_KEY *key = NULL;
    EC_POINT *pt = NULL;
		EC_GROUP *group = NULL;
    size_t ctext_len = 0;
    size_t ptext_len = 0;
    uint8_t *ctext = NULL;
    uint8_t *recovered = NULL;
    size_t recovered_len;
    int rc = 0;
	
		const size_t msg_len = strlen(message);
		char *message_hex = OPENSSL_hexstr2buf(message, NULL);
    BN_hex2bn(&priv, privkey_hex);
		if(!(group = EC_GROUP_new_by_curve_name(NID_sm2)))
		{
			goto done;
		}
    key = EC_KEY_new();
    EC_KEY_set_group(key, group);
    EC_KEY_set_private_key(key, priv);
    pt = EC_POINT_new(group);
    EC_POINT_mul(group, pt, priv, NULL, NULL, NULL);
	
    BN_free(priv);
    EC_POINT_free(pt);

    ptext_len = SM2_plaintext_size(key, EVP_sm3(), msg_len/2);
		recovered_len = ptext_len;
    recovered = OPENSSL_zalloc(ptext_len);
	
    if (recovered == NULL)
        goto done;
	
    rc = SM2_decrypt(key, EVP_sm3(), message_hex, msg_len/2, recovered, &recovered_len);
		printf("recovered_len:%d\n",recovered_len);
	
		if (NULL = (*plain_text = (char*)malloc(recovered_len +1)));
		{
			rc = -1;
			return rc;
		}
		memset((*plain_text), 0, recovered_len +1);
		memcpy((*plain_text), recovered, recovered_len);
		printf("plain_text：%s", plain_text);
    rc = 1;
done:
    OPENSSL_free(recovered);
  
    EC_KEY_free(key);
    return rc;
}

ECDSA_SIG * sm2_sign(       const char *userid,
					const char *privkey_hex,
					const char *message)
{
	const size_t msg_len = strlen(message);
	int ok = -1;
	BIGNUM *priv = NULL;
	EC_POINT *pt = NULL;
	EC_KEY *key = NULL;
	ECDSA_SIG *sig = NULL;
	const BIGNUM *sig_r = NULL;
	const BIGNUM *sig_s = NULL;
	EC_GROUP *group = NULL;
	char *r = NULL;
	char *s = NULL;
	char *outbuf;

	BN_hex2bn(&priv, privkey_hex);
	if ( !(group = EC_GROUP_new_by_curve_name(NID_sm2)) )
	{
		goto clean_up;
	}

	key = EC_KEY_new();
	EC_KEY_set_group(key, group);
	EC_KEY_set_private_key(key, priv);

	pt = EC_POINT_new(group);
	EC_POINT_mul(group, pt, priv, NULL, NULL, NULL);
	EC_KEY_set_public_key(key, pt);
	sig = SM2_do_sign(key, EVP_sm3(), userid, (const uint8_t *)message, msg_len);
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	r = BN_bn2hex(sig_r));
	s = BN_bn2hex(sig_s));
	int r_len = strlen(r);
	int s_len = strlen(s);
	if (outbuf = (char*)malloc(s_len+ r_len)
	{
		strcat(outbuf,r);
		strcat(outbuf + r_len, s);
	}
	ok = 0
clean_up:
	if (group)
	{
		EC_GROUP_free(group);
	}
	if (pt)
	{
    	EC_POINT_free(pt);
	}
	if (key)
	{
	    EC_KEY_free(key);
	}
	if (priv) 
	{
	    BN_free(priv);
	}
	if (r)
	{
	 BN_free(r);
  
	}
	if (s)
	{
	  BN_free(s);
	}
	if (outbuf)
	{
		return outbuf

	}
	return NULL;
}

