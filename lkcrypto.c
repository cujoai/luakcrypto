/*
* This file is Confidential Information of CUJO LLC.
* Copyright (c) 2021 CUJO LLC. All rights reserved.
*/

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <linux/crypto.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/completion.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
#include <crypto/skcipher.h>
#endif
#include <linux/kthread.h>
#include <crypto/hash.h>
#include <crypto/aes.h>
#include <crypto/sha.h>
#include <crypto/aead.h>

#define MAX_NAME_LEN  15
#define MAX_AUTH_SIZE AES_MAX_KEY_SIZE

static const char CUJO_CIPHER_TFM_LUA_NAME[] = "cipher_tfm";
static const char CUJO_CIPHER_AEAD_TFM_LUA_NAME[] = "cipher_aead_tfm";
static const char CUJO_HASHER_TFM_LUA_NAME[] = "hasher_tfm";

static DECLARE_COMPLETION(hasher_needs_init);
static DECLARE_COMPLETION(cipher_needs_init);
static DECLARE_COMPLETION(cipher_aead_needs_init);

enum { CIPHER, CIPHER_AEAD, HASHER };
enum {
	INIT,
	IN_PROGRESS,
	READY,
};

enum ENC_DEC {
	DECODING,
	ENCODING,
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 0)
#define SHASH_DESC_ON_STACK(shash, ctx)                                         \
	char __##shash##_desc[sizeof(struct shash_desc) +                       \
			      crypto_shash_descsize(ctx)] CRYPTO_MINALIGN_ATTR; \
	struct shash_desc *shash = (struct shash_desc *)__##shash##_desc
#endif

struct names_list_t {
	char name[MAX_NAME_LEN + 1];
	struct list_head list;
};

struct hash_lock_t {
	int status;
	spinlock_t lock;
};

struct tcrypt_result {
	struct completion completion;
	int err;
};

/* tie all data structures together */
struct cipher_def {
	struct scatterlist sg;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
	struct crypto_skcipher *tfm;
	struct skcipher_request *req;
#else
	struct blkcipher_desc desc;
#endif
	struct tcrypt_result result;
};

struct hasher_tfm_t {
	struct crypto_shash *hash_tfm;
};

struct cipher_tfm_t {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
	struct crypto_skcipher *tfm;
	struct skcipher_request *req;
#else
	struct blkcipher_desc desc;
#endif
};

struct cipher_aead_tfm_t {
	struct crypto_aead *tfm;
	struct aead_request *req;
};

struct hash_lock_t cipher = {
	0,
};
struct hash_lock_t cipher_aead = {
	0,
};
struct hash_lock_t hash = {
	0,
};

LIST_HEAD(cipher_names_list);
LIST_HEAD(cipher_aead_names_list);
LIST_HEAD(hasher_names_list);

static int get_status(struct hash_lock_t *state)
{
	int status = 0;
	spin_lock_bh(&state->lock);
	status = state->status;
	spin_unlock_bh(&state->lock);
	return status;
}

static void set_status(struct hash_lock_t *state, int value)
{
	spin_lock_bh(&state->lock);
	state->status = value;
	spin_unlock_bh(&state->lock);
}

static void delete_list_items(struct list_head *name_list)
{
	struct list_head *pos = NULL;
	struct list_head *q = NULL;
	struct names_list_t *tmp = NULL;
	list_for_each_safe (pos, q, name_list) {
		tmp = list_entry(pos, struct names_list_t, list);
		list_del(pos);
		kfree(tmp);
	}
}

static int enc_dec(struct cipher_tfm_t *tfm, const u8 *key, size_t key_len,
		   u8 *iv, size_t iv_len, const u8 *input_buffer,
		   size_t input_buffer_len, enum ENC_DEC operation)
{
	struct cipher_def def;
	int ret = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
	def.tfm = tfm->tfm;
	def.req = tfm->req;
#else
	def.desc = tfm->desc;
	def.desc.flags = 0;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
	ret = crypto_skcipher_setkey(def.tfm, key, key_len);
#else
	ret = crypto_blkcipher_setkey(def.desc.tfm, key, key_len);
#endif
	if (ret) {
		return ret;
	}

	/* We encrypt one block */
	sg_init_one(&def.sg, input_buffer, input_buffer_len);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
	skcipher_request_set_crypt(def.req, &def.sg, &def.sg, input_buffer_len,
				   iv);
#else
	if (iv_len > 0) {
		crypto_blkcipher_set_iv(def.desc.tfm, iv, iv_len);
	}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
	if (operation == ENCODING)
		ret = crypto_skcipher_encrypt(def.req);
	else
		ret = crypto_skcipher_decrypt(def.req);
#else
	if (operation == ENCODING)
		ret = crypto_blkcipher_encrypt(&def.desc, &def.sg, &def.sg,
					       input_buffer_len);
	else
		ret = crypto_blkcipher_decrypt(&def.desc, &def.sg, &def.sg,
					       input_buffer_len);
#endif

	return ret;
}

static int enc_dec_aead(struct cipher_aead_tfm_t *tfm, const u8 *key,
			size_t key_len, u8 *iv, size_t iv_len, u8 *auth,
			size_t auth_len, u8 *aad, size_t aad_len,
			u8 *input_buffer, size_t input_buffer_len,
			enum ENC_DEC operation)
{
	int ret = 0;
	struct scatterlist sg[3];

	ret = crypto_aead_setkey(tfm->tfm, key, key_len);
	if (ret) {
		return ret;
	}
	ret = crypto_aead_setauthsize(tfm->tfm, auth_len);
	if (ret) {
		return ret;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
	if (aad_len > 0) {
		sg_init_table(sg, 3);
		sg_set_buf(&sg[0], aad, aad_len);
		sg_set_buf(&sg[1], input_buffer, input_buffer_len);
		sg_set_buf(&sg[2], auth, auth_len);
	} else {
		sg_init_table(sg, 2);
		sg_set_buf(&sg[0], input_buffer, input_buffer_len);
		sg_set_buf(&sg[1], auth, auth_len);
	}

	aead_request_set_ad(tfm->req, aad_len);
#else
	struct scatterlist asg;
	sg_init_table(sg, 2);
	sg_set_buf(&sg[0], input_buffer, input_buffer_len);
	sg_set_buf(&sg[1], auth, auth_len);
	if (aad_len > 0) {
		sg_init_one(&asg, aad, aad_len);
	}
	aead_request_set_assoc(tfm->req, &asg, aad_len);
#endif

	if (operation == ENCODING) {
		aead_request_set_crypt(tfm->req, sg, sg, input_buffer_len, iv);
	} else {
		aead_request_set_crypt(tfm->req, sg, sg,
				       input_buffer_len + auth_len, iv);
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
	aead_request_set_ad(tfm->req, aad_len);
#else
	aead_request_set_assoc(tfm->req, sg, aad_len);
#endif

	if (operation == ENCODING) {
		ret = crypto_aead_encrypt(tfm->req);
	} else {
		ret = crypto_aead_decrypt(tfm->req);
	}
	return ret;
}

static int decrypt_encrypt(lua_State *L, enum ENC_DEC operation)
{
	size_t key_len = 0;
	size_t iv_len = 0;
	size_t ciphertext_len = 0;
	int result = 0;
	int nargs = 0;
	const u8 *key;
	const u8 *iv_orig;
	const u8 *ciphertext;
	u8 iv[AES_MAX_KEY_SIZE] = {
		0,
	};
	u8 *buffer = NULL;
	struct cipher_tfm_t *tfm = NULL;

	nargs = lua_gettop(L);

	tfm = luaL_checkudata(L, 1, CUJO_CIPHER_TFM_LUA_NAME);
	key = luaL_checklstring(L, 2, &key_len);
	ciphertext = luaL_checklstring(L, 3, &ciphertext_len);

	if (nargs == 4) {
		iv_orig = luaL_checklstring(L, 4, &iv_len);
		memcpy(iv, iv_orig, iv_len);
	}
	buffer = kmalloc(ciphertext_len, GFP_ATOMIC);
	if (buffer == NULL) {
		return luaL_error(L, "buffer allocation failed");
	}
	memcpy(buffer, ciphertext, ciphertext_len);
	result = enc_dec(tfm, key, key_len, iv, iv_len, buffer, ciphertext_len,
			 operation);

	if (!result) {
		lua_pushlstring(L, buffer, ciphertext_len);
		kfree(buffer);
		return 1;
	} else {
		kfree(buffer);
		return luaL_error(L, "%s failed %d",
				  operation ? "encrypt" : "decrypt");
	}
}

static int decrypt_encrypt_aead(lua_State *L, enum ENC_DEC operation)
{
	size_t key_len = 0;
	size_t iv_len = 0;
	size_t auth_len = 0;
	size_t ciphertext_len = 0;
	size_t aad_len = 0;

	int result = 0;
	int nargs = 0;
	const u8 *key;
	const u8 *iv_orig;
	const u8 *auth_orig;
	const u8 *aad_orig;
	const u8 *ciphertext;
	u8 iv[AES_MAX_KEY_SIZE] = {
		0,
	};
	u8 *auth = NULL;
	u8 *buffer = NULL;
	u8 *aad = NULL;

	struct cipher_aead_tfm_t *tfm = NULL;

	nargs = lua_gettop(L);

	tfm = luaL_checkudata(L, 1, CUJO_CIPHER_AEAD_TFM_LUA_NAME);
	key = luaL_checklstring(L, 2, &key_len);
	ciphertext = luaL_checklstring(L, 3, &ciphertext_len);
	iv_orig = luaL_checklstring(L, 4, &iv_len);
	memcpy(iv, iv_orig, iv_len);
	if (operation == DECODING) {
		auth_orig = luaL_checklstring(L, 5, &auth_len);
		auth = kmalloc(auth_len, GFP_ATOMIC);
		if (auth == NULL) {
			return luaL_error(L, "auth allocation failed");
		}
		memcpy(auth, auth_orig, auth_len);
	}

	buffer = kmalloc(ciphertext_len, GFP_ATOMIC);
	if (buffer == NULL) {
		return luaL_error(L, "buffer allocation failed");
	}

	if (operation == ENCODING) {
		auth_len = key_len;
		auth = kmalloc(auth_len, GFP_ATOMIC);
		if (auth == NULL) {
			return luaL_error(L, "auth allocation failed");
		}
		if (nargs == 5) {
			aad_orig = luaL_checklstring(L, 5, &aad_len);
			aad = kmalloc(aad_len, GFP_ATOMIC);
			if (aad == NULL) {
				return luaL_error(L, "aad allocation failed");
			}
			memcpy(aad, aad_orig, aad_len);
		}
	} else {
		if (nargs == 6) {
			aad_orig = luaL_checklstring(L, 6, &aad_len);
			aad = kmalloc(aad_len, GFP_ATOMIC);
			if (aad == NULL) {
				return luaL_error(L, "aad allocation failed");
			}
			memcpy(aad, aad_orig, aad_len);
		}
	}

	memcpy(buffer, ciphertext, ciphertext_len);

	result = enc_dec_aead(tfm, key, key_len, iv, iv_len, auth, auth_len,
			      aad, aad_len, buffer, ciphertext_len, operation);

	if (result) {
		kfree(buffer);
		kfree(auth);
		if (aad)
			kfree(aad);
		return luaL_error(L, "%s failed %d",
				  operation ? "encrypt" : "decrypt");
	}

	lua_pushlstring(L, buffer, ciphertext_len);
	kfree(buffer);
	if (aad)
		kfree(aad);
	if (operation == ENCODING) {
		lua_pushlstring(L, auth, auth_len);
		kfree(auth);
		return 2;
	} else {
		return 1;
	}
}

static int get_digest(struct crypto_shash *tfm, const u8 *key, size_t key_len,
		      const u8 *msg, size_t msg_len, u8 *out)
{
	int err = 0;

	SHASH_DESC_ON_STACK(desc, tfm);

	err = crypto_shash_setkey(tfm, key, key_len);
	if (err)
		return err;
	desc->tfm = tfm;
	err = crypto_shash_digest(desc, msg, msg_len, out);
	return err;
}

static int lget_digest(lua_State *L)
{
	size_t key_len = 0;
	size_t _text_len = 0;
	const u8 *key;
	const u8 *text;
	int result = 0;
	int out_len = 0;
	struct hasher_tfm_t *tfm = NULL;

	u8 out[SHA512_DIGEST_SIZE] = {
		0,
	};

	if (get_status(&hash) != READY)
		return 0;

	tfm = luaL_checkudata(L, 1, CUJO_HASHER_TFM_LUA_NAME);
	key = luaL_checklstring(L, 2, &key_len);
	text = luaL_checklstring(L, 3, &_text_len);
	out_len = luaL_checkinteger(L, 4);

	result = get_digest(tfm->hash_tfm, key, key_len, text, _text_len, out);

	if (result)
		luaL_error(L, "failed to get digest");

	lua_pushlstring(L, out, out_len);
	return 1;
}

static int cache_warm(int tfm_type, struct hash_lock_t *state,
		      struct list_head *name_list)
{
	struct names_list_t *tmp = NULL;
	void *tfm = NULL;
	list_for_each_entry (tmp, name_list, list) {
		if (tfm_type == HASHER) {
			tfm = crypto_alloc_shash(tmp->name, 0,
						 CRYPTO_ALG_ASYNC);
		} else if (tfm_type == CIPHER_AEAD) {
			tfm = crypto_alloc_aead(tmp->name, 0, CRYPTO_ALG_ASYNC);
		} else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
			tfm = crypto_alloc_skcipher(tmp->name, 0,
						    CRYPTO_ALG_ASYNC);
#else
			tfm = crypto_alloc_blkcipher(tmp->name, 0,
						     CRYPTO_ALG_ASYNC);
#endif
		}
		if (IS_ERR(tfm)) {
			pr_err("could not allocate %s handle\n", tmp->name);
			delete_list_items(name_list);
			return PTR_ERR(tfm);
		}
		if (tfm_type == HASHER) {
			crypto_free_shash(tfm);
		} else if (tfm_type == CIPHER_AEAD) {
			crypto_free_aead(tfm);
		} else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
			crypto_free_skcipher(tfm);
#else
			crypto_free_cipher(tfm);
#endif
		}
		pr_info("%s finished loading\n", tmp->name);
	}
	delete_list_items(name_list);
	set_status(state, READY);
	return 0;
}

static int hasher_cache_warm(void *arg)
{
	if (!wait_for_completion_killable(&hasher_needs_init))
		return cache_warm(HASHER, &hash, &hasher_names_list);
	return -1;
}

static int cipher_cache_warm(void *arg)
{
	if (!wait_for_completion_killable(&cipher_needs_init))
		return cache_warm(CIPHER, &cipher, &cipher_names_list);
	return -1;
}

static int cipher_aead_cache_warm(void *arg)
{
	if (!wait_for_completion_killable(&cipher_aead_needs_init))
		return cache_warm(CIPHER_AEAD, &cipher_aead,
				  &cipher_aead_names_list);
	return -1;
}

static int ldecrypt(lua_State *L)
{
	if (get_status(&cipher) != READY)
		return 0;

	return decrypt_encrypt(L, DECODING);
}

static int lencrypt(lua_State *L)
{
	if (get_status(&cipher) != READY)
		return 0;

	return decrypt_encrypt(L, ENCODING);
}

static int ldecrypt_aead(lua_State *L)
{
	if (get_status(&cipher_aead) != READY)
		return 0;

	return decrypt_encrypt_aead(L, DECODING);
}

static int lencrypt_aead(lua_State *L)
{
	if (get_status(&cipher_aead) != READY)
		return 0;

	return decrypt_encrypt_aead(L, ENCODING);
}

static int init(lua_State *L, struct hash_lock_t *state, struct list_head *list,
		struct completion *task)
{
	const u8 *name = NULL;
	struct names_list_t *tmp = NULL;
	int nargs = 0;
	int i = 1;
	size_t name_len = 0;

	if (get_status(state) != INIT) {
		return luaL_error(L, "kernel cache is already warmed");
	}

	nargs = lua_gettop(L);
	for (; i <= nargs; i++) {
		name = luaL_checklstring(L, i, &name_len);
		if (name_len >= MAX_NAME_LEN + 1) {
			delete_list_items(list);
			return luaL_error(
				L,
				"%s exceeds name length size, MAX_NAME_LEN bump is required!",
				name);
		}
		tmp = kmalloc(sizeof(struct names_list_t), GFP_ATOMIC);
		memset(tmp->name, 0, MAX_NAME_LEN + 1);
		memcpy(tmp->name, name, name_len);
		INIT_LIST_HEAD(&tmp->list);
		list_add(&(tmp->list), list);
	}

	set_status(state, IN_PROGRESS);

	complete(task);
	return 0;
}

/* Important!
*  Due to limitations of usage this lib as lua kernel library
*  whereis lua interpeter is running in atomic context we cannot execute
*  any blocking calls or busy waiting outside of either module_init or
*  separate kernel threads. As such we could register new kernel threads
*  only in module_init routine. User could set new set of ciphers/hashers
*  via `init_cipher`/`init_hasher` only once per module initialization
*
*  TODO drop the above limitation and let user set new ciphers during uptime
*  that requires more complicated "state" management.
*/

static int init_cipher(lua_State *L)
{
	return init(L, &cipher, &cipher_names_list, &cipher_needs_init);
}

static int init_cipher_aead(lua_State *L)
{
	return init(L, &cipher_aead, &cipher_aead_names_list,
		    &cipher_aead_needs_init);
}

static int init_hasher(lua_State *L)
{
	return init(L, &hash, &hasher_names_list, &hasher_needs_init);
}

static int cipher_tfm_gc(lua_State *L)
{
	struct cipher_tfm_t *tfm =
		luaL_checkudata(L, 1, CUJO_CIPHER_TFM_LUA_NAME);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
	skcipher_request_free(tfm->req);
	crypto_free_skcipher(tfm->tfm);
#else
	crypto_free_blkcipher(tfm->desc.tfm);
#endif
	return 0;
}

static int cipher_aead_tfm_gc(lua_State *L)
{
	struct cipher_aead_tfm_t *tfm =
		luaL_checkudata(L, 1, CUJO_CIPHER_AEAD_TFM_LUA_NAME);
	crypto_free_aead(tfm->tfm);
	aead_request_free(tfm->req);
	return 0;
}

static int hasher_tfm_gc(lua_State *L)
{
	struct hasher_tfm_t *tfm =
		luaL_checkudata(L, 1, CUJO_HASHER_TFM_LUA_NAME);
	crypto_free_shash(tfm->hash_tfm);
	return 0;
}

static const luaL_Reg hasher_funcs[] = {
	{ "get_digest", lget_digest },
	{ "__gc", hasher_tfm_gc },
	{ NULL, NULL },
};

static int lget_hasher(lua_State *L)
{
	size_t hasher_name_len = 0;
	const u8 *hasher_name;
	struct hasher_tfm_t *tfm = NULL;
	if (get_status(&hash) != READY)
		return 0;
	hasher_name = luaL_checklstring(L, 1, &hasher_name_len);

	tfm = lua_newuserdata(L, sizeof *tfm);
	tfm->hash_tfm = crypto_alloc_shash(hasher_name, 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm->hash_tfm)) {
		luaL_error(L, "could not allocate %s handle\n", hasher_name);
	}
	if (luaL_newmetatable(L, CUJO_HASHER_TFM_LUA_NAME)) {
		luaL_setfuncs(L, hasher_funcs, 0);
		lua_pushvalue(L, -1);
		lua_setfield(L, -2, "__index");
	}
	lua_setmetatable(L, -2);
	return 1;
}

static const luaL_Reg cipher_funcs[] = {
	{ "decrypt", ldecrypt },
	{ "encrypt", lencrypt },
	{ "__gc", cipher_tfm_gc },
	{ NULL, NULL },
};

static const luaL_Reg cipher_aead_funcs[] = {
	{ "decrypt", ldecrypt_aead },
	{ "encrypt", lencrypt_aead },
	{ "__gc", cipher_aead_tfm_gc },
	{ NULL, NULL },
};

static int lget_cipher(lua_State *L)
{
	size_t cipher_name_len = 0;
	const u8 *cipher_name;
	struct cipher_tfm_t *tfm = NULL;
	if (get_status(&cipher) != READY)
		return 0;
	cipher_name = luaL_checklstring(L, 1, &cipher_name_len);

	tfm = lua_newuserdata(L, sizeof *tfm);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
	tfm->tfm = crypto_alloc_skcipher(cipher_name, 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm->tfm)) {
		luaL_error(L, "could not allocate %s handle\n", cipher_name);
	}
	tfm->req = skcipher_request_alloc(tfm->tfm, GFP_ATOMIC);
	if (!tfm->req) {
		crypto_free_skcipher(tfm->tfm);
		luaL_error(L, "could not allocate request handle\n");
	}
#else
	tfm->desc.tfm =
		crypto_alloc_blkcipher(cipher_name, 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm->desc.tfm)) {
		luaL_error(L, "could not allocate %s handle\n", cipher_name);
	}
#endif

	if (luaL_newmetatable(L, CUJO_CIPHER_TFM_LUA_NAME)) {
		luaL_setfuncs(L, cipher_funcs, 0);
		lua_pushvalue(L, -1);
		lua_setfield(L, -2, "__index");
	}
	lua_setmetatable(L, -2);
	return 1;
}

static int lget_cipher_aead(lua_State *L)
{
	size_t cipher_name_len = 0;
	const u8 *cipher_name;
	struct cipher_aead_tfm_t *tfm = NULL;
	if (get_status(&cipher_aead) != READY) {
		printk("Not ready error\n");
		return 0;
	}
	cipher_name = luaL_checklstring(L, 1, &cipher_name_len);

	tfm = lua_newuserdata(L, sizeof *tfm);

	tfm->tfm = crypto_alloc_aead(cipher_name, 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm->tfm)) {
		luaL_error(L, "could not allocate %s handle\n", cipher_name);
	}

	tfm->req = aead_request_alloc(tfm->tfm, GFP_ATOMIC);
	if (!tfm->req) {
		crypto_free_aead(tfm->tfm);
		luaL_error(L, "could not allocate request handle\n");
	}

	if (luaL_newmetatable(L, CUJO_CIPHER_AEAD_TFM_LUA_NAME)) {
		luaL_setfuncs(L, cipher_aead_funcs, 0);
		lua_pushvalue(L, -1);
		lua_setfield(L, -2, "__index");
	}
	lua_setmetatable(L, -2);
	return 1;
}

static const luaL_Reg kcrypto[] = {
	{ "init_cipher", init_cipher },
	{ "init_hasher", init_hasher },
	{ "init_cipher_aead", init_cipher_aead },
	{ "get_cipher", lget_cipher },
	{ "get_cipher_aead", lget_cipher_aead },
	{ "get_hasher", lget_hasher },
	{ NULL, NULL },
};
int luaopen_kcrypto(lua_State *L)
{
	luaL_newlib(L, kcrypto);
	return 1;
}

static int __init modinit(void)
{
	kthread_run(cipher_cache_warm, NULL, "cipher_cache_warm");
	kthread_run(cipher_aead_cache_warm, NULL, "cipher_aead_cache_warm");
	kthread_run(hasher_cache_warm, NULL, "hasher_cache_warm");
	spin_lock_init(&hash.lock);
	spin_lock_init(&cipher.lock);
	spin_lock_init(&cipher_aead.lock);
	set_status(&cipher, INIT);
	set_status(&cipher_aead, INIT);
	set_status(&hash, INIT);
	return 0;
}

static void __exit modexit(void)
{
}

module_init(modinit);
module_exit(modexit);
MODULE_LICENSE("Dual MIT/GPL");
EXPORT_SYMBOL(luaopen_kcrypto);
