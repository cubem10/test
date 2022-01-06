/*
 * sdp_dek.c
 *
 */
#include <linux/kthread.h>
#include <linux/pagemap.h>
#include <linux/string.h>
#include <asm/unaligned.h>

#include <crypto/kbkdf.h>
#include <sdp/fs_handler.h>
#include "sdp_crypto.h"
#include "../crypto_sec.h"
#include "../fscrypt_private.h"

static int __fscrypt_get_sdp_context(struct inode *inode, struct fscrypt_info *crypt_info);
inline int __fscrypt_get_sdp_dek(struct fscrypt_info *crypt_info, unsigned char *dek, unsigned int dek_len);
inline int __fscrypt_set_sdp_dek(struct fscrypt_info *crypt_info, unsigned char *fe_key, int fe_key_len);
inline int __fscrypt_sdp_finish_set_sensitive(struct inode *inode,
				struct fscrypt_context *ctx, struct fscrypt_info *crypt_info,
				struct fscrypt_key *key);
inline void __fscrypt_sdp_finalize_tasks(struct inode *inode,
						struct fscrypt_info *ci, u8 *raw_key, int key_len);
static inline int __fscrypt_derive_nek_iv(u8 *drv_key, u32 drv_key_len, u8 *out, u32 out_len);
static inline int __fscrypt_get_nonce(u8 *key, u32 key_len,
						u8 *enonce, u32 nonce_len,
						u8 *out, u32 out_len);
static inline int __fscrypt_set_nonce(u8 *key, u32 key_len,
						u8 *enonce, u32 nonce_len,
						u8 *out, u32 out_len);
static struct kmem_cache *sdp_info_cachep;

inline struct sdp_info *fscrypt_sdp_alloc_sdp_info(void)
{
	struct sdp_info *ci_sdp_info;

	ci_sdp_info = kmem_cache_alloc(sdp_info_cachep, GFP_NOFS);
	if (!ci_sdp_info) {
		DEK_LOGE("Failed to alloc sdp info!!\n");
		return NULL;
	}
	ci_sdp_info->sdp_flags = 0;
	spin_lock_init(&ci_sdp_info->sdp_flag_lock);

	return ci_sdp_info;
}

int fscrypt_sdp_set_sensitive(struct inode *inode, int engine_id, struct fscrypt_key *key)
{
	struct fscrypt_info *ci = inode->i_crypt_info;
	struct fscrypt_sdp_context sdp_ctx;
	struct fscrypt_context ctx;
	int rc = 0;
	int is_dir = 0;

	if (!ci->ci_sdp_info) {
		struct sdp_info *ci_sdp_info = fscrypt_sdp_alloc_sdp_info();
		if (!ci_sdp_info) {
			return -ENOMEM;
		}

		if (cmpxchg(&ci->ci_sdp_info, NULL, ci_sdp_info) != NULL) {
			fscrypt_sdp_put_sdp_info(ci_sdp_info);
			return -EPERM;
		}
	}

	ci->ci_sdp_info->engine_id = engine_id;
	if (S_ISDIR(inode->i_mode)) {
		ci->ci_sdp_info->sdp_flags |= SDP_DEK_IS_SENSITIVE;
		is_dir = 1;
	} else if (S_ISREG(inode->i_mode)) {
		ci->ci_sdp_info->sdp_flags |= SDP_DEK_TO_SET_SENSITIVE;
	}

	sdp_ctx.engine_id = engine_id;
	sdp_ctx.sdp_dek_type = DEK_TYPE_PLAIN;
	sdp_ctx.sdp_dek_len = DEK_MAXLEN;
	memset(sdp_ctx.sdp_dek_buf, 0, DEK_MAXLEN);
	memset(sdp_ctx.sdp_en_buf, 0, MAX_EN_BUF_LEN);

	rc = fscrypt_sdp_set_context(inode, &sdp_ctx, sizeof(sdp_ctx));

	if (rc) {
		DEK_LOGE("%s: Failed to set sensitive flag (err:%d)\n", __func__, rc);
		return rc;
	}

	rc = inode->i_sb->s_cop->get_context(inode, &ctx, sizeof(ctx));
	if (rc < 0) {
		DEK_LOGE("%s: Failed to get fscrypt ctx (err:%d)\n", __func__, rc);
		return rc;
	}

	if (!is_dir) {
		//run setsensitive with nonce from ctx
		rc = __fscrypt_sdp_finish_set_sensitive(inode, &ctx, ci, key);
	} else {
		ctx.knox_flags = FSCRYPT_SDP_PARSE_FLAG_OUT_OF_SDP(ctx.knox_flags) | SDP_DEK_IS_SENSITIVE;
		inode_lock(inode);
		rc = inode->i_sb->s_cop->set_context(inode, &ctx, sizeof(ctx), NULL);
		inode_unlock(inode);
	}

	return rc;
}

int fscrypt_sdp_set_protected(struct inode *inode)
{
	struct fscrypt_info *ci = inode->i_crypt_info;
	struct fscrypt_sdp_context sdp_ctx;
	struct fscrypt_context ctx;
	struct fscrypt_key fek;
	int rc = 0;

	if (!ci || !ci->ci_sdp_info)
		return -EPERM;

	if (!(ci->ci_sdp_info->sdp_flags & SDP_DEK_IS_SENSITIVE)) {
		DEK_LOGD("set_protected: already in protected\n");
		return 0;
	}

	if (dek_is_locked(ci->ci_sdp_info->engine_id)) {
		DEK_LOGE("set_protected: failed due to sdp in locked state\n");
		return -EPERM;
	}

	rc = inode->i_sb->s_cop->get_context(inode, &ctx, sizeof(ctx));
	if (rc != sizeof(ctx)) {
		DEK_LOGE("set_protected: failed to get fscrypt ctx (err:%d)\n", rc);
		return -EINVAL;
	}

	if (!S_ISDIR(inode->i_mode)) {
		rc = fscrypt_sdp_get_context(inode, &sdp_ctx, sizeof(sdp_ctx));
		if (rc != sizeof(sdp_ctx)) {
			DEK_LOGE("set_protected: failed to get sdp context (err:%d)\n", rc);
			return -EINVAL;
		}
#if DEK_DEBUG
		hex_key_dump("set_protected: enonce", sdp_ctx.sdp_en_buf, MAX_EN_BUF_LEN);
#endif
		fek.size = FS_MAX_KEY_SIZE;
		rc = __fscrypt_get_sdp_dek(ci, fek.raw, fek.size);
		if (rc) {
			DEK_LOGE("set_protected: failed to find fek (err:%d)\n", rc);
			return rc;
		}
#if DEK_DEBUG
		hex_key_dump("set_protected: fek", fek.raw, fek.size);
#endif
		rc = __fscrypt_get_nonce(fek.raw, fek.size,
								sdp_ctx.sdp_en_buf, FS_KEY_DERIVATION_NONCE_SIZE,
								ctx.nonce, FS_KEY_DERIVATION_NONCE_SIZE);
		if (rc) {
			DEK_LOGE("set_protected: failed to get nonce (err:%d)\n", rc);
			goto out;
		}
#if DEK_DEBUG
		hex_key_dump("set_protected: nonce", ctx.nonce, FS_KEY_DERIVATION_NONCE_SIZE);
#endif
	}

	ctx.knox_flags = FSCRYPT_SDP_PARSE_FLAG_OUT_OF_SDP(ctx.knox_flags);
	inode_lock(inode);
	rc = inode->i_sb->s_cop->set_context(inode, &ctx, sizeof(ctx), NULL);
	inode_unlock(inode);
	if (rc) {
		DEK_LOGE("%s: Failed to set ext4 context for sdp (err:%d)\n", __func__, rc);
		goto out;
	}

	//Unset SDP context
	ci->ci_sdp_info->sdp_flags = FSCRYPT_SDP_PARSE_FLAG_OUT_OF_SDP(ci->ci_sdp_info->sdp_flags);
	memzero_explicit(sdp_ctx.sdp_dek_buf, DEK_MAXLEN);
	memzero_explicit(sdp_ctx.sdp_en_buf, MAX_EN_BUF_LEN);
	rc = fscrypt_sdp_set_context(inode, &sdp_ctx, sizeof(sdp_ctx));
	// OR, is it OK?
	// rc = fscrypt_sdp_set_context(inode, NULL, 0);

	if (rc) {
		DEK_LOGE("%s: Failed to set sdp context (err:%d)\n", __func__, rc);
		goto out;
	}

	fscrypt_sdp_cache_remove_inode_num(inode);
	mapping_clear_sensitive(inode->i_mapping);

out:
	memzero_explicit(&fek, sizeof(fek));
	return rc;
}

int fscrypt_sdp_add_chamber_directory(int engine_id, struct inode *inode)
{
	struct fscrypt_info *ci = inode->i_crypt_info;
	struct fscrypt_sdp_context sdp_ctx;
	struct fscrypt_context ctx;
	int rc = 0;

	rc = inode->i_sb->s_cop->get_context(inode, &ctx, sizeof(ctx));
	if (rc < 0) {
		DEK_LOGE(KERN_ERR
			   "%s: Failed to get fscrypt ctx (err:%d)\n", __func__, rc);
		return rc;
	}

	if (!ci->ci_sdp_info) {
		struct sdp_info *ci_sdp_info = fscrypt_sdp_alloc_sdp_info();
		if (!ci_sdp_info) {
			return -ENOMEM;
		}

		if (cmpxchg(&ci->ci_sdp_info, NULL, ci_sdp_info) != NULL) {
			DEK_LOGD("Need to put info\n");
			fscrypt_sdp_put_sdp_info(ci_sdp_info);
		}
	}

	ci->ci_sdp_info->sdp_flags |= SDP_IS_CHAMBER_DIR;

	if (!(ci->ci_sdp_info->sdp_flags & SDP_DEK_IS_SENSITIVE)) {
		ci->ci_sdp_info->sdp_flags |= SDP_DEK_IS_SENSITIVE;
		ci->ci_sdp_info->engine_id = engine_id;
		sdp_ctx.sdp_dek_type = DEK_TYPE_PLAIN;
		sdp_ctx.sdp_dek_len = DEK_MAXLEN;
		memset(sdp_ctx.sdp_dek_buf, 0, DEK_MAXLEN);
	} else {
		sdp_ctx.sdp_dek_type = ci->ci_sdp_info->sdp_dek.type;
		sdp_ctx.sdp_dek_len = ci->ci_sdp_info->sdp_dek.len;
		memcpy(sdp_ctx.sdp_dek_buf, ci->ci_sdp_info->sdp_dek.buf, ci->ci_sdp_info->sdp_dek.len);
	}
	sdp_ctx.engine_id = ci->ci_sdp_info->engine_id;

	rc = fscrypt_sdp_set_context(inode, &sdp_ctx, sizeof(sdp_ctx));

	if (rc) {
		DEK_LOGE("%s: Failed to add chamber dir.. (err:%d)\n", __func__, rc);
		return rc;
	}

	ctx.knox_flags = ci->ci_sdp_info->sdp_flags | FSCRYPT_SDP_PARSE_FLAG_OUT_OF_SDP(ctx.knox_flags);
	inode_lock(inode);
	rc = inode->i_sb->s_cop->set_context(inode, &ctx, sizeof(ctx), NULL);
	inode_unlock(inode);
	if (rc) {
		DEK_LOGE("%s: Failed to set ext4 context for sdp (err:%d)\n", __func__, rc);
	}

	return rc;
}

int fscrypt_sdp_remove_chamber_directory(struct inode *inode)
{
	struct fscrypt_info *ci = inode->i_crypt_info;
	struct fscrypt_sdp_context sdp_ctx;
	struct fscrypt_context ctx;
	int rc = 0;

	rc = inode->i_sb->s_cop->get_context(inode, &ctx, sizeof(ctx));
	if (rc < 0) {
		DEK_LOGE(KERN_ERR
			   "%s: Failed to get fscrypt ctx (err:%d)\n", __func__, rc);
		return rc;
	}

	if (!ci->ci_sdp_info)
		return -EINVAL;

	ci->ci_sdp_info->sdp_flags = 0;

	sdp_ctx.engine_id = ci->ci_sdp_info->engine_id;
	sdp_ctx.sdp_dek_type = ci->ci_sdp_info->sdp_dek.type;
	sdp_ctx.sdp_dek_len = ci->ci_sdp_info->sdp_dek.len;
	memset(sdp_ctx.sdp_dek_buf, 0, DEK_MAXLEN);

	rc = fscrypt_sdp_set_context(inode, &sdp_ctx, sizeof(sdp_ctx));

	if (rc) {
		DEK_LOGE("%s: Failed to remove chamber dir.. (err:%d)\n", __func__, rc);
		return rc;
	}

	ctx.knox_flags = FSCRYPT_SDP_PARSE_FLAG_OUT_OF_SDP(ctx.knox_flags);
	inode_lock(inode);
	rc = inode->i_sb->s_cop->set_context(inode, &ctx, sizeof(ctx), NULL);
	inode_unlock(inode);
	if (rc) {
		DEK_LOGE("%s: Failed to set ext4 context for sdp (err:%d)\n", __func__, rc);
	}

	return rc;
}

static inline int __fscrypt_derive_nek_iv(u8 *drv_key, u32 drv_key_len, u8 *out, u32 out_len)
{
	int err;
	u32 L = SEC_FS_DERIVED_KEY_OUTPUT_SIZE;

	if (drv_key == NULL
			|| out == NULL || out_len < SEC_FS_DERIVED_KEY_OUTPUT_SIZE)
		return -EINVAL;

	err = crypto_calc_kdf_hmac_sha512_ctr(KDF_DEFAULT, KDF_RLEN_08BIT,
					drv_key, drv_key_len,
					out, &L,
					SDP_CRYPTO_NEK_DRV_LABEL, strlen(SDP_CRYPTO_NEK_DRV_LABEL),
					SDP_CRYPTO_NEK_DRV_CONTEXT, strlen(SDP_CRYPTO_NEK_DRV_CONTEXT));
	if (err) {
		printk(KERN_ERR
			"derive_nek_iv: failed in crypto_calc_kdf_hmac_sha512_ctr (err:%d)\n", err);
	}
	return err;
}

inline int __fscrypt_get_sdp_dek(struct fscrypt_info *crypt_info,
						unsigned char *dek, unsigned int dek_len)
{
	int res = 0;
	dek_t *__dek;

	__dek = kmalloc(sizeof(dek_t), GFP_NOFS);
	if (!__dek)
		return -ENOMEM;

	res = dek_decrypt_dek_efs(crypt_info->ci_sdp_info->engine_id, &(crypt_info->ci_sdp_info->sdp_dek), __dek);
	if (res < 0) {
		res = -ENOKEY;
		goto out;
	}

	if (__dek->len > dek_len) {
		res = -EINVAL;
		goto out;
	}
	memcpy(dek, __dek->buf, __dek->len);

out:
	memset(__dek->buf, 0, DEK_MAXLEN);
	kzfree(__dek);
	return res;
}

inline int __fscrypt_set_sdp_dek(struct fscrypt_info *crypt_info,
		unsigned char *dek, int dek_len)
{
	int res;
	dek_t *__dek;

	__dek = kmalloc(sizeof(dek_t), GFP_NOFS);
	if (!__dek) {
		return -ENOMEM;
	}

	if (unlikely(dek_len > DEK_MAXLEN))
		goto out;

	__dek->type = DEK_TYPE_PLAIN;
	__dek->len = dek_len;
	memset(__dek->buf, 0, DEK_MAXLEN);
	memcpy(__dek->buf, dek, dek_len);

	res = dek_encrypt_dek_efs(crypt_info->ci_sdp_info->engine_id, __dek, &crypt_info->ci_sdp_info->sdp_dek);

	memset(__dek->buf, 0, DEK_MAXLEN);
out:
	kzfree(__dek);
	return res;
}

inline int __fscrypt_get_nonce(u8 *key, u32 key_len,
						u8 *enonce, u32 nonce_len,
						u8 *out, u32 out_len)
{
	u8 *nek;
	u8 drv_buf[SEC_FS_DERIVED_KEY_OUTPUT_SIZE];
	u32 drv_buf_len = SEC_FS_DERIVED_KEY_OUTPUT_SIZE;
	u32 nek_len = SDP_CRYPTO_NEK_LEN;
	int rc;
	struct crypto_aead *tfm;
	gcm_pack32 pack;
	gcm_pack __pack;
	size_t pack_siz = sizeof(pack);

	if (out == NULL || out_len < nonce_len)
		return -EINVAL;

	rc = __fscrypt_derive_nek_iv(key, key_len, drv_buf, drv_buf_len);
	if (rc)
		goto out;

	memcpy(&pack, enonce, pack_siz);
	nek = (u8 *)drv_buf;
#if DEK_DEBUG
	hex_key_dump("get_nonce: gcm pack", (uint8_t *)&pack, pack_siz);
	hex_key_dump("get_nonce: nek_iv", nek, SEC_FS_DERIVED_KEY_OUTPUT_SIZE);
#endif
	__pack.type = SDP_CRYPTO_GCM_PACK32;
	__pack.iv = pack.iv;
	__pack.data = pack.data;
	__pack.auth = pack.auth;

	tfm = sdp_crypto_aes_gcm_key_setup(nek, nek_len);
	if (IS_ERR(tfm)) {
		rc = PTR_ERR(tfm);
		goto out;
	}

	rc = sdp_crypto_aes_gcm_decrypt_pack(tfm, &__pack);
	if (!rc) {
		memcpy(out, pack.data, nonce_len);
#if DEK_DEBUG
		hex_key_dump("get_nonce: pack", (u8 *)&pack, pack_siz);
#endif
	}

	crypto_free_aead(tfm);

out:
	memzero_explicit(&pack, pack_siz);
	memzero_explicit(drv_buf, SEC_FS_DERIVED_KEY_OUTPUT_SIZE);
	return rc;
}

static inline int __fscrypt_set_nonce(u8 *key, u32 key_len,
						u8 *nonce, u32 nonce_len,
						u8 *out, u32 out_len)
{
	u8 *iv;
	u8 *nek;
	u8 drv_buf[SEC_FS_DERIVED_KEY_OUTPUT_SIZE];
	u32 drv_buf_len = SEC_FS_DERIVED_KEY_OUTPUT_SIZE;
	u32 nek_len = SDP_CRYPTO_NEK_LEN;
	int rc;
	struct crypto_aead *tfm;
	gcm_pack32 pack;
	gcm_pack __pack;
	size_t pack_siz = sizeof(pack);

	if (out == NULL || out_len < pack_siz)
		return -EINVAL;

	rc = __fscrypt_derive_nek_iv(key, key_len, drv_buf, drv_buf_len);
	if (rc)
		goto out;

	memset(&pack, 0, pack_siz);

	nek = (u8 *)drv_buf;
	iv = (u8 *)nek + nek_len;
#if DEK_DEBUG
	hex_key_dump("set_nonce: nonce", nonce, nonce_len);
	hex_key_dump("set_nonce: nek_iv", nek, SEC_FS_DERIVED_KEY_OUTPUT_SIZE);
#endif
	memcpy(pack.iv, iv, SDP_CRYPTO_GCM_IV_LEN);
	memcpy(pack.data, nonce, nonce_len);
	__pack.type = SDP_CRYPTO_GCM_PACK32;
	__pack.iv = pack.iv;
	__pack.data = pack.data;
	__pack.auth = pack.auth;


	tfm = sdp_crypto_aes_gcm_key_setup(nek, nek_len);
	if (IS_ERR(tfm)) {
		rc = PTR_ERR(tfm);
		goto out;
	}

	rc = sdp_crypto_aes_gcm_encrypt_pack(tfm, &__pack);
	if (!rc) {
		memcpy(out, &pack, pack_siz);
#if DEK_DEBUG
		hex_key_dump("set_nonce: pack", (u8 *)&pack, pack_siz);
#endif
	}

	crypto_free_aead(tfm);

out:
	memzero_explicit(&pack, pack_siz);
	memzero_explicit(drv_buf, SEC_FS_DERIVED_KEY_OUTPUT_SIZE);
	return rc;
}

inline int __fscrypt_get_sdp_context(struct inode *inode, struct fscrypt_info *crypt_info)
{
	int res = 0;
	struct fscrypt_sdp_context sdp_ctx;

	res = fscrypt_sdp_get_context(inode, &sdp_ctx, sizeof(sdp_ctx));

	if (res == sizeof(sdp_ctx)) {
		crypt_info->ci_sdp_info->engine_id = sdp_ctx.engine_id;
		crypt_info->ci_sdp_info->sdp_dek.type = sdp_ctx.sdp_dek_type;
		crypt_info->ci_sdp_info->sdp_dek.len = sdp_ctx.sdp_dek_len;
		DEK_LOGD("sensitive flags = %x, engid = %d\n", crypt_info->ci_sdp_info->sdp_flags, sdp_ctx.engine_id);
		memcpy(crypt_info->ci_sdp_info->sdp_dek.buf, sdp_ctx.sdp_dek_buf,
				sizeof(crypt_info->ci_sdp_info->sdp_dek.buf));

		if (S_ISDIR(inode->i_mode))
			crypt_info->ci_sdp_info->sdp_flags |= SDP_IS_DIRECTORY;

		res = 0;
	} else {
		res = -EINVAL;
	}

	return res;
}

static inline void __fscrypt_sdp_set_inode_sensitive(struct inode *inode)
{
	fscrypt_sdp_cache_add_inode_num(inode);
	mapping_set_sensitive(inode->i_mapping);
}

inline int __fscrypt_sdp_finish_set_sensitive(struct inode *inode,
				struct fscrypt_context *ctx, struct fscrypt_info *crypt_info,
				struct fscrypt_key *key) {
	int res = 0;
	struct fscrypt_sdp_context sdp_ctx;
	struct fscrypt_key fek;
	u8 enonce[MAX_EN_BUF_LEN];

	if ((crypt_info->ci_sdp_info->sdp_flags & SDP_DEK_TO_SET_SENSITIVE)
			|| (crypt_info->ci_sdp_info->sdp_flags & SDP_DEK_TO_CONVERT_KEY_TYPE)) {
		DEK_LOGD("sensitive SDP_DEK_TO_SET_SENSITIVE\n");
		//It's a new sensitive file, let's make sdp dek!
		if (key) {
			DEK_LOGD("set_sensitive: fek is already given!\n");
			memcpy(&fek, key, sizeof(fek));
		} else {
			memset(&fek, 0, sizeof(fek));
			res = fscrypt_get_encryption_key(inode, &fek);
			if (res) {
				DEK_LOGE("set_sensitive: failed to find fek (err:%d)\n", res);
				return res;
			}
		}
#if DEK_DEBUG
		hex_key_dump("set_sensitive: fek", fek.raw, fek.size);
#endif
		res = __fscrypt_set_nonce(fek.raw, fek.size,
								ctx->nonce, FS_KEY_DERIVATION_NONCE_SIZE,
								enonce, MAX_EN_BUF_LEN);
		if (res) {
			DEK_LOGE("set_sensitive: failed to encrypt nonce (err:%d)\n", res);
			goto out;
		}
#if DEK_DEBUG
		hex_key_dump("set_sensitive: enonce", enonce, MAX_EN_BUF_LEN);
#endif
		res = __fscrypt_set_sdp_dek(crypt_info, fek.raw, fek.size);
		if (res) {
				DEK_LOGE("set_sensitive: failed to encrypt dek (err:%d)\n", res);
			goto out;
		}

		crypt_info->ci_sdp_info->sdp_flags &= ~(SDP_DEK_TO_SET_SENSITIVE);
		crypt_info->ci_sdp_info->sdp_flags &= ~(SDP_DEK_TO_CONVERT_KEY_TYPE);
		crypt_info->ci_sdp_info->sdp_flags |= SDP_DEK_IS_SENSITIVE;
		sdp_ctx.engine_id = crypt_info->ci_sdp_info->engine_id;
		sdp_ctx.sdp_dek_type = crypt_info->ci_sdp_info->sdp_dek.type;
		sdp_ctx.sdp_dek_len = crypt_info->ci_sdp_info->sdp_dek.len;

		/* Update EFEK */
		memcpy(sdp_ctx.sdp_dek_buf, crypt_info->ci_sdp_info->sdp_dek.buf, DEK_MAXLEN);

		/* Update EN */
		memcpy(sdp_ctx.sdp_en_buf, enonce, MAX_EN_BUF_LEN);

		/* Update SDP Context */
		res = fscrypt_sdp_set_context(inode, &sdp_ctx, sizeof(sdp_ctx));
		if (res) {
			DEK_LOGE("set_sensitive: failed to set sdp context (err:%d)\n", res);
			goto out;
		}

		/* Update FS Context */
		ctx->knox_flags = (FSCRYPT_SDP_PARSE_FLAG_OUT_OF_SDP(ctx->knox_flags) | SDP_DEK_IS_SENSITIVE);
		memzero_explicit(ctx->nonce, FS_KEY_DERIVATION_NONCE_SIZE);
		inode_lock(inode);
		res = inode->i_sb->s_cop->set_context(inode, ctx, sizeof(*ctx), NULL);
		inode_unlock(inode);
		if (res) {
			DEK_LOGE("set_sensitive: failed to set fscrypt context(err:%d)\n", res);
			goto out;
		}
		DEK_LOGD("sensitive SDP_DEK_TO_SET_SENSITIVE finished!!\n");
	}

	if ((crypt_info->ci_sdp_info->sdp_flags & SDP_DEK_IS_SENSITIVE) &&
			!(crypt_info->ci_sdp_info->sdp_flags & SDP_IS_DIRECTORY)) {
		__fscrypt_sdp_set_inode_sensitive(inode);
#ifdef CONFIG_SDP_KEY_DUMP
		if (get_sdp_sysfs_key_dump()) {
			key_dump(fek.raw, fek.size);
		}
#endif
	}

out:
	memzero_explicit(&fek, sizeof(fek));
	return res;
}

int fscrypt_sdp_get_engine_id(struct inode *inode)
{
	struct fscrypt_info *crypt_info;

	crypt_info = inode->i_crypt_info;
	if (!crypt_info || !crypt_info->ci_sdp_info)
		return -1;

	return crypt_info->ci_sdp_info->engine_id;
}

typedef enum {
	SDP_THREAD_SET_SENSITIVE,
	SDP_THREAD_KEY_CONVERT
} sdp_thread_type;

// Should be called by only fscrypt_sdp_run_thread()
inline int __fscrypt_sdp_thread_set_sensitive(void *arg)
{
	sdp_ess_material *sem = (sdp_ess_material *)arg;
	struct inode *inode;
	struct fscrypt_info *ci;
	struct fscrypt_key *key;

	if (sem && sem->inode) {
		inode = sem->inode;
		key = &sem->key;
		ci = inode->i_crypt_info;

		if (ci && ci->ci_sdp_info) {
			fscrypt_sdp_set_sensitive(inode, ci->ci_sdp_info->engine_id, key);
		}

		if (key)
			memzero_explicit(key, sizeof(*key));
		kzfree(sem);
	}
	iput(inode);
	return 0;
}

// Should be called by only fscrypt_sdp_run_thread()
inline int __fscrypt_sdp_thread_convert_sdp_key(void *arg)
{
	sdp_ess_material *sem = (sdp_ess_material *)arg;
	struct inode *inode;
	struct fscrypt_info *ci;
	struct fscrypt_context ctx;
	struct fscrypt_sdp_context sdp_ctx;
	struct fscrypt_key *fek = NULL;
	int rc = 0;

	if (sem && sem->inode) {
		inode = sem->inode;
		fek = &sem->key;
		ci = inode->i_crypt_info;

		if (ci && ci->ci_sdp_info) {
			rc = inode->i_sb->s_cop->get_context(inode, &ctx, sizeof(ctx));
			if (rc != sizeof(ctx)) {
				if (rc > 0 )
					rc = -EINVAL;
				DEK_LOGE("convert_key: failed to get fscrypt ctx (err:%d)\n", rc);
				goto out;
			}

			if (!fek) {
				rc = -ENOKEY;
				DEK_LOGE("convert_key: failed to find fek (err:%d)\n", rc);
				goto out;
			}

			rc = fscrypt_sdp_get_context(inode, &sdp_ctx, sizeof(sdp_ctx));
			if (rc != sizeof(sdp_ctx)) {
				if (rc > 0 )
					rc = -EINVAL;
				DEK_LOGE("convert_key: failed to get sdp context (err:%d)\n", rc);
				goto out;
			}
#if DEK_DEBUG
			hex_key_dump("convert_key: fek", fek->raw, fek->size);
#endif
			rc = __fscrypt_get_nonce(fek->raw, fek->size,
									sdp_ctx.sdp_en_buf, FS_KEY_DERIVATION_NONCE_SIZE,
									ctx.nonce, FS_KEY_DERIVATION_NONCE_SIZE);
			if (rc) {
				DEK_LOGE("convert_key: failed to get nonce (err:%d)\n", rc);
				goto out;
			}

			__fscrypt_sdp_finish_set_sensitive(inode, &ctx, ci, fek);
		}
out:
		if (fek)
			memzero_explicit(fek, sizeof(*fek));
		kzfree(sem);
	}

	iput(inode);
	return 0;
}

inline int fscrypt_sdp_run_thread(struct inode *inode,
								void *data, unsigned int data_len,
								sdp_thread_type thread_type)
{
	int res = -1;
	struct task_struct *task = NULL;
	sdp_ess_material *__sem = NULL;

	if (unlikely(
			!data || data_len > FS_MAX_KEY_SIZE))
		return -EINVAL;

	__sem = kmalloc(sizeof(sdp_ess_material), GFP_ATOMIC);
	if (unlikely(!__sem))
		return -ENOMEM;

	if (thread_type == SDP_THREAD_SET_SENSITIVE) {
		if (igrab(inode)) {
			__sem->inode = inode;
			__sem->key.mode = 0;
			__sem->key.size = data_len;
			memcpy(__sem->key.raw, data, data_len);
			task = kthread_run(__fscrypt_sdp_thread_set_sensitive, (void *)__sem, "__fscrypt_sdp_thread_set_sensitive");
		}
	}
	else if (thread_type == SDP_THREAD_KEY_CONVERT) {
		if (igrab(inode)) {
			__sem->inode = inode;
			__sem->key.mode = 0;
			__sem->key.size = data_len;
			memcpy(__sem->key.raw, data, data_len);
			task = kthread_run(__fscrypt_sdp_thread_convert_sdp_key, (void *)__sem, "__fscrypt_sdp_thread_convert_sdp_key");
		}
	}

	if(IS_ERR_OR_NULL(task)) {
		if (IS_ERR(task)) {
			res = PTR_ERR(task);
			memzero_explicit(__sem, sizeof(sdp_ess_material));
			iput(inode);
		}
		DEK_LOGE("sdp_run_thread: failed to create kernel thread (err:%d)\n", res);
		kzfree(__sem);
	} else {
		res = 0;
	}
	return res;
}

int fscrypt_sdp_update_sdp_info(struct inode *inode,
						const struct fscrypt_context *ctx,
						struct fscrypt_info *crypt_info)
{
	crypt_info->ci_sdp_info->sdp_flags =
						FSCRYPT_SDP_PARSE_FLAG_SDP_ONLY(ctx->knox_flags);
	return __fscrypt_get_sdp_context(inode, crypt_info);
}

inline int fscrypt_sdp_is_regular_sensitive(struct fscrypt_info *crypt_info)
{
	return (crypt_info->ci_sdp_info->sdp_flags & SDP_DEK_IS_SENSITIVE)
			&& !(crypt_info->ci_sdp_info->sdp_flags & SDP_IS_DIRECTORY);
}

inline void fscrypt_sdp_update_conv_status(struct fscrypt_info *crypt_info)
{
	if (crypt_info->ci_sdp_info->sdp_dek.type != DEK_TYPE_AES_ENC) {
		crypt_info->ci_sdp_info->sdp_flags |= SDP_DEK_TO_CONVERT_KEY_TYPE;
		DEK_LOGD("Need conversion!\n");
	}
	return;
}

int fscrypt_sdp_derive_dek(struct fscrypt_info *crypt_info,
						unsigned char *decrypted_key,
						unsigned int decrypted_key_len)
{
	return __fscrypt_get_sdp_dek(crypt_info, decrypted_key, decrypted_key_len);
}

int fscrypt_sdp_test_and_inherit_context(struct inode *parent, struct inode *child, struct fscrypt_context *ctx)
{
	int res = 0;
	struct fscrypt_info *ci;

	ci = parent->i_crypt_info;
	if (ci && ci->ci_sdp_info
			&& (ci->ci_sdp_info->sdp_flags & SDP_DEK_IS_SENSITIVE)) {
		struct fscrypt_sdp_context sdp_ctx;

		DEK_LOGD("parent->i_crypt_info->sdp_flags: %x\n", ci->ci_sdp_info->sdp_flags);

		ctx->knox_flags = FSCRYPT_SDP_PARSE_FLAG_OUT_OF_SDP(ctx->knox_flags) | ci->ci_sdp_info->sdp_flags;
		if (!S_ISDIR(child->i_mode)) {
			ctx->knox_flags &= ~SDP_DEK_IS_SENSITIVE;
			ctx->knox_flags &= ~SDP_IS_DIRECTORY;
			ctx->knox_flags |= SDP_DEK_TO_SET_SENSITIVE;
		}
		ctx->knox_flags &= ~SDP_IS_CHAMBER_DIR;
		sdp_ctx.engine_id = ci->ci_sdp_info->engine_id;
		sdp_ctx.sdp_dek_type = DEK_TYPE_PLAIN;
		sdp_ctx.sdp_dek_len = DEK_MAXLEN;
		memset(sdp_ctx.sdp_dek_buf, 0, DEK_MAXLEN);

		DEK_LOGD("Inherited ctx->knox_flags: %x\n", ctx->knox_flags);

		res = fscrypt_sdp_set_context_nolock(child, &sdp_ctx, sizeof(sdp_ctx));
	}

	return res;
}

void fscrypt_sdp_finalize_tasks(struct inode *inode, u8 *raw_key, int key_len)
{
	struct fscrypt_info *ci = inode->i_crypt_info;//This pointer has been loaded by get_encryption_info completely

	if (ci && ci->ci_sdp_info
			&& (ci->ci_sdp_info->sdp_flags & FSCRYPT_KNOX_FLG_SDP_MASK)) {
		__fscrypt_sdp_finalize_tasks(inode, ci, raw_key, key_len);
	}
}

inline void __fscrypt_sdp_finalize_tasks(struct inode *inode,
						struct fscrypt_info *ci, u8 *raw_key, int key_len)
{
	int res;

	if ((ci->ci_sdp_info->sdp_flags & SDP_DEK_IS_SENSITIVE) &&
			!(ci->ci_sdp_info->sdp_flags & SDP_IS_DIRECTORY)) {
		__fscrypt_sdp_set_inode_sensitive(inode);
	}

	if (ci->ci_sdp_info->sdp_flags & SDP_DEK_TO_SET_SENSITIVE) {//Case for newly inherited child inode (Not sensitive yet)
		if (key_len <= 0) {
			DEK_LOGE("finalize_tasks: invalid key size (maybe previous err:%d)\n", key_len);
			goto out;
		}

		DEK_LOGD("Run set sensitive thread\n");
		res = fscrypt_sdp_run_thread(inode, (void *)raw_key, key_len, SDP_THREAD_SET_SENSITIVE);
		if (res) {
			DEK_LOGE("finalize_tasks: failed to run set_sensitive thread (err:%d)\n", res);
		}
	} else if (ci->ci_sdp_info->sdp_flags & SDP_DEK_TO_CONVERT_KEY_TYPE) {//Case for converting from asym to sym (Already sensitive)
		if (key_len <= 0) {
			DEK_LOGE("finalize_tasks: invalid key size (maybe previous err:%d)\n", key_len);
			goto out;
		}

		DEK_LOGD("Run key convert thread\n");
		res = fscrypt_sdp_run_thread(inode, (void *)raw_key, key_len, SDP_THREAD_KEY_CONVERT);
		if (res) {
			DEK_LOGE("finalize_tasks: failed to run key_convert thread (err:%d)\n", res);
		}
	}

out:
	return;
}

void fscrypt_sdp_put_sdp_info(struct sdp_info *ci_sdp_info)
{
	if (ci_sdp_info) {
		kmem_cache_free(sdp_info_cachep, ci_sdp_info);
	}
}

bool fscrypt_sdp_init_sdp_info_cachep(void)
{
	sdp_info_cachep = KMEM_CACHE(sdp_info, SLAB_RECLAIM_ACCOUNT);
	if (!sdp_info_cachep)
		return false;
	return true;
}

void fscrypt_sdp_release_sdp_info_cachep(void)
{
	kmem_cache_destroy(sdp_info_cachep);
}
