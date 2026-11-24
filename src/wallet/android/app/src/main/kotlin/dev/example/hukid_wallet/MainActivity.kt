package dev.example.hukid_wallet

import android.content.Intent
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import java.io.File
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class MainActivity : FlutterActivity() {
    companion object {
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        private const val KEYSTORE_CHANNEL = "dev.example.hukid_wallet/keystore"
        private const val VAULT_CHANNEL = "dev.example.hukid_wallet/vault"
        private const val DEEPLINK_CHANNEL = "dev.example.hukid_wallet/deeplink"
        private const val VAULT_KEY_ALIAS = "hukid_wallet_vault_aes256"
        private const val GCM_TAG_BITS = 128
        private val RECORD_ID_RE = Regex("^[A-Za-z0-9_-]{1,128}$")
        private val KEY_ALIAS_RE = Regex("^[A-Za-z0-9._-]{1,128}$")
    }

    private var deepLinkChannel: MethodChannel? = null
    private var initialOfferLink: String? = null

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        captureDeepLink(intent, dispatch = false)

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, KEYSTORE_CHANNEL)
            .setMethodCallHandler { call, result ->
                try {
                    when (call.method) {
                        "ensureHolderKey" -> {
                            val alias = requireAlias(call.argument<String>("alias"))
                            result.success(ensureHolderKey(alias))
                        }
                        "signEs256" -> {
                            val alias = requireAlias(call.argument<String>("alias"))
                            val data = call.argument<ByteArray>("data")
                                ?: throw IllegalArgumentException("missing data")
                            result.success(signEs256(alias, data))
                        }
                        "deleteHolderKey" -> {
                            val alias = requireAlias(call.argument<String>("alias"))
                            deleteKey(alias)
                            result.success(null)
                        }
                        else -> result.notImplemented()
                    }
                } catch (err: Exception) {
                    result.error("KEYSTORE_ERROR", err.message ?: "keystore failure", null)
                }
            }

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, VAULT_CHANNEL)
            .setMethodCallHandler { call, result ->
                try {
                    when (call.method) {
                        "saveRecord" -> {
                            val id = requireRecordId(call.argument<String>("id"))
                            val plaintext = call.argument<String>("plaintext")
                                ?: throw IllegalArgumentException("missing plaintext")
                            saveEncryptedRecord(id, plaintext)
                            result.success(null)
                        }
                        "readAllRecords" -> {
                            result.success(readAllEncryptedRecords())
                        }
                        "deleteRecord" -> {
                            val id = requireRecordId(call.argument<String>("id"))
                            deleteEncryptedRecord(id)
                            result.success(null)
                        }
                        else -> result.notImplemented()
                    }
                } catch (err: Exception) {
                    result.error("VAULT_ERROR", err.message ?: "vault failure", null)
                }
            }

        deepLinkChannel = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, DEEPLINK_CHANNEL)
        deepLinkChannel?.setMethodCallHandler { call, result ->
            when (call.method) {
                "consumeInitialLink" -> {
                    val pending = initialOfferLink
                    initialOfferLink = null
                    result.success(pending)
                }
                else -> result.notImplemented()
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        captureDeepLink(intent, dispatch = true)
    }

    private fun captureDeepLink(intent: Intent?, dispatch: Boolean) {
        val raw = intent?.dataString?.trim() ?: return
        if (!raw.startsWith("openid-credential-offer://") && !raw.startsWith("openid4vp://")) return
        if (dispatch && deepLinkChannel != null) {
            deepLinkChannel?.invokeMethod("onLink", raw)
        } else {
            initialOfferLink = raw
        }
    }

    private fun requireAlias(alias: String?): String {
        val trimmed = alias?.trim() ?: ""
        require(KEY_ALIAS_RE.matches(trimmed) && trimmed != VAULT_KEY_ALIAS) {
            "invalid key alias"
        }
        return trimmed
    }

    private fun requireRecordId(id: String?): String {
        val trimmed = id?.trim() ?: ""
        require(RECORD_ID_RE.matches(trimmed)) { "invalid vault record id" }
        return trimmed
    }

    private fun ensureHolderKey(alias: String): Map<String, String> {
        val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        if (!ks.containsAlias(alias)) {
            val spec = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build()
            val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER)
            kpg.initialize(spec)
            kpg.generateKeyPair()
        }
        val cert = ks.getCertificate(alias) ?: throw IllegalStateException("missing certificate")
        val ecPub = cert.publicKey as? ECPublicKey
            ?: throw IllegalStateException("key is not EC P-256")
        val xBytes = bigIntTo32Bytes(ecPub.w.affineX)
        val yBytes = bigIntTo32Bytes(ecPub.w.affineY)
        val encoder = Base64.getUrlEncoder().withoutPadding()
        return mapOf(
            "kty" to "EC",
            "crv" to "P-256",
            "x" to encoder.encodeToString(xBytes),
            "y" to encoder.encodeToString(yBytes)
        )
    }

    private fun signEs256(alias: String, data: ByteArray): ByteArray {
        val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        val entry = ks.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
            ?: throw IllegalStateException("holder key not found")
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(entry.privateKey)
        sig.update(data)
        return derToP1363(sig.sign())
    }

    private fun deleteKey(alias: String) {
        val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        if (ks.containsAlias(alias)) {
            ks.deleteEntry(alias)
        }
    }

    private fun ensureVaultKey(): SecretKey {
        val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        val existing = ks.getKey(VAULT_KEY_ALIAS, null) as? SecretKey
        if (existing != null) return existing
        val spec = KeyGenParameterSpec.Builder(
            VAULT_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
            .build()
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
        kg.init(spec)
        return kg.generateKey()
    }

    private fun vaultDir(): File = File(filesDir, "hukid_vault").apply { mkdirs() }

    private fun saveEncryptedRecord(id: String, plaintext: String) {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, ensureVaultKey())
        val iv = cipher.iv
        require(iv.isNotEmpty() && iv.size <= 32) { "unexpected GCM IV length" }
        val ciphertext = cipher.doFinal(plaintext.toByteArray(StandardCharsets.UTF_8))

        val dir = vaultDir()
        val tmp = File(dir, "$id.tmp")
        val dst = File(dir, "$id.enc")
        val packed = ByteArray(1 + iv.size + ciphertext.size)
        packed[0] = iv.size.toByte()
        System.arraycopy(iv, 0, packed, 1, iv.size)
        System.arraycopy(ciphertext, 0, packed, 1 + iv.size, ciphertext.size)
        tmp.writeBytes(packed)
        if (dst.exists()) {
            dst.delete()
        }
        if (!tmp.renameTo(dst)) {
            tmp.delete()
            throw IllegalStateException("failed to persist encrypted vault record")
        }
    }

    private fun readAllEncryptedRecords(): List<String> {
        val dir = vaultDir()
        val files = dir.listFiles { _, name -> name.endsWith(".enc") } ?: return emptyList()
        val key = ensureVaultKey()
        val out = ArrayList<String>(files.size)
        for (file in files.sortedBy { it.name }) {
            val packed = file.readBytes()
            if (packed.size < 2) continue
            val ivLen = packed[0].toInt() and 0xff
            if (ivLen <= 0 || packed.size <= 1 + ivLen) continue
            val iv = packed.copyOfRange(1, 1 + ivLen)
            val ciphertext = packed.copyOfRange(1 + ivLen, packed.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
            val plain = cipher.doFinal(ciphertext)
            out.add(String(plain, StandardCharsets.UTF_8))
        }
        return out
    }

    private fun deleteEncryptedRecord(id: String) {
        val dst = File(vaultDir(), "$id.enc")
        if (dst.exists()) {
            dst.delete()
        }
    }

    private fun bigIntTo32Bytes(value: BigInteger): ByteArray {
        val raw = value.toByteArray()
        val out = ByteArray(32)
        if (raw.size == 32) return raw
        if (raw.size > 32) {
            val offset = raw.size - 32
            for (i in 0 until offset) {
                require(raw[i].toInt() == 0) { "coordinate exceeds 256 bits" }
            }
            System.arraycopy(raw, offset, out, 0, 32)
            return out
        }
        System.arraycopy(raw, 0, out, 32 - raw.size, raw.size)
        return out
    }

    private fun derToP1363(der: ByteArray): ByteArray {
        var idx = 0
        require(der.isNotEmpty() && der[idx++].toInt() == 0x30) { "invalid DER sequence" }
        val (seqLen, nextAfterSeqLen) = readDerLength(der, idx)
        idx = nextAfterSeqLen
        require(idx + seqLen == der.size) { "invalid DER sequence length" }

        require(idx < der.size && der[idx++].toInt() == 0x02) { "expected INTEGER for r" }
        val (rLen, afterRLen) = readDerLength(der, idx)
        idx = afterRLen
        require(idx + rLen <= der.size) { "truncated r integer" }
        val rBytes = der.copyOfRange(idx, idx + rLen)
        idx += rLen

        require(idx < der.size && der[idx++].toInt() == 0x02) { "expected INTEGER for s" }
        val (sLen, afterSLen) = readDerLength(der, idx)
        idx = afterSLen
        require(idx + sLen == der.size) { "invalid s integer length" }
        val sBytes = der.copyOfRange(idx, idx + sLen)

        val out = ByteArray(64)
        copyUnsignedCoordinate(rBytes, out, 0)
        copyUnsignedCoordinate(sBytes, out, 32)
        return out
    }

    private fun readDerLength(buf: ByteArray, offset: Int): Pair<Int, Int> {
        require(offset < buf.size) { "truncated DER length" }
        val first = buf[offset].toInt() and 0xff
        if (first < 0x80) return Pair(first, offset + 1)
        val numBytes = first and 0x7f
        require(numBytes in 1..2 && offset + 1 + numBytes <= buf.size) { "unsupported DER length" }
        var len = 0
        for (i in 0 until numBytes) {
            len = (len shl 8) or (buf[offset + 1 + i].toInt() and 0xff)
        }
        return Pair(len, offset + 1 + numBytes)
    }

    private fun copyUnsignedCoordinate(src: ByteArray, dst: ByteArray, dstOffset: Int) {
        var start = 0
        while (start < src.size - 1 && src[start].toInt() == 0) {
            start++
        }
        val len = src.size - start
        require(len in 1..32) { "ECDSA component out of range" }
        System.arraycopy(src, start, dst, dstOffset + (32 - len), len)
    }
}
