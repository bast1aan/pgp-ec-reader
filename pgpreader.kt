package bast1aan.pgpreader;

import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.PGPSecretKey
import java.io.InputStream
import java.io.BufferedInputStream
import java.io.FileInputStream

internal fun openPrivateKeyFile(fileName: String, keyId: Long? = null, pass: String? = null): PGPPrivateKey? {
	var fp = FileInputStream(fileName)
	var keyIn = BufferedInputStream(fp)
	var rings = PGPSecretKeyRingCollection(
		PGPUtil.getDecoderStream(keyIn), 
		JcaKeyFingerprintCalculator()
	)
	var secKey: PGPSecretKey? = null
	if (keyId == null) {
		// find first
		for (ring in rings.getKeyRings()) {
			for (key in ring.getSecretKeys()) {
				if (key.isSigningKey()) {
					secKey = key
					break
				}
			}
			if (secKey != null) {
				break
			}
		}
	} else {
		secKey = rings.getSecretKey(keyId)
	}
	fp.close()
	if (secKey == null) {
		return null
	}
	var passChar = CharArray(0)
	
	if (pass != null) {
		passChar = pass.toCharArray()
	}

	return secKey.extractPrivateKey(
		JcePBESecretKeyDecryptorBuilder()
			.setProvider("BC")
			.build(passChar)
	)
}

public fun main(args: Array<String>) {
    println("Hallo");
    var key = openPrivateKeyFile("secret-key.pgp")
    if (key != null) {
        println(key.keyID)
        println(key::class)
        println(key.privateKeyDataPacket::class)
    } else {
        println("private key is null")
    }
}