package bast1aan.pgpreader;

import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.bcpg.ECSecretBCPGKey
import java.io.InputStream
import java.io.BufferedInputStream
import java.io.FileInputStream
import java.io.File

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

internal fun usage() {
	println("Usage: pgpreader <file.pgp>")
}

public fun main(args: Array<String>) {
	if (args.size < 1) { return usage() }
	var file = args[0]
	if (!File(file).exists()) {
		println("${file} does not exist")
		return usage()
	}
	var key = openPrivateKeyFile(file)
	if (key != null) {
		val packet = key.privateKeyDataPacket
		if (packet is ECSecretBCPGKey) {
			print("D: ")
			println(packet.getX())
		} else {
			println("Only EC private keys are supported as of now.")
		}
		println(key.keyID)
	} else {
		println("Invalid PGP file, or not a secret key")
	}
}
