package bast1aan.pgpreader

import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.bcpg.ECSecretBCPGKey
import org.bouncycastle.bcpg.ECPublicBCPGKey
import org.bouncycastle.asn1.x9.ECNamedCurveTable
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.crypto.ec.CustomNamedCurves
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper
import org.bouncycastle.math.ec.ECCurve
import org.bouncycastle.util.BigIntegers
import org.bouncycastle.util.encoders.Hex
import java.security.spec.ECPoint as JavaECPoint
import java.security.spec.ECPublicKeySpec as JavaECPublicKeySpec
import java.security.spec.ECPrivateKeySpec as JavaECPrivateKeySpec
import java.security.spec.ECGenParameterSpec as JavaECGenParameterSpec
import java.security.spec.ECParameterSpec as JavaECParameterSpec
import java.io.BufferedInputStream
import java.io.FileInputStream
import java.io.File
import java.io.FileOutputStream
import java.math.BigInteger
import java.util.HexFormat

internal fun openPrivateKeyFile(fileName: String, keyId: ByteArray? = null, pass: String? = null): PGPPrivateKey? {
	val fp = FileInputStream(fileName)
	val keyIn = BufferedInputStream(fp)
	val rings = PGPSecretKeyRingCollection(
		PGPUtil.getDecoderStream(keyIn), 
		JcaKeyFingerprintCalculator()
	)
	var secKey: PGPSecretKey? = null
	for (ring in rings.keyRings) {
		for (key in ring.secretKeys) {
			if (keyId != null && keyId contentEquals key.fingerprint || 
				keyId == null && key.isSigningKey()
			) {
				secKey = key
				break
			}
		}
		if (secKey != null) {
			break
		}
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

internal fun getX9Parameters(oid: ASN1ObjectIdentifier) = CustomNamedCurves.getByOID(oid) ?: ECNamedCurveTable.getByOID(oid)

internal fun decodePoint(xyEncoded: BigInteger, ecCurve: ECCurve) = ecCurve.decodePoint(BigIntegers.asUnsignedByteArray(xyEncoded))

internal fun usage() {
	println("Usage: pgpreader <file.pgp> [, key_fingerprint ]")
}

internal fun getECParameterSpec(curveOID: ASN1ObjectIdentifier): JavaECParameterSpec {
	val helper = DefaultJcaJceHelper()
	val params = helper.createAlgorithmParameters("EC")

	params.init(JavaECGenParameterSpec(ECNamedCurveTable.getName(curveOID)))

	return params.getParameterSpec(JavaECParameterSpec::class.java)
}

public fun main(args: Array<String>) {
	if (args.size < 1) return usage()
	val file = args[0]
	if (!File(file).exists()) {
		println("${file} does not exist")
		return usage()
	}
	var keyId: ByteArray? = null
	if (args.size >= 2) {
		try {
			keyId = HexFormat.of().parseHex(args[1])
		} catch (e: IllegalArgumentException) {
			println("Warning: ${args[1]} is not a valid key fingerprint, ignored.")
		}
	}
	// TODO implement password, from stdin would be nice
	val key = openPrivateKeyFile(file, keyId)
	if (key != null) {
		val packet = key.privateKeyDataPacket
		val publicKey = key.publicKeyPacket.key
		print("Algorithm: ")
		println(key.publicKeyPacket.algorithm)
		if (packet is ECSecretBCPGKey && publicKey is ECPublicBCPGKey) {
			val d = packet.x
			print("D: ")
			println(d)
			val curveOID = publicKey.curveOID
			val x9Params = getX9Parameters(curveOID)
			val ecPubPoint = decodePoint(publicKey.encodedPoint, x9Params.curve)
			print("X: ")
			println(ecPubPoint.affineXCoord.toBigInteger())
			print("Y: ")
			println(ecPubPoint.affineYCoord.toBigInteger())
			val ecPubSpec = JavaECPublicKeySpec(
				JavaECPoint(
					ecPubPoint.affineXCoord.toBigInteger(),
					ecPubPoint.affineYCoord.toBigInteger()
				),
				getECParameterSpec(curveOID)
			)
			val keyFactory = DefaultJcaJceHelper().createKeyFactory("EC")
			val pubKey = keyFactory.generatePublic(ecPubSpec)
			val ecPrivSpec = JavaECPrivateKeySpec(d, getECParameterSpec(curveOID))
			val privateKey = keyFactory.generatePrivate(ecPrivSpec)
			print("Pubkey: ")
			println(Hex.toHexString(pubKey.encoded))
			var outfile = FileOutputStream("pubkey.der")
			outfile.write(pubKey.encoded)
			outfile.close()
			print("Private key: ")
			println(Hex.toHexString(privateKey.encoded))
			outfile = FileOutputStream("privkey.der")
			outfile.write(privateKey.encoded)
			outfile.close()
		} else {
			println("Only EC private keys are supported as of now.")
		}
		println(key.keyID)
	} else {
		println("Invalid PGP file, or not a secret key")
	}
}
