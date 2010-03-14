/*
 * pgpry - PGP private key recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * file: genkeys.java
 * Generate private PGP keys in various formats
 */


import java.io.*;
import java.security.*;
import java.security.interfaces.*;
import java.util.*;
import javax.crypto.*;

import org.bouncycastle.bcpg.*;
import org.bouncycastle.jce.interfaces.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.*;
import org.bouncycastle.openpgp.*;


// Main class
public class genkeys
{
	// Some static parameters
	static String keyDir = "keys";
	static String identity = "John Q. Public <public@example.com>";
	static String[] keyTypes = {"RSA", "DSA"};
	static int[] keyLengths = {512, 1024, 2048, 4096};
	static int[] ciphers = {
		PGPEncryptedData.AES_128,
		PGPEncryptedData.AES_192,
		PGPEncryptedData.AES_256,
		PGPEncryptedData.BLOWFISH,
		PGPEncryptedData.CAST5,
		PGPEncryptedData.DES,
//		PGPEncryptedData.IDEA,
		PGPEncryptedData.NULL,
//		PGPEncryptedData.SAFER,
		PGPEncryptedData.TRIPLE_DES,
		PGPEncryptedData.TWOFISH
	};
	static String[] cipherNames = {
		"NULL", "IDEA", "TRIPLE_DES", "CAST5", "BLOWFISH",
		"SAFER", "DES", "AES_128", "AES_192", "AES_256", "TWOFISH"
	};
	static int[] hashAlgorithms = {
		HashAlgorithmTags.MD5,
		HashAlgorithmTags.SHA1,
//		HashAlgorithmTags.RIPEMD160,
//		HashAlgorithmTags.DOUBLE_SHA,
//		HashAlgorithmTags.MD2,
//		HashAlgorithmTags.TIGER_192,
//		HashAlgorithmTags.HAVAL_5_160,
//		HashAlgorithmTags.SHA256,
//		HashAlgorithmTags.SHA384,
//		HashAlgorithmTags.SHA512,
//		HashAlgorithmTags.SHA224
	};
	static String[] hashNames = {
		"", "MD5", "SHA1", "RIPEMD160", "DOUBLE_SHA", "MD2", "TIGER_192",
		"HAVAL_5_160", "SHA256", "SHA384", "SHA512", "SHA224"
	};


	// Generates a key pair
	private static KeyPair generatePair(String type, int length)
		throws NoSuchAlgorithmException, NoSuchProviderException
	{
		KeyPairGenerator kpg = KeyPairGenerator.getInstance(type, "BC");
		kpg.initialize(length);
		return kpg.generateKeyPair();
	}

	// Returns a cipher algorithm name
	private static String symmetricCipherName(int algorithm)
		throws PGPException
	{
		switch (algorithm) {
			case SymmetricKeyAlgorithmTags.NULL:
				return null;
			case SymmetricKeyAlgorithmTags.TRIPLE_DES:
				return "DESEDE";
			case SymmetricKeyAlgorithmTags.IDEA:
				return "IDEA";
			case SymmetricKeyAlgorithmTags.CAST5:
				return "CAST5";
			case SymmetricKeyAlgorithmTags.BLOWFISH:
				return "Blowfish";
			case SymmetricKeyAlgorithmTags.SAFER:
				return "SAFER";
			case SymmetricKeyAlgorithmTags.DES:
				return "DES";
			case SymmetricKeyAlgorithmTags.AES_128:
				return "AES";
			case SymmetricKeyAlgorithmTags.AES_192:
				return "AES";
			case SymmetricKeyAlgorithmTags.AES_256:
				return "AES";
			case SymmetricKeyAlgorithmTags.TWOFISH:
				return "Twofish";
			default:
				throw new PGPException("unknown symmetric algorithm: "+algorithm);
		}
	}

	// Constructs a cipher with the given code
	private static Cipher cipher(int code)
		throws NoSuchProviderException, PGPException 
	{
		String cName = symmetricCipherName(code);
		Cipher c = null;
		if (cName != null) {
			try {
				c = Cipher.getInstance(cName + "/CFB/NoPadding", "BC");
			} catch (NoSuchProviderException e) {
				throw e;
			} catch (Exception e) {
				throw new PGPException("Exception creating cipher", e);
			}
		}

		return c;
	}

	// Returns a public key packet for the given key
	private static PublicKeyPacket publicKeyPacket(PublicKey key, int algorithm, Date time)
		throws PGPException
	{
		BCPGKey bcpgKey;
		if (key instanceof RSAPublicKey) {
			RSAPublicKey rK = (RSAPublicKey)key;
			bcpgKey = new RSAPublicBCPGKey(rK.getModulus(), rK.getPublicExponent());
		} else if (key instanceof DSAPublicKey) {
			DSAPublicKey dK = (DSAPublicKey)key;
			DSAParams dP = dK.getParams();
			bcpgKey = new DSAPublicBCPGKey(dP.getP(), dP.getQ(), dP.getG(), dK.getY());
		} else if (key instanceof ElGamalPublicKey) {
			ElGamalPublicKey eK = (ElGamalPublicKey)key;
			ElGamalParameterSpec eS = eK.getParameters();
			bcpgKey = new ElGamalPublicBCPGKey(eS.getP(), eS.getG(), eK.getY());
		} else {
			throw new PGPException("unknown key class");
		}

		return new PublicKeyPacket(algorithm, time, bcpgKey);
	}

	// Returns the checksum of the given private key byte sequences
	private static byte[] checksum(boolean useSHA1, byte[] bytes, int length)
		throws PGPException
	{
		if (useSHA1) {
			try {
				MessageDigest dig = MessageDigest.getInstance("SHA1");
				dig.update(bytes, 0, length);
				return dig.digest();
			} catch (NoSuchAlgorithmException e) {
				throw new PGPException("Can't find SHA-1", e);
			}
		} else {
			int checksum = 0;
			for (int i = 0; i != length; i++) {
				checksum += bytes[i] & 0xff;
			}
			byte[] check = new byte[2];
			check[0] = (byte)(checksum >> 8);
			check[1] = (byte)checksum;
			return check;
		}
	}

	// Constructs a secret key packet using the given parameters
	private static SecretKeyPacket secretKeyPacket(KeyPair key, int cipher, boolean useSHA1, S2K s2k, String pass)
		throws NoSuchProviderException, PGPException 
	{
		int algorithm;
		if (key.getPrivate().getAlgorithm() == "RSA") {
			algorithm = PGPPublicKey.RSA_GENERAL;
		} else {
			algorithm = PGPPublicKey.DSA;
		}

		Date time = new Date();
		PGPKeyPair keyPair = new PGPKeyPair(algorithm, key.getPublic(),
			key.getPrivate(), time, "BC");

		PublicKeyPacket pubPk = publicKeyPacket(key.getPublic(), algorithm, time);
		BCPGObject secKey;
		switch (keyPair.getPublicKey().getAlgorithm()) {
			case PGPPublicKey.RSA_ENCRYPT:
			case PGPPublicKey.RSA_SIGN:
			case PGPPublicKey.RSA_GENERAL:
				RSAPrivateCrtKey rsK = (RSAPrivateCrtKey)keyPair.getPrivateKey().getKey();
				secKey = new RSASecretBCPGKey(rsK.getPrivateExponent(), rsK.getPrimeP(), rsK.getPrimeQ());
				break;
			case PGPPublicKey.DSA:
				DSAPrivateKey dsK = (DSAPrivateKey)keyPair.getPrivateKey().getKey();
				secKey = new DSASecretBCPGKey(dsK.getX());
				break;
			case PGPPublicKey.ELGAMAL_ENCRYPT:
			case PGPPublicKey.ELGAMAL_GENERAL:
				ElGamalPrivateKey esK = (ElGamalPrivateKey)keyPair.getPrivateKey().getKey();
				secKey = new ElGamalSecretBCPGKey(esK.getX());
				break;
			default:
				throw new PGPException("unknown key class");
		}

		Cipher c = cipher(cipher);

		SecretKeyPacket secPk;
		try {
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			BCPGOutputStream pOut = new BCPGOutputStream(bOut);

			pOut.writeObject(secKey);

			byte[] keyData = bOut.toByteArray();

			pOut.write(checksum(useSHA1, keyData, keyData.length));

			if (c != null) {
				SecretKey skey = PGPUtil.makeKeyFromPassPhrase(cipher, s2k, pass.toCharArray(), "BC");

				c.init(Cipher.ENCRYPT_MODE, skey, new SecureRandom());
				byte[] iv = c.getIV();
				byte[] encData = c.doFinal(bOut.toByteArray());

				if (useSHA1) {
					secPk = new SecretKeyPacket(pubPk, cipher, SecretKeyPacket.USAGE_SHA1, s2k, iv, encData);
				} else {
					secPk = new SecretKeyPacket(pubPk, cipher, SecretKeyPacket.USAGE_CHECKSUM, s2k, iv, encData);
				}
			} else {
				secPk = new SecretKeyPacket(pubPk, cipher, null, null, bOut.toByteArray());
			}
		} catch (PGPException e) {
			throw e;
		} catch (Exception e) {
			throw new PGPException("Exception encrypting key", e);
		}

		return secPk;
	}

	// Exports a secret key
	private static void exportSecretKey(OutputStream out, KeyPair key, int cipher, int s2kmode, int hashAlgorithm, boolean useSHA1, String pass, boolean armor)
		throws IOException, NoSuchProviderException, PGPException 
	{
		if (armor) {
			out = new ArmoredOutputStream(out);
		}

		SecureRandom rand = new SecureRandom();
		byte[] iv = new byte[8];
		rand.nextBytes(iv);
		S2K s2k = new S2K(hashAlgorithm, iv, 0x60);

		SecretKeyPacket packet = secretKeyPacket(key, cipher, useSHA1, s2k, pass);

		BCPGOutputStream bcOut;
		if (out instanceof BCPGOutputStream) {
			bcOut = (BCPGOutputStream)out;
		} else {
			bcOut = new BCPGOutputStream(out);
		}

		bcOut.writePacket(packet);

		if (armor) {
			out.close();
		}
	}

	// Generates an easy password
	public static String password(Random generator)
	{
		int length = generator.nextInt(2) + 1;
		String str = new String();
		for (int i = 0; i < length; i++) {
			str += new Integer(generator.nextInt(9)).toString();
		}
		return str;
	}

	// Program entry point
	public static void main(String[] args)
	{
		Security.addProvider(new BouncyCastleProvider());
		Random rand = new Random();

		for (String keyType : keyTypes) {
			System.out.print("Generating "+keyType+" keys... ");
			for (int keyLength : keyLengths) {

				if (keyType == "DSA" && keyLength > 1024) {
					continue;
				}

				System.out.print(keyLength);
				System.out.print(" ");

				KeyPair kp;
				try {
					kp = generatePair(keyType, keyLength);
				} catch (Exception e) {
					System.err.println("Error generating key: "+e.getMessage());
					continue;
				}

				for (int hash : hashAlgorithms) {
					String dir = String.format("%s/%s/%d/%s", keyDir, keyType, keyLength, hashNames[hash].toLowerCase());
					new File(dir).mkdirs();

					for (int cipher : ciphers) {
						boolean[] truthValues = {true, false};
						for (boolean useSHA1 : truthValues) {
							FileOutputStream out;
							boolean armor = rand.nextBoolean();
							try {
								out = new FileOutputStream(String.format("%s/%s%s.%s", dir, cipherNames[cipher].toLowerCase(), (useSHA1 ? "_sha1" : ""), (armor ? "asc" : "pgp")));
								exportSecretKey(out, kp, cipher, S2K.SALTED_AND_ITERATED, hash, useSHA1, password(rand), armor);
							} catch (Exception e) {
								System.err.println("Error exporting key: "+e.getMessage());
								e.printStackTrace();
							}
						}
					}
				}
			}
			System.out.println();
		}
	}
}
