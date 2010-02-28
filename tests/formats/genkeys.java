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
import java.util.Date;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
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

	// Generates a key pair
	private static KeyPair generatePair(String type, int length)
		throws NoSuchAlgorithmException, NoSuchProviderException
	{
		KeyPairGenerator kpg = KeyPairGenerator.getInstance(type, "BC");
		kpg.initialize(length);
		return kpg.generateKeyPair();
	}

	// Exports a secret key
	private static void exportSecretKey(OutputStream out, KeyPair key, int cipher, String pass, boolean armor)
		throws IOException, NoSuchProviderException, PGPException 
	{
		if (armor) {
			out = new ArmoredOutputStream(out);
		}

		// TODO: Use constructor with SecretKeyPacket in order to constrol
		// the string-2-key parameters
		PGPSecretKey pgpkey = new PGPSecretKey(
			PGPSignature.DEFAULT_CERTIFICATION,
			PGPPublicKey.RSA_GENERAL,
			key.getPublic(), key.getPrivate(),
			new Date(), identity,
			cipher, pass.toCharArray(),
			null, null, new SecureRandom(), "BC");

		pgpkey.encode(out);
		out.close();
	}

	// Program entry point
	public static void main(String[] args)
	{
		Security.addProvider(new BouncyCastleProvider());

		for (String keyType : keyTypes) {
			System.out.print("Generating "+keyType+" keys... ");
			for (int keyLength : keyLengths) {
				System.out.print(keyLength);
				System.out.print(" ");

				String dir = String.format("%s/%s/%d", keyDir, keyType, keyLength);
				new File(dir).mkdirs();

				try {
					KeyPair kp = generatePair("RSA", 1024);
					for (int cipher : ciphers) {
						FileOutputStream out = new FileOutputStream(String.format("%s/%s.asc", dir, cipherNames[cipher].toLowerCase()));
						try {
							exportSecretKey(out, kp, cipher, "1234", true);
						} catch (Exception e) {
							System.err.println("Error exporting key: "+e.getMessage());
						}
					}
				} catch (Exception e) {
					System.err.println("Error generating key: "+e.getMessage());
				}
			}
			System.out.println();
		}	
	}
}
