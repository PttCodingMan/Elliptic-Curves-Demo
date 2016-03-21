import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

public class Demo {

	
	static {
		//Security.insertProviderAt(new org.bouncycastle.jce.provider.BouncyCastleProvider(), 1);
		Security.addProvider(new BouncyCastleProvider());
	}
	public static void main(String[] args) {
		
		ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("P-256");
		
		try {
			KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "BC");;
			g.initialize(ecGenSpec, new SecureRandom());
			
			KeyPair KeyPair = g.generateKeyPair();
			
			KeyFactory fact = KeyFactory.getInstance("EC", "BC");
			
			ECPublicKey PublicKey = (ECPublicKey) fact.generatePublic(new X509EncodedKeySpec(KeyPair.getPublic().getEncoded()));
			ECPrivateKey PrivateKey = (ECPrivateKey) fact.generatePrivate(new PKCS8EncodedKeySpec(KeyPair.getPrivate().getEncoded()));
			
			System.out.println("1. Generate Key Pair");
			System.out.println("Public key:\n" + new String(Base64.encode(PublicKey.getEncoded())));
			System.out.println("Private Key:\n" + new String(Base64.encode(PrivateKey.getEncoded())));
			
			String TestData = "Test String 123";
			
			Signature ecdsaSign = Signature.getInstance("SHA512withECDSA","BC");
			ecdsaSign.initSign(PrivateKey);
			ecdsaSign.update(TestData.getBytes("UTF-8"));
			byte[] signatureA = ecdsaSign.sign();
			byte[] signatureB = ecdsaSign.sign();
			
			System.out.println("2. Sign");
			System.out.println("SignatureA:\n" + new String(Base64.encode(signatureA)));
			System.out.println("SignatureB:\n" + new String(Base64.encode(signatureB)));
			
			Signature ecdsaVerify = Signature.getInstance("SHA512withECDSA", "BC");
			ecdsaVerify.initVerify(PublicKey);
			ecdsaVerify.update(TestData.getBytes("UTF-8"));
			boolean resultA = ecdsaVerify.verify(signatureA);
			boolean resultB = ecdsaVerify.verify(signatureB);
			
			System.out.println("3. Verify signature");
			System.out.println("SignatureA verify result: " + resultA);
			System.out.println("SignatureB verify result: " + resultB);
			
			Cipher EncryptCipher = Cipher.getInstance("ECIES","BC");
			Cipher DecryptCipher = Cipher.getInstance("ECIES","BC");
			
			EncryptCipher.init(Cipher.ENCRYPT_MODE, PublicKey);
			byte[] Encrypt = EncryptCipher.doFinal(TestData.getBytes("UTF-8"), 0, TestData.getBytes("UTF-8").length);
			
			System.out.println("4. Encrypt");
			System.out.println("Input data: " + TestData);

			System.out.println("Encrypt result: " + new String(Base64.encode(Encrypt)));
			
			DecryptCipher.init(Cipher.DECRYPT_MODE, PrivateKey);
			
			byte[] Decrypt = DecryptCipher.doFinal(Encrypt, 0, Encrypt.length);
			
			System.out.println("5. Decrypt");
			System.out.println("Decrypt result: " + new String(Decrypt));
			
			KeyAgreement KeyAgreeA = KeyAgreement.getInstance("ECDH", "BC");
			KeyAgreement KeyAgreeB = KeyAgreement.getInstance("ECDH", "BC");
			KeyPair SomeoneKeyPair = g.generateKeyPair();
			
			KeyAgreeA.init(KeyPair.getPrivate());
		    KeyAgreeA.doPhase(SomeoneKeyPair.getPublic(), true);
		    
		    KeyAgreeB.init(SomeoneKeyPair.getPrivate());
		    KeyAgreeB.doPhase(KeyPair.getPublic(), true);
		    
		    byte[] SessionKeyA = KeyAgreeA.generateSecret();
		    byte[] SessionKeyB = KeyAgreeB.generateSecret();
		    
		    System.out.println("6. KeyAgreement");
		    System.out.println("KeyAgreement A: " + new String(Base64.encode(SessionKeyA)));
		    System.out.println("KeyAgreement B: " + new String(Base64.encode(SessionKeyB)));
			
		    System.out.println("\nDemo finish");
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		} catch (NoSuchProviderException e1) {
			e1.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
	

	}
	

}
