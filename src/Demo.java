import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
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
		
	}
	public static void main(String[] args) {
		
		Security.addProvider(new BouncyCastleProvider());
		ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("secp521r1");
		
		try {
			KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "BC");;
			g.initialize(ecGenSpec, new SecureRandom());
			
			KeyPair KeyPair = g.generateKeyPair();
			
			KeyFactory fact = KeyFactory.getInstance("EC", "BC");
			ECPublicKey PublicKey = (ECPublicKey) fact.generatePublic(new X509EncodedKeySpec(KeyPair.getPublic().getEncoded()));
			ECPrivateKey PrivateKey = (ECPrivateKey) fact.generatePrivate(new PKCS8EncodedKeySpec(KeyPair.getPrivate().getEncoded()));
			
			System.out.println("Public key:\n" + new String(Base64.encode(PublicKey.getEncoded())));
			System.out.println("Private Key:\n" + new String(Base64.encode(PrivateKey.getEncoded())));
			
			String TestData = "Test String 123";
			
			Signature ecdsaSign = Signature.getInstance("SHA512withECDSA","BC");
			ecdsaSign.initSign(PrivateKey);
			ecdsaSign.update(TestData.getBytes("UTF-8"));
			byte[] signatureA = ecdsaSign.sign();
			byte[] signatureB = ecdsaSign.sign();
			
			System.out.println("SignatureA:\n" + new String(Base64.encode(signatureA)));
			System.out.println("SignatureB:\n" + new String(Base64.encode(signatureB)));
			
			Signature ecdsaVerify = Signature.getInstance("SHA512withECDSA", "BC");
			ecdsaVerify.initVerify(PublicKey);
			ecdsaVerify.update(TestData.getBytes("UTF-8"));
			boolean resultA = ecdsaVerify.verify(signatureA);
			boolean resultB = ecdsaVerify.verify(signatureB);
			
			System.out.println("SignatureA verify result: " + resultA);
			System.out.println("SignatureB verify result: " + resultB);
			
			Cipher EncryptCipher = Cipher.getInstance("ECIES","BC");
			Cipher DecryptCipher = Cipher.getInstance("ECIES","BC");
			
			EncryptCipher.init(Cipher.ENCRYPT_MODE, PublicKey);
			byte[] Encrypt = EncryptCipher.doFinal(TestData.getBytes("UTF-8"), 0, TestData.getBytes("UTF-8").length);
			
			System.out.println(new String(Base64.encode(Encrypt)));
			
			DecryptCipher.init(Cipher.DECRYPT_MODE, PrivateKey);
			
			byte[] Decrypt = DecryptCipher.doFinal(Encrypt, 0, Encrypt.length);
			
			System.out.println(new String(Decrypt));
			
			KeyAgreement KeyAgreeA = KeyAgreement.getInstance("ECDH", "BC");
			KeyAgreement KeyAgreeB = KeyAgreement.getInstance("ECDH", "BC");
			KeyPair SomeoneKeyPair = g.generateKeyPair();
			
			KeyAgreeA.init(KeyPair.getPrivate());
		    KeyAgreeB.init(SomeoneKeyPair.getPrivate());
		    
		    KeyAgreeA.doPhase(SomeoneKeyPair.getPublic(), true);
		    KeyAgreeB.doPhase(KeyPair.getPublic(), true);

		    byte[] SessionKeyA = KeyAgreeA.generateSecret();
		    byte[] SessionKeyB = KeyAgreeB.generateSecret();
		    
		    System.out.println(new String(Base64.encode(SessionKeyA)));
		    System.out.println(new String(Base64.encode(SessionKeyB)));
			
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (NoSuchProviderException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	

	}
	

}
