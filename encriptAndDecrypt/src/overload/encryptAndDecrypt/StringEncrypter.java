package overload.encryptAndDecrypt;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class StringEncrypter {
	
	public StringEncrypter() {
	}

	/**
	 * MD5 Encrypt
	 * 
	 * @param String
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws UnsupportedEncodingException
	 */
	public String md5(String plainString) throws NoSuchAlgorithmException, UnsupportedEncodingException {

		MessageDigest md = MessageDigest.getInstance("MD5");
		md.update(plainString.getBytes("UTF-8")); // 받아온 문자열로 해시값 갱신

		byte[] byteData = md.digest(); // 해시값 획득

		return byteToHexString(byteData);
	}

	/**
	 * SHA-256 Encrypt
	 * 
	 * @param plainString
	 * @return String
	 * @throws NoSuchAlgorithmException
	 * @throws UnsupportedEncodingException
	 */
	public String sha256(String plainString) throws NoSuchAlgorithmException, UnsupportedEncodingException {

		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(plainString.getBytes("UTF-8")); // 받아온 문자열로 해시값 갱신

		byte[] byteData = md.digest(); // 해시값 획득

		return byteToHexString(byteData);
	}

	/**
	 * Convert byte[] to hex String
	 * 
	 * @param byteData
	 * @return String
	 * @throws NoSuchAlgorithmException
	 * @throws UnsupportedEncodingException
	 */
	private String byteToHexString(byte[] byteData) {
		// Hex String으로 변환
		StringBuilder sb = new StringBuilder();
		for (byte b : byteData) {
			/*
			 * b & 0xff : 8비트인 byte를 32비트의 int형으로 강제 형 변환 할 때, 2의 보수법 처리로 값이 변하는것을 방지
			 * 0x100 : 변환된 16진수를 동일하게 2자릿수로 맞춰주기위해 결과값 자릿수를 강제로 3자리로 만든다.(String으로 담을 때 맨 앞자리만 삭제하여 받는다.)
			 * 
			 * 예시 및 과정
			 * 
			 * (byte)235 = 11101011
			 * 
			 * step1: int형으로 강제 형변환
			 * 		(byte)235 & 0xff
			 * 
			 * step2: +0x100 16진수의 자릿수를 2자리로 통일한다.
			 * 		235(10) = eb(16) -> 1eb(16)
			 * 		만약 값이 15(10)일경우 step2에 의해 10f로 반환
			 * 
			 * step3: substring 메서드로 첫번째 자리값을 삭제 1eb -> eb 10f -> 0f
			 */

			sb.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
		}

		return sb.toString();
	}
	
	/**
	 * AES 256 으로 암호화 한다.
	 * @param msg
	 * @param key
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidParameterSpecException
	 * @throws UnsupportedEncodingException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public static String encryptAES256(String msg, String key) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidParameterSpecException, UnsupportedEncodingException, BadPaddingException, IllegalBlockSizeException {
		SecureRandom random = new SecureRandom();
		byte bytes[] = new byte[20];
		random.nextBytes(bytes);
		byte[] saltBytes = bytes;
		
		// Password-Based Key Derivation function 2
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		// 70000踰� �빐�떆�븯�뿬 256 bit 湲몄씠�쓽 �궎瑜� 留뚮뱺�떎.
		PBEKeySpec spec = new PBEKeySpec(key.toCharArray(), saltBytes, 40000, 256);
		
		SecretKey secretKey = factory.generateSecret(spec);
		SecretKeySpec secret = new SecretKeySpec(secretKey.getEncoded(), "AES");
		
		// CBC : Cipher Block Chaining Mode
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); // 알고리즘/모드/패딩
		cipher.init(Cipher.ENCRYPT_MODE, secret);
		AlgorithmParameters params = cipher.getParameters();
		// Initial Vector(1단계 암호화 블록용)
		byte[] ivBytes = params.getParameterSpec(IvParameterSpec.class).getIV();
		
		byte[] encryptedTextBytes = cipher.doFinal(msg.getBytes("UTF-8"));
		
		byte[] buffer = new byte[saltBytes.length + ivBytes.length + encryptedTextBytes.length];
		System.arraycopy(saltBytes, 0, buffer, 0, saltBytes.length);
        System.arraycopy(ivBytes, 0, buffer, saltBytes.length, ivBytes.length);
	    System.arraycopy(encryptedTextBytes, 0, buffer, saltBytes.length + ivBytes.length, encryptedTextBytes.length);
	    
		return Base64.getEncoder().encodeToString(buffer);
	}
	
	/**
	 * 위에서 암호화된 내용을 복호화 한다.
	 * @param msg
	 * @param key
	 * @return
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public static String decryptAES256(String msg, String key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		ByteBuffer buffer = ByteBuffer.wrap(Base64.getDecoder().decode(msg));
		
		byte[] saltBytes = new byte[20];
		buffer.get(saltBytes, 0, saltBytes.length);
		byte[] ivBytes = new byte[cipher.getBlockSize()];
		buffer.get(ivBytes, 0, ivBytes.length);
		byte[] encryoptedTextBytes = new byte[buffer.capacity() - saltBytes.length - ivBytes.length];
		buffer.get(encryoptedTextBytes);
		
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		PBEKeySpec spec = new PBEKeySpec(key.toCharArray(), saltBytes, 40000, 256);
		
		SecretKey secretKey = factory.generateSecret(spec);
		SecretKeySpec secret = new SecretKeySpec(secretKey.getEncoded(), "AES");
		
		cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(ivBytes));
		
		byte[] decryptedTextBytes = cipher.doFinal(encryoptedTextBytes);
		return new String(decryptedTextBytes);
	}

}
