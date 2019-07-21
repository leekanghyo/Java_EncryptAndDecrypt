package overload.encryptAndDecrypt;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;

public class CryptMain {
	
	public static void main(String[] args) throws NoSuchAlgorithmException, UnsupportedEncodingException {
		
		String plainString ="Overload";
		
		StringEncrypter stringEncrypter = new StringEncrypter(); 
		
		
		// unidirectional encryption : MD5, SHA-256
		String outputMD5 = stringEncrypter.md5(plainString);
		String outputSHA256 = stringEncrypter.sha256(plainString);
		
		System.out.println("plainString: " + plainString);
		System.out.println("MD5: " + outputMD5);
		System.out.println("sha256: " + outputSHA256);
	}
}
