package criptografia;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.Cipher;

public class EncriptaDecriptaRSA {

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);

        System.out.println("Digite o texto a ser criptografado:");
        String plaintext = scanner.nextLine();
        
        scanner.close();

        KeyPair keyPair = generateKeys();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        System.out.println("Chave pública: " + publicKeyToString(publicKey));
        System.out.println("Chave privada: " + privateKeyToString(privateKey));

        String ciphertext = encrypt(plaintext, publicKey);
        System.out.println("Texto criptografado: " + ciphertext);

        String decryptedText = decrypt(ciphertext, privateKey);
        System.out.println("Texto descriptografado: " + decryptedText);
    }

    public static KeyPair generateKeys() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); 
        return keyPairGenerator.generateKeyPair();
    }

    public static String publicKeyToString(RSAPublicKey publicKey) {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    public static String privateKeyToString(RSAPrivateKey privateKey) {
        return Base64.getEncoder().encodeToString(privateKey.getEncoded());
    }

    public static String encrypt(String plaintext, RSAPublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] plaintextBytes = plaintext.getBytes();
        byte[] ciphertextBytes = cipher.doFinal(plaintextBytes);
        return Base64.getEncoder().encodeToString(ciphertextBytes);
    }

    public static String decrypt(String ciphertext, RSAPrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] ciphertextBytes = Base64.getDecoder().decode(ciphertext);
        byte[] decryptedBytes = cipher.doFinal(ciphertextBytes);
        return new String(decryptedBytes);
    }
}

