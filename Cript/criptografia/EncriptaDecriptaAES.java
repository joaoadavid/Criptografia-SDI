package criptografia;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

public class EncriptaDecriptaAES {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("Digite o texto a ser cifrado:");
        String texto = scanner.nextLine();

        scanner.close();

        try {
   
            byte[] chave = gerarChaveAutomatica();
            String chaveBase64 = Base64.getEncoder().encodeToString(chave);
            System.out.println("Chave utilizada (em Base64): " + chaveBase64);

            byte[] textoCifrado = cifrarAES(texto, chave);
            System.out.println("Texto cifrado em bytes: " + Arrays.toString(textoCifrado));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static byte[] cifrarAES(String texto, byte[] chave) throws Exception {
        SecretKeySpec chaveAES = new SecretKeySpec(chave, "AES");
        Cipher cifrador = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cifrador.init(Cipher.ENCRYPT_MODE, chaveAES);
        return cifrador.doFinal(texto.getBytes());
    }

    public static byte[] gerarChaveAutomatica() throws NoSuchAlgorithmException {
        SecureRandom secureRandom = SecureRandom.getInstanceStrong();
        byte[] chave = new byte[16];
        secureRandom.nextBytes(chave);
        return chave;
    }
}
