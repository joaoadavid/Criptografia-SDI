package criptografia;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Scanner;
import java.math.BigInteger;

public class EncriptaDecriptaAES {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("Digite o texto a ser cifrado:");
        String texto = scanner.nextLine();

        System.out.println("Digite a chave (qualquer string):");
        String chaveString = scanner.nextLine();
        
        scanner.close();

        try {
            byte[] chave = gerarChave(chaveString);
            String chaveHex = bytesToHex(chave);
            System.out.println("Chave utilizada (em hexadecimal): " + chaveHex);
            byte[] textoCifrado = cifrarAES(texto, chave);
            System.out.println("Texto cifrado em bytes: " + Arrays.toString(textoCifrado));

            String textoDecifrado = decifrarAES(textoCifrado, chave);
            System.out.println("Texto decifrado: " + textoDecifrado);
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

    public static String decifrarAES(byte[] textoCifrado, byte[] chave) throws Exception {
        SecretKeySpec chaveAES = new SecretKeySpec(chave, "AES");
        Cipher decifrador = Cipher.getInstance("AES/ECB/PKCS5Padding");
        decifrador.init(Cipher.DECRYPT_MODE, chaveAES);
        return new String(decifrador.doFinal(textoCifrado));
    }

    public static byte[] gerarChave(String chaveString) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            byte[] chaveBytes = chaveString.getBytes("UTF-8");
            chaveBytes = sha.digest(chaveBytes);
            chaveBytes = Arrays.copyOf(chaveBytes, 16); // 16 bytes = 128 bits
            return chaveBytes;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String bytesToHex(byte[] bytes) {
        BigInteger bigInt = new BigInteger(1, bytes);
        return bigInt.toString(16);
    }
}
