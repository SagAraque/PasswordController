package com.keyvault;
import org.jetbrains.annotations.NotNull;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

/**
 * @author Sergio Araque
 * @version 1.1
 */
public class PasswordController {
    private String key_algorithm;
    private int key_length, iteration;
    private String cipher_list;
    private String token;

    /**
     * Constructor that by default set PBKDF2WithHmacSHA256 as Key algorithm,
     * Cipher transformation list as AES/CBC/PKCS5Padding,
     * 256 as key length
     * and 100000 iterations
     * @param tokenText Secret server token
     */
    public PasswordController(@NotNull String tokenText) {
        key_algorithm = "PBKDF2WithHmacSHA256";
        key_length = 256;
        iteration = 100000;
        cipher_list = "AES/CBC/PKCS5Padding";
        token = tokenText;
    }

    /**
     * Constructor that by default set PBKDF2WithHmacSHA256 as Key algorithm,
     * Cipher transformation list as AES/CBC/PKCS5Padding,
     * 256 as key length
     * and 100000 iterations
     */
    public PasswordController() {
        key_algorithm = "PBKDF2WithHmacSHA256";
        key_length = 256;
        iteration = 100000;
        cipher_list = "AES/CBC/PKCS5Padding";
        token = "A default token, maybe you should provide a more secure one.";
    }

    /**
     * Constructor that takes Key algorithm, Cipher transformation list, Key length and Iteration count
     *
     * @param keyAlgorithm Key algorithm to use during key generation
     * @param cipherList Cipher transformation list
     * @param keyLength The length of the key that we need to derive
     * @param iterationCount Number of iterations that algorithm should take
     * @param tokenText Secret server token
     */
    public PasswordController(@NotNull String keyAlgorithm, @NotNull String cipherList,  int keyLength, int iterationCount, @NotNull String tokenText) throws NoSuchPaddingException, NoSuchAlgorithmException {
        key_algorithm = keyAlgorithm;
        key_length = keyLength;
        iteration = iterationCount;
        cipher_list = cipherList;
        token = tokenText;
    }

    /**
     * Constructor that takes Key algorithm and Cipher transformation list
     *
     * @param keyAlgorithm Key algorithm to use during key generation.
     * @param cipherList Cipher transformation list
     * @param tokenText Secret server token
     */
    public PasswordController(@NotNull String keyAlgorithm, @NotNull String cipherList, @NotNull String tokenText) throws NoSuchPaddingException, NoSuchAlgorithmException {
        key_algorithm = keyAlgorithm;
        cipher_list = cipherList;
        token = tokenText;
    }

    /**
     * Constructor that takes Key length and Iteration count
     *
     * @param keyLength The length of the key that we need to derive
     * @param iterationCount Number of iterations that algorithm should take
     * @param tokenText Secret server token
     */
    public PasswordController(int keyLength, int iterationCount, @NotNull String tokenText){
        key_length = keyLength;
        iteration = iterationCount;
        token = tokenText;
    }

    /**
     * Set token value
     * @param token New token value
     */
    public void setToken(String token){
        this.token = token;
    }

    /**
     * Encrypt a raw password using the provided salt value.
     * if they are not specified on the constructor, this function use PBKDF2WithHmacSHA256 to generate a secret key
     * and encrypt the raw password with AES/CBC/PKCS5Padding algorithm and the secret key
     *
     * @param toEncrypt Raw password
     * @param salt Salt value
     * @return Encrypted password with IvParameters in format IvParameter:Password
     * @throws Exception
     */
    public String encrypt(@NotNull String toEncrypt, @NotNull String salt) throws Exception {
        Cipher cipher = Cipher.getInstance(cipher_list);
        cipher.init(Cipher.ENCRYPT_MODE, generateKey(salt));

        byte[] iVParam = cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();
        byte[] encryptedPassword = cipher.doFinal(toEncrypt.getBytes(StandardCharsets.UTF_8));

        return encode(iVParam) + ":" + encode(encryptedPassword);
    }

    /**
     * Decrypt password using the provided salt value
     *
     * @param encryptedPassword Encrypted password
     * @param salt Salt value
     * @return Decrypted password
     * @throws Exception
     */
    public String decrypt(@NotNull String encryptedPassword, @NotNull String salt) throws Exception{
        String[] parts = encryptedPassword.split(":");
        String iv = parts[0];
        String password = parts[1];


        Cipher cipher = Cipher.getInstance(cipher_list);
        cipher.init(Cipher.DECRYPT_MODE, generateKey(salt), new IvParameterSpec(decode(iv)));

        return new String(cipher.doFinal(decode(password)), StandardCharsets.UTF_8);
    }

    /**
     * Generate random 256 bytes salt value using SHA1PRNG algorithm
     *
     * @return Salt value encoded in Base64
     * @throws NoSuchAlgorithmException
     */
    public String getSalt() throws NoSuchAlgorithmException {
        SecureRandom sr = SecureRandom.getInstance("DRBG");
        byte[] bytes = sr.generateSeed(64);
        sr.nextBytes(bytes);

        return encode(bytes);
    }

    /**
     * Convert de provided data in a hash using SHA-512
     * @param data Data to be hashed
     * @return SHA-512 hash
     * @throws NoSuchAlgorithmException
     */
    public String hashData(String data) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        return encode(digest.digest(data.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * Generate a secret key using the provided salt value
     *
     * @param salt Salt value
     * @return Secret key
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     */
    private SecretKeySpec generateKey(@NotNull String salt) throws InvalidKeySpecException, NoSuchAlgorithmException {
        SecretKeyFactory skf = SecretKeyFactory.getInstance(key_algorithm);
        PBEKeySpec spec = new PBEKeySpec(token.toCharArray(), salt.getBytes(), iteration, key_length);
        SecretKey secretKey = skf.generateSecret(spec);

        return new SecretKeySpec(secretKey.getEncoded(), "AES");
    }

    private String encode(byte[] bytes){
        return Base64.getEncoder().encodeToString(bytes);
    }

    private byte[] decode(@NotNull String property){
        return Base64.getDecoder().decode(property);
    }
}
