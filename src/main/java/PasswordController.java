import org.jetbrains.annotations.NotNull;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * @author Sergio Araque
 * @version 1.0
 */
public class PasswordController {
    private String key_algorithm, cipher_list;
    private int key_length, iteration;
    private static final String TOKEN = "RANDOM TOKEN";

    /**
     * Constructor that by default set PBKDF2WithHmacSHA512 as Key algorithm,
     * Cipher transformation list as AES/CBC/PKCS5Padding,
     * 128 as key length
     * and 40000 iterations
     */
    public PasswordController(){
        key_algorithm = "PBKDF2WithHmacSHA512";
        key_length = 256;
        iteration = 40000;
        cipher_list = "AES/CBC/PKCS5Padding";
    }

    /**
     * Constructor that takes Key algorithm, Cipher transformation list, Key length and Iteration count
     *
     * @param keyAlgorithm Key algorithm to use during key generation
     * @param cipherList Cipher transformation list
     * @param keyLength The length of the key that we need to derive
     * @param iterationCount Number of iterations that algorithm should take
     */
    public PasswordController(@NotNull String keyAlgorithm, @NotNull String cipherList, int keyLength, int iterationCount){
        key_algorithm = keyAlgorithm;
        key_length = keyLength;
        iteration = iterationCount;
        cipher_list = cipherList;
    }

    /**
     * Constructor that takes Key algorithm and Cipher transformation list
     *
     * @param keyAlgorithm Key algorithm to use during key generation.
     * @param cipherList Cipher transformation list
     */
    public PasswordController(@NotNull String keyAlgorithm, @NotNull String cipherList){
        key_algorithm = keyAlgorithm;
        cipher_list = cipherList;
    }

    /**
     * Constructor that takes Key length and Iteration count
     *
     * @param keyLength The length of the key that we need to derive
     * @param iterationCount Number of iterations that algorithm should take
     */
    public PasswordController(int keyLength, int iterationCount){
        key_length = keyLength;
        iteration = iterationCount;
    }

    /**
     * Encrypt a raw password using the provided salt value.
     * if they are not specified on the constructor, this function use PBKDF2WithHmacSHA512 to generate a secret key
     * and encrypt the raw password with AES/CBC/PKCS5Padding algorithm and the secret key
     *
     * @param password Raw password
     * @param salt Salt value
     * @return Encrypted password with IvParameters in format IvParameter:Password
     * @throws Exception
     */
    public String encrypt(@NotNull String password, @NotNull String salt) throws Exception {
        Cipher cipher = Cipher.getInstance(cipher_list);
        cipher.init(Cipher.ENCRYPT_MODE, generateKey(salt));

        byte[] iVParam = cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();
        byte[] encryptedPassword = cipher.doFinal(password.getBytes(StandardCharsets.UTF_8));

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
        String iv = encryptedPassword.split(":")[0];
        String password = encryptedPassword.split(":")[1];

        Cipher cipher = Cipher.getInstance(cipher_list);
        cipher.init(Cipher.DECRYPT_MODE, generateKey(salt), new IvParameterSpec(decode(iv)));

        return new String(cipher.doFinal(decode(password)));
    }

    /**
     * Generate random 256 bytes salt value using SHA1PRNG algorithm
     *
     * @return Salt value encoded in Base64
     * @throws NoSuchAlgorithmException
     */
    public String getSalt() throws NoSuchAlgorithmException {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        byte[] bytes = new byte[256];
        sr.nextBytes(bytes);

        return encode(bytes);
    }

    /**
     * Generate a secret key using the provided salt value
     *
     * @param salt Salt value
     * @return Secret key
     * @throws Exception
     */
    private SecretKeySpec generateKey(@NotNull String salt) throws Exception{
        SecretKeyFactory skf = SecretKeyFactory.getInstance(key_algorithm);
        PBEKeySpec spec = new PBEKeySpec(TOKEN.toCharArray(), salt.getBytes(), iteration, key_length);
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
