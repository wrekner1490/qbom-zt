import java.security.*;
import javax.crypto.*;

public class AuthService {
    public KeyPair genRsa() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    public byte[] hashToken(byte[] token) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA1");
        return md.digest(token);
    }

    public Cipher legacyCipher() throws Exception {
        return Cipher.getInstance("DES/ECB/PKCS5Padding");
    }
}
