import java.security.*;
import javax.crypto.*;

public class AuthService {
    public KeyPair genRsa() throws Exception {
        // Migrated off RSA: a bigger key would still be Shor-breakable (BouncyCastle-PQC provider)
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA");
        return kpg.generateKeyPair();
    }

    public byte[] hashToken(byte[] token) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(token);
    }

    public Cipher legacyCipher() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }
}
