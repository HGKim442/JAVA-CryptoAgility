import javax.crypto.KEM;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;

public class SunJceHybridProbe {
    static void append(ByteArrayOutputStream out, byte[] secret) {
        out.write((secret.length >>> 8) & 255);
        out.write(secret.length & 255);
        out.write(secret, 0, secret.length);
    }

    static byte[] deriveKey(byte[] ikm, byte[] salt)
            throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256", "SunJCE");

        // HKDF-Extract
        mac.init(new SecretKeySpec(salt, "HmacSHA256"));
        byte[] prk = mac.doFinal(ikm);

        // HKDF-Expand: 32-byte output
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        mac.update("D2-SUNJCE-HYBRID-TEST-V1"
            .getBytes(StandardCharsets.UTF_8));
        mac.update((byte) 1);
        byte[] key = mac.doFinal();

        Arrays.fill(prk, (byte) 0);
        return key;
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1 ||
            !(args[0].equals("HYBRID") ||
              args[0].equals("OMIT_KEM"))) {
            throw new IllegalArgumentException(
                "Usage: HYBRID or OMIT_KEM");
        }

        boolean includeKem = args[0].equals("HYBRID");

        // 1. X25519 shared secret
        KeyPairGenerator xgen =
            KeyPairGenerator.getInstance("X25519", "SunEC");

        KeyPair alice = xgen.generateKeyPair();
        KeyPair bob = xgen.generateKeyPair();

        KeyAgreement xa =
            KeyAgreement.getInstance("X25519", "SunEC");
        xa.init(alice.getPrivate());
        xa.doPhase(bob.getPublic(), true);
        byte[] x1 = xa.generateSecret();

        KeyAgreement xb =
            KeyAgreement.getInstance("X25519", "SunEC");
        xb.init(bob.getPrivate());
        xb.doPhase(alice.getPublic(), true);
        byte[] x2 = xb.generateSecret();

        boolean xMatch = MessageDigest.isEqual(x1, x2);

        // 2. ML-KEM-768 shared secret
        KeyPairGenerator kgen =
            KeyPairGenerator.getInstance("ML-KEM-768", "SunJCE");

        KeyPair pair = kgen.generateKeyPair();
        KEM kem = KEM.getInstance("ML-KEM-768", "SunJCE");

        KEM.Encapsulated wrapped =
            kem.newEncapsulator(pair.getPublic()).encapsulate();

        byte[] k1 = wrapped.key().getEncoded();
        byte[] k2 = kem.newDecapsulator(pair.getPrivate())
            .decapsulate(wrapped.encapsulation()).getEncoded();

        boolean kemMatch = MessageDigest.isEqual(k1, k2);

        if (!xMatch || !kemMatch ||
            x1.length != 32 || k1.length != 32) {
            throw new IllegalStateException(
                "Shared secret verification failed");
        }

        // 3. Policy-controlled KDF input
        ByteArrayOutputStream input =
            new ByteArrayOutputStream();

        append(input, x1);
        if (includeKem) {
            append(input, k1);
        }

        byte[] ikm = input.toByteArray();
        byte[] salt = new byte[32];
        new SecureRandom().nextBytes(salt);

        byte[] finalKey = deriveKey(ikm, salt);

        // 4. Application ground truth, not RVSec findings
        System.out.println("MODE=" + args[0]);
        System.out.println("JAVA=" + Runtime.version());
        System.out.println("X25519_PROVIDER=" +
            xgen.getProvider().getName());
        System.out.println("MLKEM_PROVIDER=" +
            kgen.getProvider().getName());
        System.out.println("KDF_PROVIDER=SunJCE");
        System.out.println("X25519_SECRET_MATCH=" + xMatch);
        System.out.println("MLKEM_SECRET_MATCH=" + kemMatch);
        System.out.println("KDF_INPUT_LENGTH=" + ikm.length);
        System.out.println("FINAL_KEY_LENGTH=" + finalKey.length);
        System.out.println("APP_MLKEM_USED_IN_KDF=" + includeKem);
        System.out.println("APP_POLICY_VIOLATION=" + !includeKem);
        System.out.println("APP_RESULT=PASS");

        Arrays.fill(x1, (byte) 0);
        Arrays.fill(x2, (byte) 0);
        Arrays.fill(k1, (byte) 0);
        Arrays.fill(k2, (byte) 0);
        Arrays.fill(ikm, (byte) 0);
        Arrays.fill(salt, (byte) 0);
        Arrays.fill(finalKey, (byte) 0);
    }
}
