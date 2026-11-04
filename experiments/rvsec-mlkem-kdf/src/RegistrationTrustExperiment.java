import java.security.*;
import java.util.*;
import javax.crypto.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.*;

/** Controlled application-registration spoofing demonstration.
 * Provider-reference guard is a local experimental oracle, not a trusted agent.
 */
public class RegistrationTrustExperiment {
    static final SecureRandom RNG = new SecureRandom();

    public static void main(String[] args) throws Exception {
        if (args.length != 3) throw new IllegalArgumentException(
            "Usage: HONEST|FORGED_REGISTRATION APPLICATION_REGISTRY|PROVIDER_REFERENCE ENFORCED|AUDIT_ONLY");
        String mode = args[0], guardSource = args[1], enforcement = args[2];
        if (!Arrays.asList("HONEST", "FORGED_REGISTRATION").contains(mode)
                || !Arrays.asList("APPLICATION_REGISTRY", "PROVIDER_REFERENCE").contains(guardSource)
                || !Arrays.asList("ENFORCED", "AUDIT_ONLY").contains(enforcement))
            throw new IllegalArgumentException("Invalid scenario arguments");
        Security.addProvider(new BouncyCastleProvider());

        // Real cryptographic agreement, independent of the application registry.
        KeyPairGenerator xgen = KeyPairGenerator.getInstance("X25519", "BC");
        KeyPair alice = xgen.generateKeyPair(), bob = xgen.generateKeyPair();
        byte[] xa = KdfBindingExperiment.agree(alice.getPrivate(), bob.getPublic());
        byte[] xb = KdfBindingExperiment.agree(bob.getPrivate(), alice.getPublic());
        boolean xMatch = xa.length == 32 && MessageDigest.isEqual(xa, xb);
        if (!xMatch) throw new IllegalStateException("X25519 mismatch");

        KeyPairGenerator kgen = KeyPairGenerator.getInstance("ML-KEM", "BC");
        kgen.initialize(MLKEMParameterSpec.ml_kem_768, RNG);
        KeyPair kemPair = kgen.generateKeyPair();
        KeyGenerator kem = KeyGenerator.getInstance("ML-KEM", "BC");
        kem.init(new KEMGenerateSpec(kemPair.getPublic(), "AES", 256), RNG);
        SecretKeyWithEncapsulation encap = (SecretKeyWithEncapsulation) kem.generateKey();
        byte[] ka = encap.getEncoded();
        byte[] ciphertext = encap.getEncapsulation().clone();
        kem.init(new KEMExtractSpec(kemPair.getPrivate(), ciphertext, "AES", 256));
        SecretKeyWithEncapsulation decap = (SecretKeyWithEncapsulation) kem.generateKey();
        byte[] kb = decap.getEncoded();
        boolean kemMatch = ka.length == 32 && kb.length == 32
            && ciphertext.length == 1088 && MessageDigest.isEqual(ka, kb);
        if (!kemMatch) throw new IllegalStateException("ML-KEM shared secret mismatch");

        // Simulated application-controlled registry. In FORGED mode, both its
        // registered expectation and the candidate are replaced coherently.
        byte[] forged = new byte[32];
        do { RNG.nextBytes(forged); } while (MessageDigest.isEqual(forged, ka));
        boolean forgedMode = mode.equals("FORGED_REGISTRATION");
        byte[] appRegisteredAlice = forgedMode ? forged.clone() : ka.clone();
        byte[] appRegisteredBob = forgedMode ? forged.clone() : kb.clone();
        byte[] candidateAlice = appRegisteredAlice.clone();
        byte[] candidateBob = appRegisteredBob.clone();

        boolean actualProviderBinding =
            MessageDigest.isEqual(candidateAlice, ka)
            && MessageDigest.isEqual(candidateBob, kb);
        KdfBindingExperiment.BindingGuard guard = guardSource.equals("APPLICATION_REGISTRY")
            ? new KdfBindingExperiment.BindingGuard(appRegisteredAlice, appRegisteredBob)
            : new KdfBindingExperiment.BindingGuard(ka, kb);
        boolean guardAllowed = guard.check(candidateAlice, candidateBob);
        boolean effectiveAccept = guardAllowed || enforcement.equals("AUDIT_ONLY");

        boolean keyConfirmation = false, recordRoundTrip = false;
        int recordCalls = 0;
        if (effectiveAccept) {
            byte[] transcript = KdfBindingExperiment.sha(KdfBindingExperiment.frame(
                KdfBindingExperiment.str("X25519-ML-KEM-768"),
                alice.getPublic().getEncoded(), bob.getPublic().getEncoded(),
                kemPair.getPublic().getEncoded(), ciphertext));
            KdfBindingExperiment.Session sa =
                KdfBindingExperiment.derive(xa, candidateAlice, transcript);
            KdfBindingExperiment.Session sb =
                KdfBindingExperiment.derive(xb, candidateBob, transcript);
            keyConfirmation = MessageDigest.isEqual(
                KdfBindingExperiment.hmac(sa.confirm,
                    KdfBindingExperiment.str("D2-12-KEY-CONFIRM")),
                KdfBindingExperiment.hmac(sb.confirm,
                    KdfBindingExperiment.str("D2-12-KEY-CONFIRM")));
            if (keyConfirmation) {
                recordCalls++;
                recordRoundTrip = KdfBindingExperiment.record(sa, sb);
            }
            sa.clear(); sb.clear();
            Arrays.fill(transcript, (byte) 0);
        }

        boolean expectedBinding = !forgedMode;
        boolean expectedGuardAllow = !forgedMode
            || guardSource.equals("APPLICATION_REGISTRY");
        boolean expectedAccept = expectedGuardAllow || enforcement.equals("AUDIT_ONLY");
        boolean expectedMissingBindingAccepted = forgedMode && expectedAccept;
        boolean missingBindingAccepted = !actualProviderBinding && recordCalls > 0;
        boolean valid = xMatch && kemMatch && actualProviderBinding == expectedBinding
            && guardAllowed == expectedGuardAllow
            && effectiveAccept == expectedAccept
            && keyConfirmation == expectedAccept
            && recordRoundTrip == expectedAccept
            && recordCalls == (expectedAccept ? 1 : 0)
            && missingBindingAccepted == expectedMissingBindingAccepted;

        System.out.println("MODE=" + mode);
        System.out.println("GUARD_SOURCE=" + guardSource);
        System.out.println("ENFORCEMENT=" + enforcement);
        System.out.println("POLICY=PQC_REQUIRED");
        System.out.println("X25519_MATCH=" + xMatch);
        System.out.println("MLKEM_SHARED_MATCH=" + kemMatch);
        System.out.println("KEM_CIPHERTEXT_BYTES=" + ciphertext.length);
        System.out.println("APP_REGISTERED_MATCHES_PROVIDER=" + actualProviderBinding);
        System.out.println("GUARD_DECISION=" + (guardAllowed ? "ALLOW" : "DENY"));
        System.out.println("EFFECTIVE_ACCEPT=" + effectiveAccept);
        System.out.println("KEY_CONFIRMATION=" + keyConfirmation);
        System.out.println("RECORD_CALLS=" + recordCalls);
        System.out.println("RECORD_ROUNDTRIP=" + recordRoundTrip);
        System.out.println("UNBOUND_SECRET_USED=" + missingBindingAccepted);
        System.out.println("RESULT=" + (valid ? "PASS" : "FAIL"));

        guard.clear();
        for (byte[] secret : new byte[][]{xa, xb, ka, kb, forged,
                appRegisteredAlice, appRegisteredBob, candidateAlice, candidateBob})
            Arrays.fill(secret, (byte) 0);
        if (!valid) throw new IllegalStateException("Controlled expectation failed");
    }
}
