import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;

/** Isolated deterministic PoC06/E2 fixture, NOT a production hybrid protocol or RVSec patch. */
public final class PolicyCutoverFixture {
    enum Policy { C1_HYBRID_ALLOWED, C2_PQC_REQUIRED }
    enum Model { SNAPSHOT, STRICT_CUTOVER }
    enum Variant { V0_VULNERABLE, V1_ALLOWLIST, V2_FINAL_POLICY }
    enum Suite { X25519_ONLY, X25519_MLKEM768 }

    record Config(String name, Policy begin, Policy end, Suite suite) {}
    record PolicyState(Policy policy, int epoch) {}
    record CryptoEvidence(Suite suite, boolean kemComplete, boolean aesRoundtrip) {}
    record WorkerResult(PolicyState snapshot, PolicyState finish, PolicyState effective,
                        CryptoEvidence crypto, String status, long observedAt,
                        long cryptoStartAt, long completedAt) {}
    record Result(Config config, Model model, Variant variant, WorkerResult result,
                  long changedAt, String expected, boolean match) {}

    private static final Provider BC = new BouncyCastleProvider();
    private static final SecureRandom RNG = new SecureRandom();
    private static final byte[] DOMAIN = "POC06-E2-TOY-COMBINER-v1".getBytes(StandardCharsets.US_ASCII);

    static byte[] frame(byte[]... parts) throws Exception {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(b);
        for (byte[] part : parts) { out.writeInt(part.length); out.write(part); }
        out.flush(); return b.toByteArray();
    }
    static byte[] mac(byte[] key, byte[] msg) throws Exception {
        Mac m = Mac.getInstance("HmacSHA256");
        m.init(new SecretKeySpec(key, "HmacSHA256"));
        return m.doFinal(msg);
    }
    static byte[] x25519() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519", "SunEC");
        KeyPair alice = kpg.generateKeyPair(), bob = kpg.generateKeyPair();
        KeyAgreement ka = KeyAgreement.getInstance("X25519", "SunEC");
        ka.init(alice.getPrivate()); ka.doPhase(bob.getPublic(), true);
        byte[] left = ka.generateSecret();
        ka.init(bob.getPrivate()); ka.doPhase(alice.getPublic(), true);
        byte[] right = ka.generateSecret();
        try {
            if (left.length != 32 || !MessageDigest.isEqual(left, right))
                throw new GeneralSecurityException("X25519 mismatch");
            return left;
        } finally { Arrays.fill(right, (byte)0); }
    }
    static byte[] mlkem() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", BC);
        kpg.initialize(MLKEMParameterSpec.ml_kem_768, RNG);
        KeyPair pair = kpg.generateKeyPair();
        KeyGenerator kg = KeyGenerator.getInstance("ML-KEM", BC);
        kg.init(new KEMGenerateSpec(pair.getPublic(), "AES", 256), RNG);
        SecretKeyWithEncapsulation encaps = (SecretKeyWithEncapsulation)kg.generateKey();
        byte[] left = encaps.getEncoded();
        byte[] ciphertext = encaps.getEncapsulation();
        kg.init(new KEMExtractSpec(pair.getPrivate(), ciphertext, "AES", 256));
        byte[] right = kg.generateKey().getEncoded();
        try {
            if (left.length != 32 || ciphertext.length != 1088 ||
                !MessageDigest.isEqual(left, right))
                throw new GeneralSecurityException("ML-KEM-768 mismatch");
            return left;
        } finally { Arrays.fill(right, (byte)0); }
    }
    static CryptoEvidence crypt(Suite suite) throws Exception {
        byte[] x = null, pq = null, ikm = null, salt = null, prk = null, aesKey = null;
        try {
            x = x25519();
            if (suite == Suite.X25519_MLKEM768) pq = mlkem();
            ikm = frame(x, pq == null ? new byte[0] : pq);
            salt = MessageDigest.getInstance("SHA-256").digest(DOMAIN);
            prk = mac(salt, ikm);
            aesKey = mac(prk, frame(DOMAIN, "AES-GCM".getBytes(StandardCharsets.US_ASCII)));
            byte[] nonce = new byte[12]; RNG.nextBytes(nonce);
            byte[] plaintext = "synthetic-poc06-record".getBytes(StandardCharsets.UTF_8);
            byte[] aad = "fixture-poc06-aad".getBytes(StandardCharsets.US_ASCII);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"),
                   new GCMParameterSpec(128, nonce));
            c.updateAAD(aad);
            byte[] ciphertext = c.doFinal(plaintext);
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"),
                   new GCMParameterSpec(128, nonce));
            c.updateAAD(aad);
            boolean ok = Arrays.equals(plaintext, c.doFinal(ciphertext));
            return new CryptoEvidence(suite, pq != null, ok);
        } finally {
            for (byte[] secret : new byte[][]{x, pq, ikm, salt, prk, aesKey})
                if (secret != null) Arrays.fill(secret, (byte)0);
        }
    }
    static boolean allowedComponent(Suite suite) {
        // Both components belong to the global allowlist; their *required combination*
        // under C2 is NOT represented by a component-only allowlist.
        return suite == Suite.X25519_ONLY || suite == Suite.X25519_MLKEM768;
    }
    static boolean compliant(Policy policy, CryptoEvidence evidence) {
        return evidence.aesRoundtrip && (policy != Policy.C2_PQC_REQUIRED ||
            (evidence.suite == Suite.X25519_MLKEM768 && evidence.kemComplete));
    }
    static String expected(Config c, Model model, Variant variant) {
        Policy effective = model == Model.SNAPSHOT ? c.begin : c.end;
        return variant == Variant.V2_FINAL_POLICY && effective == Policy.C2_PQC_REQUIRED &&
               c.suite == Suite.X25519_ONLY ? "REJECTED" : "SUCCESS";
    }
    static Result one(Config c, Model model, Variant variant) throws Exception {
        AtomicReference<PolicyState> policy = new AtomicReference<>(new PolicyState(c.begin, 1));
        CountDownLatch approved = new CountDownLatch(1);
        CountDownLatch resume = new CountDownLatch(1);
        ExecutorService pool = Executors.newSingleThreadExecutor();
        long changeAt;
        Future<WorkerResult> worker = pool.submit(() -> {
            PolicyState snapshot = policy.get();
            long observed = System.nanoTime();
            approved.countDown();
            if (!resume.await(10, TimeUnit.SECONDS)) throw new IllegalStateException("resume timeout");
            long cryptoStart = System.nanoTime();
            CryptoEvidence e = crypt(c.suite);
            PolicyState finish = policy.get();
            PolicyState effective = model == Model.SNAPSHOT ? snapshot : finish;
            // V0 executes without any crypto policy; V1 checks approved component names;
            // V2 additionally evaluates the entire final suite against the effective policy.
            boolean allow = e.aesRoundtrip && (variant == Variant.V0_VULNERABLE ||
                            (allowedComponent(e.suite) && (variant == Variant.V1_ALLOWLIST ||
                             compliant(effective.policy, e))));
            long completed = System.nanoTime();
            return new WorkerResult(snapshot, finish, effective, e,
                                    allow ? "SUCCESS" : "REJECTED", observed, cryptoStart, completed);
        });
        try {
            if (!approved.await(10, TimeUnit.SECONDS)) throw new IllegalStateException("policy check timeout");
            policy.set(new PolicyState(c.end, c.begin == c.end ? 1 : 2));
            changeAt = System.nanoTime();
            resume.countDown();
            WorkerResult r = worker.get(20, TimeUnit.SECONDS);
            String wanted = expected(c, model, variant);
            boolean ordered = r.observedAt <= changeAt && changeAt <= r.cryptoStartAt &&
                              r.cryptoStartAt <= r.completedAt;
            return new Result(c, model, variant, r, changeAt, wanted,
                              ordered && wanted.equals(r.status) && r.crypto.aesRoundtrip &&
                              r.snapshot.policy == c.begin && r.finish.policy == c.end);
        } finally { resume.countDown(); pool.shutdownNow(); }
    }
    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("expected: repetition integer");
        int rep = Integer.parseInt(args[0]);
        if (Security.getProvider("BC") == null) Security.addProvider(BC);
        List<Config> cases = List.of(
            new Config("BASE_C1_CLASSICAL", Policy.C1_HYBRID_ALLOWED, Policy.C1_HYBRID_ALLOWED, Suite.X25519_ONLY),
            new Config("BASE_C2_HYBRID", Policy.C2_PQC_REQUIRED, Policy.C2_PQC_REQUIRED, Suite.X25519_MLKEM768),
            new Config("UPGRADE_CLASSICAL", Policy.C1_HYBRID_ALLOWED, Policy.C2_PQC_REQUIRED, Suite.X25519_ONLY),
            new Config("UPGRADE_HYBRID", Policy.C1_HYBRID_ALLOWED, Policy.C2_PQC_REQUIRED, Suite.X25519_MLKEM768),
            new Config("RELAX_CLASSICAL", Policy.C2_PQC_REQUIRED, Policy.C1_HYBRID_ALLOWED, Suite.X25519_ONLY),
            new Config("RELAX_HYBRID", Policy.C2_PQC_REQUIRED, Policy.C1_HYBRID_ALLOWED, Suite.X25519_MLKEM768)
        );
        System.out.println("repeat,case,model,variant,policy_at_check,policy_at_finish,effective_policy,snapshot_epoch,finish_epoch,effective_epoch,actual_suite,kem_complete,aead_roundtrip,final_status,oracle_verdict,expected_status,expectation_match,ordering_ok");
        for (Config c : cases) for (Model m : Model.values()) for (Variant v : Variant.values()) {
            Result r = one(c, m, v);
            boolean ordered = r.result.observedAt <= r.changedAt && r.changedAt <= r.result.cryptoStartAt &&
                              r.result.cryptoStartAt <= r.result.completedAt;
            String oracle = r.result.status.equals("REJECTED") ? "REJECTED" :
                            (compliant(r.result.effective.policy, r.result.crypto) ? "COMPLIANT" : "VIOLATION");
            WorkerResult w = r.result;
            System.out.printf(Locale.ROOT, "%d,%s,%s,%s,%s,%s,%s,%d,%d,%d,%s,%s,%s,%s,%s,%s,%s,%s%n",
                rep,c.name,m,v,w.snapshot.policy,w.finish.policy,w.effective.policy,
                w.snapshot.epoch,w.finish.epoch,w.effective.epoch,w.crypto.suite,w.crypto.kemComplete,
                w.crypto.aesRoundtrip,w.status,oracle,r.expected,r.match,ordered);
            if (!r.match) throw new IllegalStateException("unexpected fixture result: "+c.name+"/"+m+"/"+v);
        }
    }
}
