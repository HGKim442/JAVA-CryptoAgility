import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.*;

/** Synthetic PoC03 + PoC06 + E2 controlled experiment; NOT a standardized hybrid protocol. */
public final class FallbackCutoverFixture {
    enum Policy { C1_HYBRID_ALLOWED, C2_PQC_REQUIRED }
    enum Model { SNAPSHOT, STRICT_CUTOVER }
    enum Variant { V0_VULNERABLE, V1_ALLOWLIST, V2_FINAL_POLICY }
    enum Failure { NONE, BC_UNREGISTERED, SUNEC_PINNED }
    enum Fallback { CLASSICAL, NONE }
    enum Suite { NONE, X25519_ONLY, X25519_MLKEM768 }
    record PolicyState(Policy policy, int epoch) {}
    record Config(String id, Policy begin, Policy end, Failure failure, Fallback fallback) {}
    record CryptoEvidence(Suite actualSuite, boolean kemComplete, boolean fallbackTaken,
                          boolean aeadRoundtrip, String providerAttempted, String failureType) {}
    record Worker(PolicyState check, PolicyState finish, PolicyState effective,
                  CryptoEvidence crypto, String finalStatus, long checkedAt,
                  long cryptoStartedAt, long finishedAt, long elapsedNs) {}
    record Result(Config c, Model model, Variant variant, Worker worker,
                  long policyUpdatedAt, boolean orderOK) {}

    private static final Provider BC = new BouncyCastleProvider();
    private static final Provider EC = Security.getProvider("SunEC");
    private static final SecureRandom RNG = new SecureRandom();
    private static final byte[] DOMAIN = "POC03-06-E2-SYNTHETIC-KDF-v1".getBytes(StandardCharsets.US_ASCII);

    static byte[] frame(byte[]... parts) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(b);
        for (byte[] p : parts) { out.writeInt(p.length); out.write(p); }
        out.flush(); return b.toByteArray();
    }
    static byte[] mac(byte[] key, byte[] msg) throws GeneralSecurityException {
        Mac m = Mac.getInstance("HmacSHA256");
        m.init(new SecretKeySpec(key, "HmacSHA256"));
        return m.doFinal(msg);
    }
    static byte[] x25519() throws GeneralSecurityException {
        KeyPairGenerator g = KeyPairGenerator.getInstance("X25519", EC);
        KeyPair a = g.generateKeyPair(), b = g.generateKeyPair();
        KeyAgreement ka = KeyAgreement.getInstance("X25519", EC);
        ka.init(a.getPrivate()); ka.doPhase(b.getPublic(), true);
        byte[] left = ka.generateSecret();
        ka.init(b.getPrivate()); ka.doPhase(a.getPublic(), true);
        byte[] right = ka.generateSecret();
        try {
            if (left.length != 32 || !MessageDigest.isEqual(left, right))
                throw new GeneralSecurityException("X25519 shared-secret disagreement");
            return left;
        } finally { Arrays.fill(right, (byte) 0); }
    }
    static byte[] mlkem(Failure f) throws GeneralSecurityException {
        KeyPairGenerator g;
        if (f == Failure.BC_UNREGISTERED) {
            // Real JCA provider-resolution failure: provider instance is on classpath,
            // but intentionally not registered under its name in Security registry.
            if (Security.getProvider("BC") != null)
                throw new IllegalStateException("BC must be unregistered in this fixture");
            g = KeyPairGenerator.getInstance("ML-KEM", "BC");
        } else if (f == Failure.SUNEC_PINNED) {
            // Real provider algorithm-not-supported failure: SunEC is selected.
            g = KeyPairGenerator.getInstance("ML-KEM", EC);
        } else {
            g = KeyPairGenerator.getInstance("ML-KEM", BC);
        }
        g.initialize(MLKEMParameterSpec.ml_kem_768, RNG);
        KeyPair pair = g.generateKeyPair();
        KeyGenerator k = KeyGenerator.getInstance("ML-KEM", BC);
        k.init(new KEMGenerateSpec(pair.getPublic(), "AES", 256), RNG);
        SecretKeyWithEncapsulation encaps = (SecretKeyWithEncapsulation)k.generateKey();
        byte[] left = encaps.getEncoded();
        byte[] ciphertext = encaps.getEncapsulation();
        k.init(new KEMExtractSpec(pair.getPrivate(), ciphertext, "AES", 256));
        byte[] right = k.generateKey().getEncoded();
        try {
            if (left.length != 32 || right.length != 32 || ciphertext.length != 1088 ||
                !MessageDigest.isEqual(left, right))
                throw new GeneralSecurityException("ML-KEM-768 shared-secret disagreement");
            return left;
        } finally { Arrays.fill(right, (byte) 0); }
    }
    static CryptoEvidence crypt(Config c) throws Exception {
        byte[] x = null, pq = null, input = null, salt = null, prk = null, key = null;
        String failureType = "NONE";
        try {
            x = x25519();
            try {
                pq = mlkem(c.failure);
            } catch (GeneralSecurityException e) {
                if (c.failure == Failure.NONE)
                    throw new GeneralSecurityException("Unexpected ML-KEM provider error", e);
                failureType = e.getClass().getSimpleName();
                if (c.failure == Failure.BC_UNREGISTERED && !(e instanceof NoSuchProviderException))
                    throw new GeneralSecurityException("Expected NoSuchProviderException", e);
                if (c.failure == Failure.SUNEC_PINNED && !(e instanceof NoSuchAlgorithmException))
                    throw new GeneralSecurityException("Expected NoSuchAlgorithmException", e);
            }
            String attemptedProvider = c.failure == Failure.SUNEC_PINNED ? "SunEC" : "BC";
            if (pq == null && c.fallback == Fallback.NONE) {
                return new CryptoEvidence(Suite.NONE,false,false,false,attemptedProvider,failureType);
            }
            Suite actual = pq == null ? Suite.X25519_ONLY : Suite.X25519_MLKEM768;
            input = frame(x,pq == null ? new byte[0] : pq);
            salt = MessageDigest.getInstance("SHA-256").digest(DOMAIN);
            prk = mac(salt,input);
            key = mac(prk,frame(DOMAIN,"AES-GCM".getBytes(StandardCharsets.US_ASCII)));
            byte[] nonce = new byte[12]; RNG.nextBytes(nonce);
            byte[] plain = "synthetic-poc03-poc06-record".getBytes(StandardCharsets.UTF_8);
            byte[] aad = "fixture-tenant:T0|document:D0".getBytes(StandardCharsets.US_ASCII);
            Cipher enc = Cipher.getInstance("AES/GCM/NoPadding","SunJCE");
            enc.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,nonce));
            enc.updateAAD(aad);
            byte[] cipher = enc.doFinal(plain);
            Cipher dec = Cipher.getInstance("AES/GCM/NoPadding","SunJCE");
            dec.init(Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,nonce));
            dec.updateAAD(aad);
            boolean roundtrip = Arrays.equals(plain,dec.doFinal(cipher));
            return new CryptoEvidence(actual,pq != null,pq == null,roundtrip,
                                      attemptedProvider,failureType);
        } finally {
            for (byte[] value : new byte[][]{x,pq,input,salt,prk,key})
                if (value != null) Arrays.fill(value,(byte)0);
        }
    }
    static boolean approved(Policy p,CryptoEvidence e) {
        return e.aeadRoundtrip && (p != Policy.C2_PQC_REQUIRED ||
            (e.actualSuite == Suite.X25519_MLKEM768 && e.kemComplete));
    }
    static String status(Variant variant, Policy policy, CryptoEvidence e) {
        // No externally accepted response is produced on a failed crypto path.
        if (!e.aeadRoundtrip) return "REJECTED_EXECUTION";
        // V1 checks allowed components individually; it cannot require both components.
        boolean allowlisted = e.actualSuite == Suite.X25519_ONLY ||
                               e.actualSuite == Suite.X25519_MLKEM768;
        if (variant == Variant.V1_ALLOWLIST && !allowlisted) return "REJECTED_COMPONENT";
        if (variant == Variant.V2_FINAL_POLICY && !approved(policy,e)) return "REJECTED_POLICY";
        return "SUCCESS";
    }
    static Result one(Config c,Model m,Variant v) throws Exception {
        AtomicReference<PolicyState> live = new AtomicReference<>(new PolicyState(c.begin,1));
        CountDownLatch checked = new CountDownLatch(1),go = new CountDownLatch(1);
        ExecutorService pool = Executors.newSingleThreadExecutor();
        Future<Worker> task = pool.submit(() -> {
            PolicyState before = live.get();
            long checkedAt = System.nanoTime();
            checked.countDown();
            if (!go.await(15,TimeUnit.SECONDS)) throw new IllegalStateException("resume timeout");
            long start = System.nanoTime();
            CryptoEvidence evidence = crypt(c);
            PolicyState after = live.get();
            PolicyState effective = m == Model.SNAPSHOT ? before : after;
            String decision = status(v,effective.policy,evidence);
            long end = System.nanoTime();
            return new Worker(before,after,effective,evidence,decision,checkedAt,start,end,end-start);
        });
        try {
            if (!checked.await(15,TimeUnit.SECONDS)) throw new IllegalStateException("check timeout");
            live.set(new PolicyState(c.end,c.begin == c.end ? 1 : 2));
            long changedAt = System.nanoTime();
            go.countDown();
            Worker w = task.get(60,TimeUnit.SECONDS);
            return new Result(c,m,v,w,changedAt,w.checkedAt <= changedAt &&
                              changedAt <= w.cryptoStartedAt && w.cryptoStartedAt <= w.finishedAt);
        } finally { go.countDown(); pool.shutdownNow(); }
    }
    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("Expected one repetition number");
        int repeat = Integer.parseInt(args[0]);
        if (EC == null || Security.getProvider("BC") != null)
            throw new IllegalStateException("Requires SunEC and BC unregistered");
        List<Config> cases = List.of(
            new Config("C1_STABLE_HYBRID",Policy.C1_HYBRID_ALLOWED,Policy.C1_HYBRID_ALLOWED,Failure.NONE,Fallback.CLASSICAL),
            new Config("C2_STABLE_HYBRID",Policy.C2_PQC_REQUIRED,Policy.C2_PQC_REQUIRED,Failure.NONE,Fallback.CLASSICAL),
            new Config("C1_STABLE_BC_FAIL",Policy.C1_HYBRID_ALLOWED,Policy.C1_HYBRID_ALLOWED,Failure.BC_UNREGISTERED,Fallback.CLASSICAL),
            new Config("C2_STABLE_BC_FAIL",Policy.C2_PQC_REQUIRED,Policy.C2_PQC_REQUIRED,Failure.BC_UNREGISTERED,Fallback.CLASSICAL),
            new Config("UPGRADE_BC_FAIL",Policy.C1_HYBRID_ALLOWED,Policy.C2_PQC_REQUIRED,Failure.BC_UNREGISTERED,Fallback.CLASSICAL),
            new Config("UPGRADE_SUNEC_FAIL",Policy.C1_HYBRID_ALLOWED,Policy.C2_PQC_REQUIRED,Failure.SUNEC_PINNED,Fallback.CLASSICAL),
            new Config("RELAX_BC_FAIL",Policy.C2_PQC_REQUIRED,Policy.C1_HYBRID_ALLOWED,Failure.BC_UNREGISTERED,Fallback.CLASSICAL),
            new Config("UPGRADE_NO_FALLBACK",Policy.C1_HYBRID_ALLOWED,Policy.C2_PQC_REQUIRED,Failure.BC_UNREGISTERED,Fallback.NONE)
        );
        System.out.println("repeat,case,model,variant,policy_at_check,policy_at_finish,effective_policy,snapshot_epoch,finish_epoch,effective_epoch,key_version,kem_failure_injection,provider_attempted,kem_failure_type,actual_suite,kem_complete,fallback_taken,aead_roundtrip,final_status,oracle_verdict,ordering_ok,elapsed_ns");
        for (Config c : cases) for(Model m : Model.values()) for(Variant v : Variant.values()) {
            Result result = one(c,m,v);
            Worker w = result.worker;
            CryptoEvidence e = w.crypto;
            String oracle = w.finalStatus.equals("SUCCESS") ?
                  (approved(w.effective.policy,e) ? "COMPLIANT" : "VIOLATION") :
                   w.finalStatus;
            System.out.printf(Locale.ROOT,
                "%d,%s,%s,%s,%s,%s,%s,%d,%d,%d,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%d%n",
                repeat,c.id,m,v,w.check.policy,w.finish.policy,w.effective.policy,
                w.check.epoch,w.finish.epoch,w.effective.epoch,"K1",c.failure,
                e.providerAttempted,e.failureType,e.actualSuite,e.kemComplete,
                e.fallbackTaken,e.aeadRoundtrip,w.finalStatus,oracle,result.orderOK,w.elapsedNs);
            if (!result.orderOK) throw new IllegalStateException("Invalid event ordering: "+c.id);
        }
    }
}
