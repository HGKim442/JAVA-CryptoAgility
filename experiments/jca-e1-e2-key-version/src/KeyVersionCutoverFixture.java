import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Independent synthetic PoC06 single-factor key-version test. NOT a production library.
 * An administrator-authorized K1 -> K2 rotation is ordered between request check
 * and final cryptographic operation. No PQC or ML-DSA in this single-factor fixture.
 */
public final class KeyVersionCutoverFixture {
    enum Mode { V0_VULNERABLE, V1_ALLOWLIST, V2_POLICY_BOUND }
    enum Model { SNAPSHOT, STRICT_CUTOVER }
    enum Scenario { STABLE_K1, STABLE_K2, ROTATE_K1_TO_K2 }
    static final Provider SUNJCE = Security.getProvider("SunJCE");
    static final SecureRandom RANDOM = new SecureRandom();
    static final class Policy {
        final int epoch, requiredKeyVersion;
        Policy(int epoch, int version) { this.epoch = epoch; this.requiredKeyVersion = version; }
    }
    static final class Result {
        String result, reason, oracle, usedVersion;
        boolean roundtrip, ordering;
        int checkVersion, finishVersion, effectiveVersion, checkEpoch, finishEpoch;
    }
    private static byte[] aad(int version) {
        return ("JCA-POC06|tenant=t1|doc=d1|keyVersion=K" + version).getBytes(StandardCharsets.UTF_8);
    }
    private static boolean encryptAndRoundTrip(byte[] key, int version) throws Exception {
        byte[] nonce = new byte[12];
        RANDOM.nextBytes(nonce);
        byte[] plain = "POC06-CONTROLLED-PLAINTEXT".getBytes(StandardCharsets.US_ASCII);
        Cipher enc = Cipher.getInstance("AES/GCM/NoPadding", SUNJCE);
        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key,"AES"), new GCMParameterSpec(128, nonce));
        enc.updateAAD(aad(version));
        byte[] ciphertext = enc.doFinal(plain);
        Cipher dec = Cipher.getInstance("AES/GCM/NoPadding", SUNJCE);
        dec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key,"AES"), new GCMParameterSpec(128, nonce));
        dec.updateAAD(aad(version));
        return Arrays.equals(plain, dec.doFinal(ciphertext));
    }
    static String oracle(boolean accepted, int actualVersion, int effectiveVersion) {
        if (!accepted) return "REJECTED_POLICY";
        return actualVersion == effectiveVersion ? "COMPLIANT" : "VIOLATION";
    }
    private static void check(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }
    static Result test(Scenario scenario, Model model, Mode mode) throws Exception {
        final boolean rotated = scenario == Scenario.ROTATE_K1_TO_K2;
        final int firstVersion = scenario == Scenario.STABLE_K2 ? 2 : 1;
        final Policy initial = new Policy(1, firstVersion);
        final AtomicReference<Policy> active = new AtomicReference<>(initial);
        final byte[] key1 = new byte[32], key2 = new byte[32];
        RANDOM.nextBytes(key1); RANDOM.nextBytes(key2);
        final CountDownLatch checked = new CountDownLatch(1);
        final CountDownLatch proceed = new CountDownLatch(1);
        final AtomicReference<Throwable> failure = new AtomicReference<>();
        final AtomicReference<Result> output = new AtomicReference<>();
        Thread worker = new Thread(() -> {
            Result r = new Result();
            try {
                Policy approvedAtCheck = active.get();
                // V1 & V2 are equivalent for the approved entry gate in this test.
                if (mode != Mode.V0_VULNERABLE) {
                    check(SUNJCE != null, "Trusted Provider absent");
                    check(approvedAtCheck.requiredKeyVersion == 1 || approvedAtCheck.requiredKeyVersion == 2,
                          "Unapproved key version");
                }
                checked.countDown();
                if (!proceed.await(10, TimeUnit.SECONDS)) throw new IllegalStateException("RELEASE_TIMEOUT");
                Policy end = active.get();
                Policy effective = model == Model.SNAPSHOT ? approvedAtCheck : end;
                int chosenVersion = approvedAtCheck.requiredKeyVersion; // issued request key remains pinned
                r.checkVersion = approvedAtCheck.requiredKeyVersion;
                r.finishVersion = end.requiredKeyVersion;
                r.effectiveVersion = effective.requiredKeyVersion;
                r.checkEpoch = approvedAtCheck.epoch;
                r.finishEpoch = end.epoch;
                r.ordering = (end.epoch >= approvedAtCheck.epoch)
                    && (!rotated || end.epoch > approvedAtCheck.epoch);
                if (mode == Mode.V2_POLICY_BOUND && chosenVersion != effective.requiredKeyVersion) {
                    r.result = "REJECTED_POLICY";
                    r.reason = "KEY_VERSION_MISMATCH";
                    r.usedVersion = "NONE";
                    r.roundtrip = false;
                    r.oracle = "REJECTED_POLICY";
                } else {
                    byte[] chosen = chosenVersion == 1 ? key1 : key2;
                    r.roundtrip = encryptAndRoundTrip(chosen, chosenVersion);
                    check(r.roundtrip, "AES_GCM_ROUNDTRIP_FAILED");
                    r.result = "SUCCESS";
                    r.reason = "NONE";
                    r.usedVersion = "K" + chosenVersion;
                    r.oracle = oracle(true, chosenVersion, effective.requiredKeyVersion);
                }
                output.set(r);
            } catch(Throwable t) { failure.set(t); checked.countDown(); }
        }, "poc06-request");
        try {
            worker.start();
            if (!checked.await(10, TimeUnit.SECONDS)) throw new IllegalStateException("CHECK_TIMEOUT");
            if (rotated) active.set(new Policy(2, 2));
            proceed.countDown();
            worker.join(15000);
            check(!worker.isAlive(), "WORKER_TIMEOUT");
            if (failure.get() != null) throw new IllegalStateException("WORKER_ERROR", failure.get());
            check(output.get() != null, "NO_RESULT");
            return output.get();
        } finally {
            proceed.countDown();
            Arrays.fill(key1, (byte)0);
            Arrays.fill(key2, (byte)0);
        }
    }
    public static void main(String[] args) throws Exception {
        int repetition = args.length == 1 ? Integer.parseInt(args[0]) : 1;
        System.out.println("repeat,scenario,model,mode,policy_at_check,policy_at_finish,effective_version,check_epoch,finish_epoch,actual_key_version,final_status,reason,aead_roundtrip,ordering_ok,oracle_verdict");
        for (Scenario sc : Scenario.values()) {
            for (Model policy : Model.values()) for (Mode mode : Mode.values()) {
                Result r = test(sc,policy,mode);
                System.out.printf(Locale.ROOT, "%d,%s,%s,%s,K%d,K%d,K%d,%d,%d,%s,%s,%s,%s,%s,%s%n",
                    repetition,sc,policy,mode,r.checkVersion,r.finishVersion,r.effectiveVersion,
                    r.checkEpoch,r.finishEpoch,r.usedVersion,r.result,r.reason,
                    Boolean.toString(r.roundtrip),Boolean.toString(r.ordering),r.oracle);
            }
        }
    }
}
