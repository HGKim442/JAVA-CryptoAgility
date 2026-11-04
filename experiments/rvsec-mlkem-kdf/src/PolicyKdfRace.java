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

public class PolicyKdfRace {
    static final SecureRandom RNG = new SecureRandom();

    static byte[] str(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
    static byte[] concat(byte[]... parts) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) out.write(p);
        return out.toByteArray();
    }
    static byte[] frame(byte[]... parts) throws Exception {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(buffer);
        for (byte[] p : parts) {
            out.writeInt(p.length);
            out.write(p);
        }
        out.flush();
        return buffer.toByteArray();
    }
    static byte[] sha(byte[] message) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(message);
    }
    static byte[] hmac(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data);
    }
    static byte[] agree(PrivateKey own, PublicKey peer) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("X25519", "BC");
        ka.init(own);
        ka.doPhase(peer, true);
        return ka.generateSecret();
    }
    static final class Session {
        final byte[] enc;
        final byte[] confirm;
        Session(byte[] e, byte[] c) { enc = e; confirm = c; }
        void clear() {
            Arrays.fill(enc, (byte) 0);
            Arrays.fill(confirm, (byte) 0);
        }
    }
    // Toy labeled HKDF for controlled experiment; not a standardized wire protocol.
    static Session derive(byte[] x, byte[] kem, byte[] transcript)
        throws Exception {
        byte[] ikm = frame(x, kem == null ? new byte[0] : kem);
        byte[] salt = sha(frame(str("D2-10-EXTRACT-SALT"), transcript));
        byte[] prk = hmac(salt, ikm);
        byte[] info = frame(str("D2-10-SESSION"), transcript);
        byte[] t1 = hmac(prk, concat(info, new byte[]{1}));
        byte[] t2 = hmac(prk, concat(t1, info, new byte[]{2}));
        Session result = new Session(t1.clone(), t2.clone());
        for (byte[] item : new byte[][]{ikm, salt, prk, t1, t2})
            Arrays.fill(item, (byte) 0);
        return result;
    }
    static final class BindingGuard {
        private final byte[] expectedAlice;
        private final byte[] expectedBob;
        BindingGuard(byte[] encapSecret, byte[] decapSecret) {
            expectedAlice = encapSecret.clone();
            expectedBob = decapSecret.clone();
        }
        boolean check(byte[] aliceInput, byte[] bobInput) {
            return aliceInput != null && bobInput != null
                && aliceInput.length == 32 && bobInput.length == 32
                && expectedAlice.length == 32 && expectedBob.length == 32
                && MessageDigest.isEqual(aliceInput, expectedAlice)
                && MessageDigest.isEqual(bobInput, expectedBob);
        }
        VerifiedPair verifyAndPin(byte[] aliceInput, byte[] bobInput) {
            if (!check(aliceInput, bobInput)) return null;
            // Return copies from the registered provider results, never
            // retain caller-owned mutable arrays for later KDF use.
            return new VerifiedPair(expectedAlice.clone(), expectedBob.clone());
        }
        void clear() {
            Arrays.fill(expectedAlice, (byte) 0);
            Arrays.fill(expectedBob, (byte) 0);
        }
    }
    static final class VerifiedPair {
        final byte[] alice;
        final byte[] bob;
        VerifiedPair(byte[] alice, byte[] bob) {
            this.alice = alice;
            this.bob = bob;
        }
        void clear() {
            Arrays.fill(alice, (byte) 0);
            Arrays.fill(bob, (byte) 0);
        }
    }
    static boolean record(Session alice, Session bob) throws Exception {
        byte[] nonce = new byte[12];
        RNG.nextBytes(nonce);
        byte[] message = str("D2-10-KDF-PROVENANCE-RECORD");
        byte[] aad = str("D2-10-SESSION-CONTEXT");
        Cipher enc = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(alice.enc, "AES"),
            new GCMParameterSpec(128, nonce));
        enc.updateAAD(aad);
        byte[] ciphertext = enc.doFinal(message);
        Cipher dec = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        dec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(bob.enc, "AES"),
            new GCMParameterSpec(128, nonce));
        dec.updateAAD(aad);
        return MessageDigest.isEqual(message, dec.doFinal(ciphertext));
    }
    public static void main(String[] args) throws Exception {
        if (args.length != 2) throw new IllegalArgumentException("MODE ENFORCEMENT");
        String mode = args[0], enforcement = args[1];
        if (!Arrays.asList("HONEST", "MUTATE_AFTER_CHECK")
                .contains(mode)) throw new IllegalArgumentException(mode);
        if (!Arrays.asList("DIRECT", "PINNED").contains(enforcement))
            throw new IllegalArgumentException(enforcement);
        Security.addProvider(new BouncyCastleProvider());

        KeyPairGenerator xgen = KeyPairGenerator.getInstance("X25519", "BC");
        KeyPair alice = xgen.generateKeyPair(), bob = xgen.generateKeyPair();
        byte[] xa = agree(alice.getPrivate(), bob.getPublic());
        byte[] xb = agree(bob.getPrivate(), alice.getPublic());
        boolean xMatch = xa.length == 32 && MessageDigest.isEqual(xa, xb);
        if (!xMatch) throw new IllegalStateException("X25519 disagreement");

        KeyPairGenerator kgen = KeyPairGenerator.getInstance("ML-KEM", "BC");
        kgen.initialize(MLKEMParameterSpec.ml_kem_768, RNG);
        KeyPair kp = kgen.generateKeyPair();
        KeyGenerator k = KeyGenerator.getInstance("ML-KEM", "BC");
        k.init(new KEMGenerateSpec(kp.getPublic(), "AES", 256), RNG);
        SecretKeyWithEncapsulation encap =
            (SecretKeyWithEncapsulation) k.generateKey();
        byte[] ka = encap.getEncoded();
        byte[] ct = encap.getEncapsulation().clone();
        k.init(new KEMExtractSpec(kp.getPrivate(), ct, "AES", 256));
        SecretKeyWithEncapsulation decap =
            (SecretKeyWithEncapsulation) k.generateKey();
        byte[] kb = decap.getEncoded();
        boolean kemMatch = ka.length == 32 && kb.length == 32
            && ct.length == 1088 && MessageDigest.isEqual(ka, kb);
        if (!kemMatch) throw new IllegalStateException("ML-KEM disagreement");

        byte[] candidateA, candidateB;
        switch (mode) {
            case "HONEST":
            case "MUTATE_AFTER_CHECK":
                candidateA = ka.clone(); candidateB = kb.clone(); break;
            case "OMIT":
                candidateA = null; candidateB = null; break;
            case "SUBSTITUTE":
                candidateA = new byte[32]; RNG.nextBytes(candidateA);
                candidateB = candidateA.clone(); break;
            case "WRONG_SESSION":
                KeyPair other = kgen.generateKeyPair();
                KeyGenerator otherK = KeyGenerator.getInstance("ML-KEM", "BC");
                otherK.init(new KEMGenerateSpec(other.getPublic(), "AES", 256), RNG);
                SecretKeyWithEncapsulation otherEncap =
                    (SecretKeyWithEncapsulation) otherK.generateKey();
                candidateA = otherEncap.getEncoded();
                candidateB = candidateA.clone(); break;
            default: throw new IllegalStateException(mode);
        }

        BindingGuard guard = new BindingGuard(ka, kb);
        // Authorization and secret pinning happen before the adversarial mutation.
        VerifiedPair pinned = guard.verifyAndPin(candidateA, candidateB);
        boolean bindingOK = pinned != null;
        if (!bindingOK) throw new IllegalStateException("Honest input was denied");

        boolean mutatorRan = false;
        if (mode.equals("MUTATE_AFTER_CHECK")) {
            final byte[] mutableAlice = candidateA;
            final byte[] mutableBob = candidateB;
            CountDownLatch release = new CountDownLatch(1);
            CountDownLatch finished = new CountDownLatch(1);
            AtomicReference<Throwable> mutationError = new AtomicReference<>();
            Thread mutator = new Thread(() -> {
                try {
                    if (!release.await(10, TimeUnit.SECONDS))
                        throw new IllegalStateException("Mutation start timeout");
                    // A fixed public replacement excludes ML-KEM secret entropy.
                    Arrays.fill(mutableAlice, (byte) 0);
                    Arrays.fill(mutableBob, (byte) 0);
                } catch (Throwable ex) {
                    mutationError.set(ex);
                } finally {
                    finished.countDown();
                }
            }, "after-check-mutator");
            mutator.start();
            release.countDown();
            if (!finished.await(10, TimeUnit.SECONDS))
                throw new IllegalStateException("Mutation completion timeout");
            mutator.join(10000);
            if (mutator.isAlive() || mutationError.get() != null)
                throw new IllegalStateException("Mutator failed", mutationError.get());
            mutatorRan = true;
        }

        byte[] kdfAlice = enforcement.equals("PINNED")
            ? pinned.alice : candidateA;
        byte[] kdfBob = enforcement.equals("PINNED")
            ? pinned.bob : candidateB;
        boolean kdfBindingAtUse = MessageDigest.isEqual(kdfAlice, ka)
            && MessageDigest.isEqual(kdfBob, kb);
        boolean shouldProcess = bindingOK;
        boolean keyConfirmation = false, roundtrip = false;
        int recordCalls = 0;
        if (shouldProcess) {
            byte[] transcript = sha(frame(str("X25519-ML-KEM-768"),
                alice.getPublic().getEncoded(), bob.getPublic().getEncoded(),
                kp.getPublic().getEncoded(), ct));
            Session sa = derive(xa, kdfAlice, transcript);
            Session sb = derive(xb, kdfBob, transcript);
            keyConfirmation = MessageDigest.isEqual(
                hmac(sa.confirm, str("D2-10-KEY-CONFIRM")),
                hmac(sb.confirm, str("D2-10-KEY-CONFIRM")));
            if (keyConfirmation) {
                recordCalls++;
                roundtrip = record(sa, sb);
            }
            sa.clear(); sb.clear();
        }
        boolean expectedKdfBinding = mode.equals("HONEST")
            || enforcement.equals("PINNED");
        boolean passed = xMatch && kemMatch && bindingOK && shouldProcess
            && mutatorRan == mode.equals("MUTATE_AFTER_CHECK")
            && kdfBindingAtUse == expectedKdfBinding
            && keyConfirmation && roundtrip && recordCalls == 1;
        System.out.println("MODE=" + mode);
        System.out.println("ENFORCEMENT=" + enforcement);
        System.out.println("POLICY=PQC_REQUIRED");
        System.out.println("X25519_MATCH=" + xMatch);
        System.out.println("MLKEM_SHARED_MATCH=" + kemMatch);
        System.out.println("MLKEM_CIPHERTEXT_BYTES=" + ct.length);
        System.out.println("BINDING_OK=" + bindingOK);
        System.out.println("GUARD_DECISION=" + (bindingOK ? "ALLOW" : "DENY"));
        System.out.println("MUTATOR_RAN=" + mutatorRan);
        System.out.println("KDF_INPUT_BINDING=" + kdfBindingAtUse);
        System.out.println("KDF_INPUT_SOURCE=" + (
            enforcement.equals("PINNED") ? "PINNED_PROVIDER_COPY" : "CALLER_MUTABLE"));
        System.out.println("EFFECTIVE_ACCEPT=" + shouldProcess);
        System.out.println("KEY_CONFIRMATION=" + keyConfirmation);
        System.out.println("RECORD_CALLS=" + recordCalls);
        System.out.println("RECORD_ROUNDTRIP=" + roundtrip);
        System.out.println("RESULT=" + (passed ? "PASS" : "FAIL"));
        pinned.clear();
        guard.clear();
        for (byte[] secret : new byte[][]{xa, xb, ka, kb})
            Arrays.fill(secret, (byte) 0);
        if (candidateA != null) Arrays.fill(candidateA, (byte) 0);
        if (candidateB != null) Arrays.fill(candidateB, (byte) 0);
        if (!passed) throw new IllegalStateException("D2-10 controlled assertion failed");
    }
}
