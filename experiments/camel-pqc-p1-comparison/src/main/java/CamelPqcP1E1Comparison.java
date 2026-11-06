import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Set;
import javax.crypto.KeyGenerator;
import org.apache.camel.Exchange;
import org.apache.camel.component.pqc.PQCKeyEncapsulationAlgorithms;
import org.apache.camel.component.pqc.dataformat.PQCDataFormat;
import org.apache.camel.impl.DefaultCamelContext;
import org.apache.camel.support.DefaultExchange;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

/**
 * E1/P1 PoC06 comparison against the UNMODIFIED Camel 4.22.0 released JAR.
 * V2 checks request/effective JCA algorithm+provider at the point of dispatch.
 * This is a SEQUENTIAL controlled demonstration, not a full concurrency invariant.
 * It does not output keys, shared secrets, plaintext or ciphertext.
 */
public final class CamelPqcP1E1Comparison {
    private static final byte[] MESSAGE = "controlled-poc06".getBytes(StandardCharsets.UTF_8);
    // Illustrative accepted algorithm labels, NOT an endorsement of HQC for production.
    private static final Set<String> ALLOWLIST = Set.of("MLKEM", "KYBER", "HQC");
    private static final String[] REQUESTS = {
            "MLKEM", "KYBER", "HQC", "NOT_A_REAL_KEM_ALGORITHM"
    };
    private enum Mode { V0, V1, V2 }
    private enum Status { EXECUTED, BLOCKED_POLICY, FAILED_EXECUTION }
    private static final class Result {
        final Status status;
        final boolean verifiedByMlkem;
        final String reason;
        Result(Status status, boolean verifiedByMlkem, String reason) {
            this.status = status;
            this.verifiedByMlkem = verifiedByMlkem;
            this.reason = reason;
        }
    }

    private static Result checkGate(Mode mode, PQCDataFormat dataFormat, String requested) {
        if (mode == Mode.V0) {
            return null;
        }
        if (!ALLOWLIST.contains(requested)) {
            return new Result(Status.BLOCKED_POLICY, false, "HEADER_NOT_ALLOWLISTED");
        }
        if (mode == Mode.V1) {
            return null;
        }
        // Match the caller's requested KEM to the actual JCA generator and its provider.
        // KYBER is an explicit ML-KEM alias in Camel 4.22.0; normalize via the enum.
        PQCKeyEncapsulationAlgorithms requestedConfig;
        try {
            requestedConfig = PQCKeyEncapsulationAlgorithms.valueOf(requested);
        } catch (IllegalArgumentException e) {
            return new Result(Status.BLOCKED_POLICY, false, "UNKNOWN_KEM");
        }
        KeyGenerator active = dataFormat.getKeyGenerator();
        if (active == null || active.getProvider() == null) {
            return new Result(Status.BLOCKED_POLICY, false, "GENERATOR_NOT_ATTESTABLE");
        }
        String expectedJce = requestedConfig.getAlgorithm();
        String expectedProvider = requestedConfig.getBcProvider();
        if (!expectedJce.equalsIgnoreCase(active.getAlgorithm())) {
            return new Result(Status.BLOCKED_POLICY, false, "ACTUAL_KEM_MISMATCH");
        }
        if (expectedProvider != null && !expectedProvider.equals(active.getProvider().getName())) {
            return new Result(Status.BLOCKED_POLICY, false, "ACTUAL_PROVIDER_MISMATCH");
        }
        return null;
    }

    private static Result execute(DefaultCamelContext context, PQCDataFormat dataFormat,
                                  Mode mode, String requested) {
        Result gate = checkGate(mode, dataFormat, requested);
        if (gate != null) {
            return gate;
        }
        try {
            Exchange sender = new DefaultExchange(context);
            sender.getIn().setHeader(PQCDataFormat.KEM_ALGORITHM, requested);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            dataFormat.marshal(sender, MESSAGE, out);
            // No request override during decryption: confirms that the default ML-KEM
            // instance successfully reads the produced record (indirect observable).
            Exchange receiver = new DefaultExchange(context);
            Object clear = dataFormat.unmarshal(receiver,
                    new ByteArrayInputStream(out.toByteArray()));
            boolean same = clear instanceof byte[] && Arrays.equals(MESSAGE, (byte[]) clear);
            return new Result(Status.EXECUTED, same, same ? "NONE" : "ROUNDTRIP_MISMATCH");
        } catch (Exception e) {
            return new Result(Status.FAILED_EXECUTION, false, e.getClass().getSimpleName());
        }
    }

    private static Status expectedStatus(Mode mode, String requested) {
        if (mode == Mode.V0) return Status.EXECUTED;
        if (!ALLOWLIST.contains(requested)) return Status.BLOCKED_POLICY;
        if (mode == Mode.V1) return Status.EXECUTED;
        return requested.equals("HQC") ? Status.BLOCKED_POLICY : Status.EXECUTED;
    }

    private static boolean expectedSuccess(Mode mode, String requested, Result result) {
        Status expected = expectedStatus(mode, requested);
        return result.status == expected
                && (expected != Status.EXECUTED || result.verifiedByMlkem);
    }

    public static void main(String[] args) throws Exception {
        System.out.println("TARGET=APACHE_CAMEL_4.22.0_RELEASED_JARS");
        System.out.println("SCOPE=SEQUENTIAL_P1_KEM_HEADER_TO_EFFECTIVE_JCA_MATCH");
        System.out.println("NO_PATCH_TO_CAMEL=true");
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ML-KEM", "BC");
        keyPairGenerator.initialize(MLKEMParameterSpec.ml_kem_768, new SecureRandom());
        KeyPair kp = keyPairGenerator.generateKeyPair();
        DefaultCamelContext context = new DefaultCamelContext();
        int checked = 0;
        int matching = 0;
        int actualMismatchExecuted = 0;
        try {
            context.start();
            for (Mode mode : Mode.values()) {
                // Independent initialized DataFormat per mode; same keypair + library.
                PQCDataFormat dataFormat = new PQCDataFormat("MLKEM", "AES", kp);
                dataFormat.setSymmetricKeyLength(256);
                dataFormat.start();
                try {
                    KeyGenerator actual = dataFormat.getKeyGenerator();
                    if (actual == null) {
                        throw new IllegalStateException("BASELINE_GENERATOR_UNAVAILABLE");
                    }
                    System.out.printf("MODE=%s ACTUAL_KEM=%s ACTUAL_PROVIDER=%s%n",
                            mode, actual.getAlgorithm(), actual.getProvider().getName());
                    for (String requested : REQUESTS) {
                        Result r = execute(context, dataFormat, mode, requested);
                        boolean matches = expectedSuccess(mode, requested, r);
                        System.out.printf("MODE=%s HEADER=%s STATUS=%s MLKEM_ROUNDTRIP=%s REASON=%s EXPECTED_MATCH=%s%n",
                                mode, requested, r.status, r.verifiedByMlkem, r.reason, matches);
                        checked++;
                        if (matches) matching++;
                        if ((requested.equals("HQC") || requested.equals("NOT_A_REAL_KEM_ALGORITHM"))
                                && r.status == Status.EXECUTED && r.verifiedByMlkem) {
                            actualMismatchExecuted++;
                        }
                    }
                } finally {
                    dataFormat.stop();
                }
            }
        } finally {
            context.stop();
        }
        System.out.printf("EXPECTED_MATCH=%d/%d%n", matching, checked);
        System.out.println("EFFECTIVE_KEM_MISMATCH_SUCCESSES=" + actualMismatchExecuted);
        System.out.println("RESULT=" + (matching == checked && checked == 12
                ? "CONTROLLED_E1_P1_COMPARISON_PASS" : "REVIEW_REQUIRED"));
        if (matching != checked || checked != 12) {
            throw new IllegalStateException("COMPARISON_REQUIRES_REVIEW");
        }
    }
}
