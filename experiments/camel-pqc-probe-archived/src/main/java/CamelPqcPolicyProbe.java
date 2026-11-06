import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

import org.apache.camel.Exchange;
import org.apache.camel.component.pqc.PQCKeyEncapsulationAlgorithms;
import org.apache.camel.component.pqc.dataformat.PQCDataFormat;
import org.apache.camel.impl.DefaultCamelContext;
import org.apache.camel.support.DefaultExchange;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

/**
 * Controlled PoC06 probe on the unmodified Apache Camel 4.22.0 library.
 * No secret keys, shared secrets, ciphertext, or passwords are logged.
 * Observations do not automatically establish a security vulnerability.
 */
public final class CamelPqcPolicyProbe {
    private static final byte[] PAYLOAD =
            "camel-pqc-poc06-controlled-test".getBytes(StandardCharsets.UTF_8);

    private static final class Observation {
        final boolean encrypted;
        final boolean decryptedByMlkem;
        final String errorType;
        Observation(boolean e, boolean d, String t) {
            encrypted = e; decryptedByMlkem = d; errorType = t;
        }
    }

    private static Observation measure(
            DefaultCamelContext context, PQCDataFormat df, String requestedKem) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try {
            Exchange exchange = new DefaultExchange(context);
            if (requestedKem != null) {
                exchange.getIn().setHeader(PQCDataFormat.KEM_ALGORITHM, requestedKem);
            }
            df.marshal(exchange, PAYLOAD, output);
        } catch (Exception e) {
            return new Observation(false, false, e.getClass().getSimpleName());
        }
        try {
            // Deliberately omit the override on decryption. If it succeeds,
            // the original ML-KEM configuration can read this record.
            Exchange receiving = new DefaultExchange(context);
            Object decrypted = df.unmarshal(receiving,
                    new ByteArrayInputStream(output.toByteArray()));
            return new Observation(true,
                    decrypted instanceof byte[] && Arrays.equals(PAYLOAD, (byte[]) decrypted),
                    "NONE");
        } catch (Exception e) {
            return new Observation(true, false, e.getClass().getSimpleName());
        }
    }

    private static void emit(String caseName, Observation r) {
        System.out.printf("CASE=%s ENCRYPTED=%s DECRYPTED_BY_MLKEM=%s ERROR_TYPE=%s%n",
                caseName, r.encrypted, r.decryptedByMlkem, r.errorType);
    }

    public static void main(String[] args) throws Exception {
        System.out.println("TARGET=APACHE_CAMEL_4.22.0_RELEASED_JARS");
        System.out.println("SCOPE=PQC_DATAFORMAT_KEM_HEADER_AND_PROVIDER_ONLY");
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());
        KeyPairGenerator generator = KeyPairGenerator.getInstance(
                PQCKeyEncapsulationAlgorithms.MLKEM.getAlgorithm(),
                PQCKeyEncapsulationAlgorithms.MLKEM.getBcProvider());
        generator.initialize(MLKEMParameterSpec.ml_kem_768, new SecureRandom());
        KeyPair kp = generator.generateKeyPair();

        DefaultCamelContext context = new DefaultCamelContext();
        try {
            context.start();
            PQCDataFormat df = new PQCDataFormat("MLKEM", "AES", kp);
            df.setSymmetricKeyLength(256);
            df.start();
            System.out.println("STARTED_KEY_GENERATOR_ALGORITHM="
                    + df.getKeyGenerator().getAlgorithm());

            Observation honest = measure(context, df, "MLKEM");
            Observation prestandard = measure(context, df, "KYBER");
            Observation unknown = measure(context, df, "NOT_A_REAL_KEM_ALGORITHM");
            emit("VALID_MLKEM_HEADER", honest);
            emit("DIFFERENT_KYBER_HEADER", prestandard);
            emit("INVALID_KEM_HEADER", unknown);
            boolean suspect = unknown.encrypted && unknown.decryptedByMlkem;
            System.out.println("CANDIDATE_HEADER_POLICY_MISMATCH=" + suspect);
            df.stop();

            PQCDataFormat invalidProvider = new PQCDataFormat("MLKEM", "AES", kp);
            invalidProvider.setProvider("NO_SUCH_PROVIDER_POC06");
            boolean providerRejected;
            try {
                invalidProvider.start();
                providerRejected = false;
                invalidProvider.stop();
            } catch (Exception e) {
                providerRejected = true;
                System.out.println("INVALID_PROVIDER_ERROR_TYPE="
                        + e.getClass().getSimpleName());
            }
            System.out.println("INVALID_PROVIDER_REJECTED=" + providerRejected);
            boolean baseline = honest.encrypted && honest.decryptedByMlkem;
            System.out.println("BASELINE_ROUNDTRIP=" + baseline);
            System.out.println("RESULT=" + (baseline && providerRejected
                    ? "CONTROLLED_PROBE_COMPLETED" : "REVIEW_REQUIRED"));
            if (!baseline || !providerRejected) {
                throw new IllegalStateException("Baseline or provider control requires review");
            }
        } finally {
            context.stop();
        }
    }
}
