import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.BufferedWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.SplittableRandom;
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
 * Exploratory E1 timing benchmark for an unmodified Camel 4.22.0 PQCDataFormat.
 * Normal requests ONLY. This is not JMH, and cannot establish production latency.
 * Each fork is a new JVM; modes are interleaved in rotating seeded order.
 * No secret or message material is written to the report.
 */
public final class CamelPqcP1E1Timing {
    private enum Mode { V0, V1, V2 }
    private static final Set<String> ALLOWLIST = Set.of("MLKEM", "KYBER", "HQC");
    private static final byte[] MESSAGE = "normal-controlled-request".getBytes(StandardCharsets.UTF_8);
    private static final String REQUEST = "MLKEM";
    private static final int WARMUP = 120;
    private static final int SAMPLES = 300;
    private static final int GATE_WARMUP_BATCHES = 35;
    private static final int GATE_SAMPLES = 120;
    private static final int GATE_BATCH_SIZE = 10_000;
    private static volatile long observableSink = 0;

    private static final class Measurement {
        final Mode mode;
        final long nanos;
        final int iteration;
        Measurement(Mode mode, long nanos, int iteration) {
            this.mode = mode;
            this.nanos = nanos;
            this.iteration = iteration;
        }
    }

    /** The same policy logic as CamelPqcP1E1Comparison.checkGate(), for accepted requests. */
    private static String gate(Mode mode, PQCDataFormat df, String requested) {
        if (mode == Mode.V0) return null;
        if (!ALLOWLIST.contains(requested)) return "HEADER_NOT_ALLOWLISTED";
        if (mode == Mode.V1) return null;
        PQCKeyEncapsulationAlgorithms config;
        try {
            config = PQCKeyEncapsulationAlgorithms.valueOf(requested);
        } catch (IllegalArgumentException e) {
            return "UNKNOWN_KEM";
        }
        KeyGenerator actual = df.getKeyGenerator();
        if (actual == null || actual.getProvider() == null) return "GENERATOR_NOT_ATTESTABLE";
        if (!config.getAlgorithm().equalsIgnoreCase(actual.getAlgorithm())) return "ACTUAL_KEM_MISMATCH";
        String expectedProvider = config.getBcProvider();
        if (expectedProvider != null && !expectedProvider.equals(actual.getProvider().getName())) {
            return "ACTUAL_PROVIDER_MISMATCH";
        }
        return null;
    }

    private static void oneRoundTrip(DefaultCamelContext ctx, PQCDataFormat df, Mode mode)
            throws Exception {
        String reason = gate(mode, df, REQUEST);
        if (reason != null) throw new IllegalStateException("NORMAL_REQUEST_REJECTED:" + reason);
        Exchange sender = new DefaultExchange(ctx);
        sender.getIn().setHeader(PQCDataFormat.KEM_ALGORITHM, REQUEST);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        df.marshal(sender, MESSAGE, out);
        Exchange receiver = new DefaultExchange(ctx);
        Object clear = df.unmarshal(receiver, new ByteArrayInputStream(out.toByteArray()));
        if (!(clear instanceof byte[]) || !Arrays.equals(MESSAGE, (byte[]) clear)) {
            throw new IllegalStateException("NORMAL_ROUNDTRIP_MISMATCH");
        }
        observableSink += out.size() & 1;
    }

    private static long oneGateBatch(PQCDataFormat df, Mode mode) {
        int ok = 0;
        long before = System.nanoTime();
        for (int i = 0; i < GATE_BATCH_SIZE; i++) {
            // Alternate two valid labels; KYBER is the ML-KEM alias in Camel 4.22.0.
            String request = ((i & 1) == 0) ? "MLKEM" : "KYBER";
            if (gate(mode, df, request) == null) ok++;
        }
        long elapsed = System.nanoTime() - before;
        if (ok != GATE_BATCH_SIZE) throw new IllegalStateException("GATE_NORMAL_REJECT");
        observableSink += ok;
        return elapsed;
    }

    private static long percentile(List<Long> samples, double q) {
        List<Long> copy = new ArrayList<>(samples);
        Collections.sort(copy);
        int index = Math.max(0, Math.min(copy.size() - 1,
                (int) Math.ceil(q * copy.size()) - 1));
        return copy.get(index);
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            throw new IllegalArgumentException("Usage: CamelPqcP1E1Timing FORK_NUMBER OUTPUT_CSV");
        }
        int fork = Integer.parseInt(args[0]);
        if (fork < 1 || fork > 100) throw new IllegalArgumentException("BAD_FORK");
        Path csv = Path.of(args[1]);
        if (csv.getParent() != null) Files.createDirectories(csv.getParent());
        if (Files.exists(csv)) throw new IllegalStateException("REFUSE_TO_OVERWRITE:" + csv);
        System.out.println("TARGET=APACHE_CAMEL_4.22.0_RELEASED_JARS");
        System.out.println("SCOPE=NORMAL_MLKEM_AEAD_ROUNDTRIP_AND_POLICY_ONLY");
        System.out.println("WARMUP_PER_MODE=" + WARMUP);
        System.out.println("SAMPLES_PER_MODE=" + SAMPLES);
        System.out.println("POLICY_ONLY_GATE_BATCH_SIZE=" + GATE_BATCH_SIZE);
        System.out.println("FORK=" + fork);
        System.out.println("NO_PATCH_TO_CAMEL=true");
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", "BC");
        kpg.initialize(MLKEMParameterSpec.ml_kem_768, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();
        DefaultCamelContext context = new DefaultCamelContext();
        EnumMap<Mode, PQCDataFormat> formats = new EnumMap<>(Mode.class);
        EnumMap<Mode, List<Long>> timings = new EnumMap<>(Mode.class);
        EnumMap<Mode, List<Long>> gateTimings = new EnumMap<>(Mode.class);
        SplittableRandom rnd = new SplittableRandom(0x5AC01L + fork);
        for (Mode mode : Mode.values()) {
            timings.put(mode, new ArrayList<>());
            gateTimings.put(mode, new ArrayList<>());
        }
        try {
            context.start();
            for (Mode mode : Mode.values()) {
                PQCDataFormat df = new PQCDataFormat("MLKEM", "AES", kp);
                df.setSymmetricKeyLength(256);
                df.start();
                formats.put(mode, df);
                KeyGenerator kg = df.getKeyGenerator();
                if (kg == null || !"ML-KEM".equals(kg.getAlgorithm())
                        || !"BC".equals(kg.getProvider().getName())) {
                    throw new IllegalStateException("UNEXPECTED_CACHED_GENERATOR:" + mode);
                }
            }
            // Warm-up and measurements use shuffled interleaving, identical normal work in all modes.
            List<Measurement> rows = new ArrayList<>(SAMPLES * 3 + GATE_SAMPLES * 3);
            for (int i = -WARMUP; i < SAMPLES; i++) {
                List<Mode> order = new ArrayList<>(Arrays.asList(Mode.values()));
                Collections.rotate(order, rnd.nextInt(3));
                if (rnd.nextBoolean()) Collections.reverse(order);
                for (Mode mode : order) {
                    long before = System.nanoTime();
                    oneRoundTrip(context, formats.get(mode), mode);
                    long elapsed = System.nanoTime() - before;
                    if (i >= 0) {
                        timings.get(mode).add(elapsed);
                        rows.add(new Measurement(mode, elapsed, i));
                    }
                }
            }
            // The gate-only benchmark uses batches to reduce single-call clock quantization.
            for (int i = -GATE_WARMUP_BATCHES; i < GATE_SAMPLES; i++) {
                List<Mode> order = new ArrayList<>(Arrays.asList(Mode.values()));
                Collections.rotate(order, rnd.nextInt(3));
                if (rnd.nextBoolean()) Collections.reverse(order);
                for (Mode mode : order) {
                    long elapsed = oneGateBatch(formats.get(mode), mode);
                    if (i >= 0) gateTimings.get(mode).add(elapsed);
                }
            }
            try (BufferedWriter writer = Files.newBufferedWriter(csv)) {
                writer.write("fork,phase,mode,iteration,elapsed_ns,operations\n");
                for (Measurement row : rows) {
                    writer.write(fork + ",roundtrip," + row.mode + "," + row.iteration
                            + "," + row.nanos + ",1\n");
                }
                for (Mode mode : Mode.values()) {
                    List<Long> list = gateTimings.get(mode);
                    for (int i = 0; i < list.size(); i++) {
                        writer.write(fork + ",policy_only," + mode + "," + i
                                + "," + list.get(i) + "," + GATE_BATCH_SIZE + "\n");
                    }
                }
            }
            for (Mode mode : Mode.values()) {
                List<Long> sample = timings.get(mode);
                System.out.printf(Locale.ROOT,
                        "MODE=%s PHASE=ROUNDTRIP N=%d MEDIAN_US=%.3f P95_US=%.3f%n",
                        mode, sample.size(), percentile(sample, 0.50) / 1000.0,
                        percentile(sample, 0.95) / 1000.0);
                List<Long> gate = gateTimings.get(mode);
                System.out.printf(Locale.ROOT,
                        "MODE=%s PHASE=POLICY_ONLY N=%d GATE_MEDIAN_NS_PER_OP=%.3f%n",
                        mode, gate.size(), percentile(gate, 0.50) / (double) GATE_BATCH_SIZE);
            }
            System.out.println("REPORT_CSV=" + csv);
            System.out.println("RESULT=NORMAL_TIMING_EXPLORATORY_PASS");
        } finally {
            for (PQCDataFormat df : formats.values()) {
                try { df.stop(); } catch (Exception ignored) { /* keep primary failure */ }
            }
            context.stop();
        }
    }
}
