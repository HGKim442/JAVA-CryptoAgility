import java.lang.management.ManagementFactory;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;

/** Normal workloads only. Timing boundaries are specified in paper/protocol.json. */
public final class PaperBenchmark {
    private static final String CONTEXT = "paper-workload-v1";
    private static final int[] SIZES = {0, 4096, 1048576, 16777216};
    private static final int[] WARMUP = {20, 20, 5, 3};
    private static final int[] SAMPLES = {31, 31, 15, 7};
    private static final com.sun.management.ThreadMXBean BEAN =
        (com.sun.management.ThreadMXBean) ManagementFactory.getThreadMXBean();
    private static final long THREAD = Thread.currentThread().getId();
    private static volatile int sink;
    private static final StringBuilder CSV = new StringBuilder(
        "fork,profile,operation,plaintext_bytes,sample,ns,thread_allocated_bytes,output_bytes,reservation_writes,plaintext_sha256,correct\n");

    private static Path directory(Path root, String name) throws Exception {
        return Files.createDirectory(root.resolve(name),
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
    }
    private static byte[] message(int size) {
        byte[] bytes = new byte[size];
        for (int i = 0; i < bytes.length; i++) bytes[i] = (byte) (i * 31 + 7);
        return bytes;
    }
    private static String hash(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256", "SUN").digest(bytes));
    }
    private static void equal(byte[] expected, byte[] actual) {
        try { if (!Arrays.equals(expected, actual)) throw new AssertionError("Normal workload mismatch"); }
        finally { PqcExtension.wipe(actual); }
    }
    private static void row(int fork, int profile, String operation, int size, int sample,
                            long ns, long allocation, int output, long writes, String sha) {
        if (sample < 0) return;
        if (ns <= 0 || allocation < 0 || writes < 0) throw new AssertionError("Invalid measurement");
        CSV.append(fork).append(',').append(profile).append(',').append(operation).append(',')
            .append(size).append(',').append(sample).append(',').append(ns).append(',')
            .append(allocation).append(',').append(output).append(',').append(writes).append(',')
            .append(sha).append(",true\n");
    }
    private static List<Integer> sizeOrder(int fork) {
        List<Integer> order = new ArrayList<>(List.of(0, 1, 2, 3));
        Collections.rotate(order, -(fork - 1) % 4);
        if (fork % 2 == 0) Collections.reverse(order);
        return order;
    }
    private static void warm(int fork, PqcExtension.Profile profile, Path root, byte[] master) throws Exception {
        Path base = directory(root, "warm-" + profile.category());
        Path data = directory(base, "data"), anchor = directory(base, "anchor");
        try (PqcExtension.Engine engine = PqcExtension.Engine.createPersistent(profile, CONTEXT, data, anchor, master)) {
            for (int index : sizeOrder(fork)) {
                int size = SIZES[index]; byte[] plain = message(size); String sha = hash(plain);
                for (int i = -WARMUP[index]; i < SAMPLES[index]; i++) {
                    var probe = engine.prepare(profile, CONTEXT);
                    long writes = engine.reservationWrites(probe);
                    long before = BEAN.getThreadAllocatedBytes(THREAD), start = System.nanoTime();
                    var packet = engine.seal(engine.prepare(profile, CONTEXT), plain);
                    byte[] encoded = packet.encode();
                    long ns = System.nanoTime() - start, allocation = BEAN.getThreadAllocatedBytes(THREAD) - before;
                    long delta = engine.reservationWrites(probe) - writes;
                    equal(plain, engine.open(engine.prepareHistorical(profile.policyVersion()),
                        PqcExtension.Packet.decode(encoded)));
                    sink = encoded.length;
                    row(fork, profile.category(), "seal_encode", size, i, ns, allocation, encoded.length, delta, sha);
                }
                byte[] encoded = engine.seal(engine.prepare(profile, CONTEXT), plain).encode();
                for (int i = -WARMUP[index]; i < SAMPLES[index]; i++) {
                    long before = BEAN.getThreadAllocatedBytes(THREAD), start = System.nanoTime();
                    byte[] opened = engine.open(engine.prepareHistorical(profile.policyVersion()),
                        PqcExtension.Packet.decode(encoded));
                    long ns = System.nanoTime() - start, allocation = BEAN.getThreadAllocatedBytes(THREAD) - before;
                    sink = opened.length; equal(plain, opened);
                    row(fork, profile.category(), "decode_open", size, i, ns, allocation, size, 0, sha);
                }
                PqcExtension.wipe(plain);
            }
        }
    }
    private static void lifecycle(int fork, PqcExtension.Profile profile, Path root, byte[] master) throws Exception {
        String sha = hash(new byte[0]);
        for (int i = -3; i < 7; i++) {
            Path base = directory(root, "lifecycle-" + profile.category() + "-" + (i + 3));
            Path data = directory(base, "data"), anchor = directory(base, "anchor");
            long before = BEAN.getThreadAllocatedBytes(THREAD), start = System.nanoTime();
            try (PqcExtension.Engine engine = PqcExtension.Engine.createPersistent(profile, CONTEXT, data, anchor, master)) {
                sink = engine.currentProfile().category();
            }
            long ns = System.nanoTime() - start, allocation = BEAN.getThreadAllocatedBytes(THREAD) - before;
            row(fork, profile.category(), "create_close", 0, i, ns, allocation, 0, 0, sha);
            before = BEAN.getThreadAllocatedBytes(THREAD); start = System.nanoTime();
            try (PqcExtension.Engine engine = PqcExtension.Engine.reopen(CONTEXT, data, anchor, master, false)) {
                sink = engine.currentProfile().category();
                if (!engine.currentProfile().equals(profile)) throw new AssertionError("Restored profile mismatch");
            }
            ns = System.nanoTime() - start; allocation = BEAN.getThreadAllocatedBytes(THREAD) - before;
            row(fork, profile.category(), "reopen_close", 0, i, ns, allocation, 0, 0, sha);
            try (PqcExtension.Engine engine = PqcExtension.Engine.reopen(CONTEXT, data, anchor, master, false)) {
                byte[] plain = message(4096);
                equal(plain, engine.open(engine.prepareHistorical(profile.policyVersion()),
                    engine.seal(engine.prepare(profile, CONTEXT), plain)));
            }
        }
    }
    private static void upgrade(int fork, Path root, byte[] master) throws Exception {
        byte[] plain = message(4096); String sha = hash(plain);
        for (int i = -3; i < 7; i++) {
            Path base = directory(root, "upgrade-" + (i + 3));
            Path data = directory(base, "data"), anchor = directory(base, "anchor");
            try (PqcExtension.Engine engine = PqcExtension.Engine.createPersistent(PqcExtension.P3, CONTEXT, data, anchor, master)) {
                var old = engine.seal(engine.prepare(PqcExtension.P3, CONTEXT), plain);
                long before = BEAN.getThreadAllocatedBytes(THREAD), start = System.nanoTime();
                engine.activate(PqcExtension.P5);
                long ns = System.nanoTime() - start, allocation = BEAN.getThreadAllocatedBytes(THREAD) - before;
                if (!engine.currentProfile().equals(PqcExtension.P5)) throw new AssertionError("Upgrade mismatch");
                equal(plain, engine.open(engine.prepareHistorical(1), old));
                equal(plain, engine.open(engine.prepareHistorical(2), engine.seal(engine.prepare(PqcExtension.P5, CONTEXT), plain)));
                row(fork, 5, "upgrade3_to5", 4096, i, ns, allocation, 0, 0, sha);
            }
            try (PqcExtension.Engine engine = PqcExtension.Engine.reopen(CONTEXT, data, anchor, master, false)) {
                if (!engine.currentProfile().equals(PqcExtension.P5)) throw new AssertionError("Upgrade persistence");
            }
        }
    }
    public static void main(String[] args) throws Exception {
        if (args.length != 2) throw new IllegalArgumentException("OUTPUT FORK");
        Path output = Path.of(args[0]); int fork = Integer.parseInt(args[1]);
        if (fork < 1 || fork > 6 || !BEAN.isThreadAllocatedMemorySupported()) throw new IllegalArgumentException("Unsupported measurement");
        BEAN.setThreadAllocatedMemoryEnabled(true);
        byte[] master = new byte[32]; new SecureRandom().nextBytes(master);
        Path root = Files.createTempDirectory("pqc-paper-", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        try {
            List<PqcExtension.Profile> profiles = fork % 2 == 1 ? List.of(PqcExtension.P3, PqcExtension.P5) : List.of(PqcExtension.P5, PqcExtension.P3);
            for (var profile : profiles) { warm(fork, profile, root, master); lifecycle(fork, profile, root, master); }
            upgrade(fork, root, master);
            Files.writeString(output, CSV.toString(), StandardOpenOption.CREATE_NEW);
        } finally {
            PqcExtension.wipe(master);
            try (var walk = Files.walk(root)) {
                for (Path path : walk.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(path);
            }
        }
        System.out.println("PASS normal paper workloads fork=" + fork + " rows=371");
    }
}
