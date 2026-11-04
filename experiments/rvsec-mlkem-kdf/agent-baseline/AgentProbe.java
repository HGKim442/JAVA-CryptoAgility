import java.security.MessageDigest;
import java.util.Arrays;

/** Isolated single-request probe; logs counters only, never secret bytes. */
public final class AgentProbe {
    public static final String MODE = System.getProperty("d215.mode", "AUDIT");
    private static final byte[][] reference = new byte[2][];
    private static int captured = 0, derived = 0, mismatches = 0, records = 0;
    private static int transforms = 0, blocks = 0;
    private static int coverageGaps = 0, coverageBlocks = 0;
    private static boolean closed = false;

    static {
        if (!"AUDIT".equals(MODE) && !"ENFORCE".equals(MODE))
            throw new IllegalArgumentException("Invalid d215.mode=" + MODE);
        Runtime.getRuntime().addShutdownHook(new Thread(new Runnable() {
            public void run() { summarize(); }
        }, "d213-probe-summary"));
    }

    private AgentProbe() {}

    public static synchronized void transformed(String cls) { transforms++; }

    public static synchronized void captureKem(byte[] key) {
        captured++;
        if (captured <= 2 && key != null) reference[captured - 1] = key.clone();
        System.out.println("AGENT_CAPTURE_INDEX=" + captured);
        System.out.println("AGENT_CAPTURE_LENGTH_OK=" + (key != null && key.length == 32));
    }

    public static synchronized void beforeKdf(byte[] submitted) {
        final int slot = derived;
        derived++;
        boolean matches = slot < 2 && reference[slot] != null
            && submitted != null && submitted.length == 32
            && MessageDigest.isEqual(reference[slot], submitted);
        if (!matches) mismatches++;
        System.out.println("AGENT_DERIVE_INDEX=" + derived);
        System.out.println("AGENT_KDF_INPUT_MATCH=" + matches);
        if (!matches && "ENFORCE".equals(MODE)) {
            blocks++;
            System.out.println("AGENT_BLOCK_EVENT=true");
            System.out.flush();
            throw new SecurityException("D215_BLOCKED_UNBOUND_KDF");
        }
    }

    public static synchronized void beforeRecord() {
        // Single-session controlled model: exactly two KEM extractions
        // and two KDF entries are required before processing a record.
        // Unknown or uninstrumented KDF paths are NOT silently allowed.
        final boolean coverageReady = captured == 2 && derived == 2
            && transforms == 2;
        final boolean verified = coverageReady && mismatches == 0;
        if (!coverageReady) {
            coverageGaps++;
            System.out.println("AGENT_COVERAGE_GAP=true");
        }
        System.out.println("AGENT_RECORD_GATE=" + (verified ? "ALLOW" : "DENY"));
        if (!verified && "ENFORCE".equals(MODE)) {
            blocks++;
            if (!coverageReady) {
                coverageBlocks++;
                System.out.println("AGENT_COVERAGE_BLOCK_EVENT=true");
            }
            System.out.println("AGENT_BLOCK_EVENT=true");
            System.out.flush();
            throw new SecurityException(coverageReady
                ? "D215_BLOCKED_KDF_MISMATCH" : "D215_BLOCKED_KDF_COVERAGE");
        }
        records++;
        System.out.println("AGENT_RECORD_EVENT=true");
    }

    private static synchronized void summarize() {
        if (closed) return;
        closed = true;
        System.out.println("AGENT_SUMMARY_TRANSFORMS=" + transforms);
        System.out.println("AGENT_SUMMARY_CAPTURES=" + captured);
        System.out.println("AGENT_SUMMARY_DERIVES=" + derived);
        System.out.println("AGENT_SUMMARY_MISMATCHES=" + mismatches);
        System.out.println("AGENT_SUMMARY_RECORDS=" + records);
        System.out.println("AGENT_SUMMARY_BLOCKS=" + blocks);
        System.out.println("AGENT_SUMMARY_COVERAGE_GAPS=" + coverageGaps);
        System.out.println("AGENT_SUMMARY_COVERAGE_BLOCKS=" + coverageBlocks);
        System.out.println("AGENT_SUMMARY_END=true");
        for (int i=0;i<reference.length;i++) {
            if (reference[i] != null) Arrays.fill(reference[i], (byte)0);
            reference[i] = null;
        }
    }
}
