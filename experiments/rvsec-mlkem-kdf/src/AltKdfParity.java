import java.security.MessageDigest;
import java.util.Arrays;

public final class AltKdfParity {
    public static void main(String[] ignored) throws Exception {
        byte[] x = new byte[32], kem = new byte[32], transcript = new byte[32];
        for (int i=0;i<32;i++) { x[i] = (byte)(i+1); kem[i] = (byte)(i+37);
            transcript[i] = (byte)(255-i); }
        KdfBindingExperiment.Session a = KdfBindingExperiment.derive(x, kem, transcript);
        KdfBindingExperiment.Session b = AlternateKdf.derive(x, kem, transcript);
        boolean match = MessageDigest.isEqual(a.enc,b.enc)
            && MessageDigest.isEqual(a.confirm,b.confirm);
        a.clear(); b.clear();
        Arrays.fill(x,(byte)0); Arrays.fill(kem,(byte)0);
        Arrays.fill(transcript,(byte)0);
        System.out.println("ALTERNATE_KDF_PARITY=" + match);
        if (!match) throw new IllegalStateException("Alternate KDF mismatch");
    }
}
