import java.util.Arrays;

/** Deliberately uninstrumented alternate entry point, byte-for-byte algorithm equivalent
 * to KdfBindingExperiment.derive for this controlled research experiment.
 * Not a standardized or deployment-ready KDF implementation.
 */
final class AlternateKdf {
    private AlternateKdf() {}

    static KdfBindingExperiment.Session derive(byte[] x, byte[] kem, byte[] transcript)
        throws Exception {
        byte[] ikm = KdfBindingExperiment.frame(x, kem == null ? new byte[0] : kem);
        byte[] salt = KdfBindingExperiment.sha(KdfBindingExperiment.frame(
            KdfBindingExperiment.str("D2-10-EXTRACT-SALT"), transcript));
        byte[] prk = KdfBindingExperiment.hmac(salt, ikm);
        byte[] info = KdfBindingExperiment.frame(
            KdfBindingExperiment.str("D2-10-SESSION"), transcript);
        byte[] t1 = KdfBindingExperiment.hmac(prk,
            KdfBindingExperiment.concat(info, new byte[]{1}));
        byte[] t2 = KdfBindingExperiment.hmac(prk,
            KdfBindingExperiment.concat(t1, info, new byte[]{2}));
        KdfBindingExperiment.Session result =
            new KdfBindingExperiment.Session(t1.clone(), t2.clone());
        for (byte[] item : new byte[][]{ikm, salt, prk, t1, t2})
            Arrays.fill(item, (byte) 0);
        return result;
    }
}
