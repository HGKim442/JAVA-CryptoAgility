import java.nio.file.*;
import java.io.PrintWriter;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.*;

/** Fixture hybrid combiner, not RFC HPKE nor a production hybrid protocol. Synthetic data only. */
public final class PqcDowngradeExperiment {
    static final Provider BC=new BouncyCastleProvider(),SUN=Security.getProvider("SunJCE"),EC=Security.getProvider("SunEC");
    record Outcome(String suite,boolean roundtrip,String failure) {}
    static final class PolicyReject extends GeneralSecurityException {
        private static final long serialVersionUID=1L;
        PolicyReject(String m){super(m);}
    }
    // Entry-only allowlist approves components, including classical X25519 for hybrid use.
    // It does not express the policy requiring BOTH approved components in the final suite.
    static void componentGate(String mode,String algorithm,Provider provider)throws PolicyReject {
        if(mode.equals("VULNERABLE"))return;
        if(!((algorithm.equals("X25519")&&provider==EC)||(algorithm.equals("ML-KEM")&&provider==BC)))
            throw new PolicyReject("component_not_approved");
    }
    static byte[] classical()throws Exception {
        KeyPairGenerator g=KeyPairGenerator.getInstance("X25519",EC);KeyPair a=g.generateKeyPair(),b=g.generateKeyPair();
        KeyAgreement x=KeyAgreement.getInstance("X25519",EC);x.init(a.getPrivate());x.doPhase(b.getPublic(),true);byte[] left=x.generateSecret();
        x.init(b.getPrivate());x.doPhase(a.getPublic(),true);byte[] right=x.generateSecret();
        try{if(!MessageDigest.isEqual(left,right))throw new GeneralSecurityException("X25519 control mismatch");return left;}finally{Arrays.fill(right,(byte)0);}
    }
    static byte[] pqc(int failure)throws Exception {
        // No fake algorithm/parameter names: reproduce real deployment selection failures.
        // 1: BC is on the classpath but absent from the runtime provider registry.
        // 2: a deployment pins the existing SunEC provider, which lacks ML-KEM.
        KeyPairGenerator g;
        if(failure==1) {
            Provider saved=Security.getProvider("BC");
            if(saved!=null)throw new IllegalStateException("fixture requires unregistered BC");
            g=KeyPairGenerator.getInstance("ML-KEM","BC");
        } else if(failure==2)g=KeyPairGenerator.getInstance("ML-KEM",EC);
        else g=KeyPairGenerator.getInstance("ML-KEM",BC);
        g.initialize(MLKEMParameterSpec.ml_kem_768);
        KeyPair pair=g.generateKeyPair();KeyGenerator kem=KeyGenerator.getInstance("ML-KEM",BC);
        kem.init(new KEMGenerateSpec.Builder(pair.getPublic(),"Generic",256).withNoKdf().build());
        SecretKeyWithEncapsulation generated=(SecretKeyWithEncapsulation)kem.generateKey();byte[] left=generated.getEncoded();
        kem.init(new KEMExtractSpec.Builder(pair.getPrivate(),generated.getEncapsulation(),"Generic",256).withNoKdf().build());byte[] right=kem.generateKey().getEncoded();
        try{if(!MessageDigest.isEqual(left,right))throw new GeneralSecurityException("ML-KEM control mismatch");return left;}finally{Arrays.fill(right,(byte)0);}
    }
    static Outcome execute(String mode,int failure)throws Exception {
        componentGate(mode,"X25519",EC);
        componentGate(mode,"ML-KEM",BC);
        byte[] x=classical(),pq=null,key=null;String failed="none";
        try {
            try{pq=pqc(failure);}catch(GeneralSecurityException e){failed=e.getClass().getSimpleName();if(mode.equals("PROPOSED"))throw new PolicyReject(failed);}
            // The fallback component passes the entry allowlist independently. This is
            // why ALLOWLIST can reject unapproved inputs but still miss suite downgrade.
            if(pq==null)componentGate(mode,"X25519",EC);
            String suite=pq==null?"X25519_ONLY":"MLKEM768_X25519";
            Mac derive=Mac.getInstance("HmacSHA256",SUN);derive.init(new SecretKeySpec(new byte[32],"HmacSHA256"));derive.update("E2-FIXTURE-COMBINER-v1".getBytes(java.nio.charset.StandardCharsets.US_ASCII));derive.update(x);if(pq!=null)derive.update(pq);key=derive.doFinal();
            byte[] nonce=new byte[12];new SecureRandom().nextBytes(nonce);byte[] plain={1,2,3,4},aad="policy:PQC_REQUIRED|v2".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            Cipher c=Cipher.getInstance("AES/GCM/NoPadding",SUN);c.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,nonce));c.updateAAD(aad);byte[] ct=c.doFinal(plain);
            c.init(Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,nonce));c.updateAAD(aad);return new Outcome(suite,Arrays.equals(plain,c.doFinal(ct)),failed);
        }finally{Arrays.fill(x,(byte)0);if(pq!=null)Arrays.fill(pq,(byte)0);if(key!=null)Arrays.fill(key,(byte)0);}
    }
    public static void main(String[] args)throws Exception {
        Path output=Path.of(args[0]);Files.createDirectories(output);int fork=Integer.parseInt(args[1]);
        if(Security.getProvider("BC")!=null)throw new IllegalStateException("BC unexpectedly registered");
        // Negative control exercises the actual allowlist independently of attack outcomes.
        boolean vulnerableAccepts=true,allowlistRejects=false;
        componentGate("VULNERABLE","DH",EC);
        try{componentGate("ALLOWLIST","DH",EC);}catch(PolicyReject expected){allowlistRejects=true;}
        if(!allowlistRejects)throw new IllegalStateException("allowlist negative control failed");
        Files.writeString(output.resolve("allowlist-control.json"),
            "{\"unapproved_component\":\"DH\",\"vulnerable_accepts\":"+vulnerableAccepts+",\"allowlist_rejects\":"+allowlistRejects+"}\n");
        try(PrintWriter csv=new PrintWriter(Files.newBufferedWriter(output.resolve("pqc-downgrade.csv")))) {
            csv.println("fork,mode,failure_variant,normal_hybrid_success,observed_suite,roundtrip,downgrade_effect,outcome,error");
            for(String mode:List.of("VULNERABLE","ALLOWLIST","PROPOSED"))for(int failure=1;failure<=2;failure++) {
                Outcome normal=execute(mode,0);boolean control=normal.roundtrip && normal.suite.equals("MLKEM768_X25519");
                try{Outcome attacked=execute(mode,failure);csv.printf("%d,%s,%d,%s,%s,%s,%s,OBSERVED,%s%n",fork,mode,failure,control,attacked.suite,attacked.roundtrip,attacked.suite.equals("X25519_ONLY")&&attacked.roundtrip,attacked.failure);}
                catch(PolicyReject e){csv.printf("%d,%s,%d,%s,NONE,false,false,POLICY_REJECTION,%s%n",fork,mode,failure,control,e.getMessage());}
                catch(Exception e){csv.printf("%d,%s,%d,%s,UNKNOWN,false,unknown,INDETERMINATE,%s%n",fork,mode,failure,control,e.getClass().getSimpleName());}
            }
            if(csv.checkError())throw new java.io.IOException("Raw CSV write failed");
        }
        System.out.println("COLLECTED PQC downgrade observations fork="+fork+" rows=6");
    }
}
