import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.NamedParameterSpec;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/** Standalone synthetic policy fixture; identical Java 17 source runs on both JDKs. */
public final class JdkPqcMigrationProbe {
    static final class PolicyReject extends GeneralSecurityException {
        private static final long serialVersionUID=1L;
        PolicyReject(String reason){super(reason);}
    }
    static void gate(String mode,String component)throws PolicyReject {
        if(!mode.equals("VULNERABLE")&&!Set.of("ML-KEM","X25519").contains(component))
            throw new PolicyReject("unapproved_component");
    }
    static byte[] x25519()throws GeneralSecurityException {
        KeyPairGenerator g=KeyPairGenerator.getInstance("X25519","SunEC");
        KeyPair a=g.generateKeyPair(),b=g.generateKeyPair();
        KeyAgreement k=KeyAgreement.getInstance("X25519","SunEC");
        k.init(a.getPrivate());k.doPhase(b.getPublic(),true);byte[] left=k.generateSecret();
        k.init(b.getPrivate());k.doPhase(a.getPublic(),true);byte[] right=k.generateSecret();
        try{if(!MessageDigest.isEqual(left,right))throw new IllegalStateException("X25519 control mismatch");return left;}
        finally{Arrays.fill(right,(byte)0);}
    }
    static byte[] nativeMlKem()throws Exception {
        // Pin the JDK backend, excluding BC registry/classpath differences from this comparison.
        KeyPairGenerator g=KeyPairGenerator.getInstance("ML-KEM","SunJCE");
        g.initialize(new NamedParameterSpec("ML-KEM-768"));KeyPair pair=g.generateKeyPair();
        Class<?> kemClass=Class.forName("javax.crypto.KEM");
        Object kem=kemClass.getMethod("getInstance",String.class,String.class).invoke(null,"ML-KEM","SunJCE");
        Object encoder=kemClass.getMethod("newEncapsulator",PublicKey.class).invoke(kem,pair.getPublic());
        Object encapsulated=Class.forName("javax.crypto.KEM$Encapsulator").getMethod("encapsulate").invoke(encoder);
        Class<?> resultClass=Class.forName("javax.crypto.KEM$Encapsulated");
        byte[] left=((SecretKey)resultClass.getMethod("key").invoke(encapsulated)).getEncoded();
        byte[] ct=(byte[])resultClass.getMethod("encapsulation").invoke(encapsulated);
        Object decoder=kemClass.getMethod("newDecapsulator",PrivateKey.class).invoke(kem,pair.getPrivate());
        byte[] right=((SecretKey)Class.forName("javax.crypto.KEM$Decapsulator")
            .getMethod("decapsulate",byte[].class).invoke(decoder,(Object)ct)).getEncoded();
        try{if(!MessageDigest.isEqual(left,right))throw new IllegalStateException("ML-KEM control mismatch");return left;}
        finally{Arrays.fill(right,(byte)0);Arrays.fill(ct,(byte)0);}
    }
    static String quoted(String value){return "\""+value.replace("\\","\\\\").replace("\"","\\\"").replace("\n","\\n").replace("\r","\\r").replace("\t","\\t")+"\"";}
    static void row(String mode,String outcome,String suite,boolean roundtrip,String effect,String error) {
        System.out.println("{\"mode\":"+quoted(mode)+",\"outcome\":"+quoted(outcome)+",\"suite\":"+quoted(suite)
            +",\"roundtrip\":"+roundtrip+",\"downgrade_effect\":"+quoted(effect)+",\"error\":"+quoted(error)
            +",\"java_runtime\":"+quoted(System.getProperty("java.runtime.version"))+",\"java_vendor\":"+quoted(System.getProperty("java.vendor"))
            +",\"os\":"+quoted(System.getProperty("os.name"))+",\"arch\":"+quoted(System.getProperty("os.arch"))+"}");
    }
    static void execute(String mode)throws Exception {
        gate(mode,"X25519");gate(mode,"ML-KEM");byte[] x=x25519(),pq=null,key=null;String error="none";
        try {
            try{pq=nativeMlKem();}
            catch(NoSuchAlgorithmException|NoSuchProviderException|InvalidAlgorithmParameterException|ClassNotFoundException e){
                error=e.getClass().getSimpleName();if(mode.equals("PROPOSED"))throw new PolicyReject(error);
            }
            if(pq==null)gate(mode,"X25519");
            Mac mac=Mac.getInstance("HmacSHA256","SunJCE");mac.init(new SecretKeySpec(new byte[32],"HmacSHA256"));
            mac.update("JDK-MIGRATION-SYNTHETIC-COMBINER-v1".getBytes(StandardCharsets.US_ASCII));mac.update(x);if(pq!=null)mac.update(pq);key=mac.doFinal();
            byte[] nonce=new byte[12];new SecureRandom().nextBytes(nonce);byte[] plain={1,2,3,4};
            byte[] aad="PQC_REQUIRED=true".getBytes(StandardCharsets.US_ASCII);
            Cipher c=Cipher.getInstance("AES/GCM/NoPadding","SunJCE");
            c.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,nonce));c.updateAAD(aad);byte[] ct=c.doFinal(plain);
            c.init(Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,nonce));c.updateAAD(aad);
            boolean ok=Arrays.equals(plain,c.doFinal(ct));if(!ok)throw new IllegalStateException("AEAD control mismatch");
            row(mode,"OBSERVED",pq==null?"X25519_ONLY":"MLKEM768_X25519",ok,String.valueOf(pq==null),error);
        }finally{Arrays.fill(x,(byte)0);if(pq!=null)Arrays.fill(pq,(byte)0);if(key!=null)Arrays.fill(key,(byte)0);}
    }
    public static void main(String[] args) {
        for(String mode:List.of("VULNERABLE","ALLOWLIST","PROPOSED")) {
            try{execute(mode);}
            catch(PolicyReject e){row(mode,"POLICY_REJECTION","NONE",false,"false",e.getMessage());}
            catch(Exception e){Throwable cause=e instanceof InvocationTargetException?e.getCause():e;
                row(mode,"INDETERMINATE","UNKNOWN",false,"unknown",cause.getClass().getSimpleName());}
        }
        if(System.out.checkError())throw new IllegalStateException("Observation output failed");
    }
}
