import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.interfaces.*;
import org.bouncycastle.jcajce.spec.*;

/** Approved real JCA/JCE PQC execution; no classical algorithm fallback. */
public final class PqcExtension {
    private static final Provider BC=new BouncyCastleProvider(),SUN=Objects.requireNonNull(Security.getProvider("SunJCE"));
    private static final SecureRandom RNG=new SecureRandom();
    static final java.util.concurrent.atomic.AtomicInteger assertions=new java.util.concurrent.atomic.AtomicInteger(),backendCalls=new java.util.concurrent.atomic.AtomicInteger();static volatile int sink;
    public record Profile(long policyVersion,long keyVersion,String kem,String signature,int category,String provider,boolean pqcRequired) {}
    record Snapshot(Profile profile,String context) {}
    record Decision(boolean allowed,String reason) {}
    static final Profile P3=new Profile(1,1,"ML-KEM-768","ML-DSA-65",3,"BC",true),P5=new Profile(2,2,"ML-KEM-1024","ML-DSA-87",5,"BC",true);
    static final String CONTEXT="tenant-A/document-1";
    private record Keys(KeyPair kem,KeyPair signature) {}
    private record Capsule(byte[] ciphertext,byte[] secret) implements AutoCloseable{public void close(){wipe(secret);}}
    static void wipe(byte[]... arrays){for(byte[] a:arrays)if(a!=null)Arrays.fill(a,(byte)0);}
    static void require(boolean ok,String label){assertions.incrementAndGet();if(!ok)throw new AssertionError(label);}
    static boolean listed(Profile p){return p!=null && p.policyVersion>0 && p.keyVersion>0 && "BC".equals(p.provider) && p.pqcRequired && ("ML-KEM-768".equals(p.kem) && "ML-DSA-65".equals(p.signature) && p.category==3 || "ML-KEM-1024".equals(p.kem) && "ML-DSA-87".equals(p.signature) && p.category==5);}
    static Decision authorize(Snapshot s,Profile execution,String context,boolean available,boolean failed){
        if(s==null || s.profile==null || s.context==null || execution==null || context==null || !s.profile.pqcRequired || !listed(s.profile))return new Decision(false,"invalid approved PQC snapshot");
        if(!available || failed)return new Decision(false,"PQC dependency unavailable or failed; no fallback");
        if(!listed(execution))return new Decision(false,"unapproved PQC family/parameters/provider/requirement");
        if(!s.profile.equals(execution))return new Decision(false,"execution differs from immutable approved profile/key version");
        if(!s.context.equals(context))return new Decision(false,"request context mismatch");
        return new Decision(true,"approved PQC snapshot");
    }
    static void permit(Snapshot s,Profile p,String context){if(!authorize(s,p,context,true,false).allowed)throw new SecurityException("PQC policy rejected");}
    private static MLKEMParameterSpec kemSpec(Profile p){return "ML-KEM-768".equals(p.kem)?MLKEMParameterSpec.ml_kem_768:MLKEMParameterSpec.ml_kem_1024;}
    private static MLDSAParameterSpec sigSpec(Profile p){return "ML-DSA-65".equals(p.signature)?MLDSAParameterSpec.ml_dsa_65:MLDSAParameterSpec.ml_dsa_87;}
    private static void checkKey(Profile p,Keys keys){
        require(keys.kem.getPublic() instanceof MLKEMKey && keys.kem.getPrivate() instanceof MLKEMKey,"actual ML-KEM key types");
        require(keys.signature.getPublic() instanceof MLDSAKey && keys.signature.getPrivate() instanceof MLDSAKey,"actual ML-DSA key types");
        require(((MLKEMKey)keys.kem.getPublic()).getParameterSpec().getName().equals(kemSpec(p).getName()) && ((MLKEMKey)keys.kem.getPrivate()).getParameterSpec().getName().equals(kemSpec(p).getName()),"actual ML-KEM parameter set");
        require(((MLDSAKey)keys.signature.getPublic()).getParameterSpec().getName().equals(sigSpec(p).getName()) && ((MLDSAKey)keys.signature.getPrivate()).getParameterSpec().getName().equals(sigSpec(p).getName()),"actual ML-DSA parameter set");
    }
    private static KeyPair kemKeys(Profile p)throws Exception {
        backendCalls.incrementAndGet();KeyPairGenerator k=KeyPairGenerator.getInstance("ML-KEM",BC);require(k.getProvider()==BC,"KEM keygen provider");k.initialize(kemSpec(p),RNG);return k.generateKeyPair();
    }
    private static KeyPair signatureKeys(Profile p)throws Exception {
        backendCalls.incrementAndGet();KeyPairGenerator k=KeyPairGenerator.getInstance("ML-DSA",BC);require(k.getProvider()==BC,"signature keygen provider");k.initialize(sigSpec(p),RNG);return k.generateKeyPair();
    }
    private static Keys generate(Snapshot s)throws Exception {permit(s,s.profile,s.context);Keys k=new Keys(kemKeys(s.profile),signatureKeys(s.profile));checkKey(s.profile,k);return k;}
    private static Capsule encapsulate(Profile p,PublicKey pub)throws Exception {
        require(((MLKEMKey)pub).getParameterSpec().getName().equals(kemSpec(p).getName()),"encapsulation key matches selected parameters");
        backendCalls.incrementAndGet();KeyGenerator k=KeyGenerator.getInstance("ML-KEM",BC);require(k.getProvider()==BC,"encapsulation provider");
        k.init(new KEMGenerateSpec.Builder(pub,"Generic",256).withNoKdf().build(),RNG);
        SecretKeyWithEncapsulation generated=(SecretKeyWithEncapsulation)k.generateKey();byte[] secret=checkedSharedSecret(generated.getEncoded());boolean transferred=false;
        try{Capsule capsule=new Capsule(generated.getEncapsulation(),secret);transferred=true;return capsule;}finally{if(!transferred)wipe(secret);}
    }
    private static byte[] decapsulate(Profile p,PrivateKey priv,byte[] encapsulation)throws Exception {
        require(((MLKEMKey)priv).getParameterSpec().getName().equals(kemSpec(p).getName()),"decapsulation key matches selected parameters");
        backendCalls.incrementAndGet();KeyGenerator k=KeyGenerator.getInstance("ML-KEM",BC);require(k.getProvider()==BC,"decapsulation provider");
        k.init(new KEMExtractSpec.Builder(priv,encapsulation,"Generic",256).withNoKdf().build());return checkedSharedSecret(k.generateKey().getEncoded());
    }
    static byte[] checkedSharedSecret(byte[] secret)throws GeneralSecurityException {
        if(secret==null || secret.length!=32){wipe(secret);throw new GeneralSecurityException("Raw ML-KEM shared secret must be 32 bytes");}return secret;
    }
    private static byte[] binding(Snapshot s){Profile p=s.profile;return ("JCA-PQC-RESEARCH-v2|"+p.policyVersion+"|"+p.keyVersion+"|"+p.kem+"|"+p.signature+"|"+p.category+"|"+p.provider+"|"+s.context).getBytes(StandardCharsets.UTF_8);}
    private static byte[] derive(byte[] raw,byte[] salt,byte[] context)throws Exception {
        Mac m=Mac.getInstance("HmacSHA256",SUN);m.init(new SecretKeySpec(salt,"HmacSHA256"));byte[] prk=m.doFinal(raw);
        try{m.init(new SecretKeySpec(prk,"HmacSHA256"));m.update(context);m.update((byte)1);return m.doFinal();}finally{wipe(prk);}
    }
    private static byte[] crypt(boolean encrypt,byte[] key,byte[] nonce,byte[] aad,byte[] input)throws Exception {
        backendCalls.incrementAndGet();Cipher c=Cipher.getInstance("AES/GCM/NoPadding",SUN);require(c.getProvider()==SUN,"symmetric provider");c.init(encrypt?Cipher.ENCRYPT_MODE:Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,nonce));c.updateAAD(aad);return c.doFinal(input);
    }
    private static byte[] sign(Snapshot s,PrivateKey key,byte[] message)throws Exception {
        require(((MLDSAKey)key).getParameterSpec().getName().equals(sigSpec(s.profile).getName()),"signing key matches snapshot");
        backendCalls.incrementAndGet();Signature sig=Signature.getInstance("ML-DSA",BC);require(sig.getProvider()==BC,"sign provider");sig.setParameter(new ContextParameterSpec(binding(s)));sig.initSign(key,RNG);sig.update(message);return sig.sign();
    }
    private static boolean verify(Snapshot s,PublicKey key,byte[] message,byte[] signature)throws Exception {
        require(((MLDSAKey)key).getParameterSpec().getName().equals(sigSpec(s.profile).getName()),"verification key matches snapshot");
        backendCalls.incrementAndGet();Signature sig=Signature.getInstance("ML-DSA",BC);require(sig.getProvider()==BC,"verify provider");sig.setParameter(new ContextParameterSpec(binding(s)));sig.initVerify(key);sig.update(message);return sig.verify(signature);
    }
    static void policyTests(Path out)throws Exception {
        StringBuilder csv=new StringBuilder("approved_profile,case,rejected,backend_invocations,reason\n");
        for(Profile p:List.of(P3,P5)){
            Snapshot s=new Snapshot(p,CONTEXT);
            List<Profile> candidates=List.of(
                new Profile(p.policyVersion,p.keyVersion,"X25519",p.signature,p.category,p.provider,true),
                new Profile(p.policyVersion,p.keyVersion,p.kem,"Ed25519",p.category,p.provider,true),
                new Profile(p.policyVersion,p.keyVersion,"ML-KEM-512","ML-DSA-44",1,p.provider,true),
                new Profile(p.policyVersion,p.keyVersion,p.kem,p.signature,p.category,"UNTRUSTED",true),
                new Profile(p.policyVersion,p.keyVersion,p.kem,p.signature,p.category,p.provider,false),
                new Profile(p.policyVersion+1,p.keyVersion,p.kem,p.signature,p.category,p.provider,true),
                new Profile(p.policyVersion,p.keyVersion+1,p.kem,p.signature,p.category,p.provider,true),
                new Profile(p.policyVersion,p.keyVersion,p==P3?P5.kem:P3.kem,p==P3?P5.signature:P3.signature,p==P3?5:3,p.provider,true));
            List<String> names=List.of("classical_kem","classical_signature","unapproved_lower_parameters","unapproved_provider","pqc_requirement_disabled","policy_version_mismatch","key_version_mismatch","listed_but_snapshot_parameter_mismatch");
            for(int i=0;i<candidates.size();i++){
                int before=backendCalls.get();Decision d=authorize(s,candidates.get(i),CONTEXT,true,false);require(!d.allowed && backendCalls.get()==before,"preexecution negative candidate");
                try{permit(s,candidates.get(i),CONTEXT);throw new AssertionError("Dispatcher accepted rejected candidate");}catch(SecurityException expected){require(backendCalls.get()==before,"no backend called on refusal");}
                csv.append(p.kem).append('+').append(p.signature).append(',').append(names.get(i)).append(",true,0,").append(d.reason).append('\n');
            }
            for(String name:List.of("dependency_unavailable","implementation_failure","context_mismatch")){
                int before=backendCalls.get();Decision d=authorize(s,p,name.equals("context_mismatch")?"tenant-B/document-1":CONTEXT,!name.equals("dependency_unavailable"),name.equals("implementation_failure"));
                require(!d.allowed && backendCalls.get()==before,"dependency/context fails closed");csv.append(p.kem).append('+').append(p.signature).append(',').append(name).append(",true,0,").append(d.reason).append('\n');
            }
            require(authorize(s,p,CONTEXT,true,false).allowed,"approved profile succeeds");
        }
        Files.writeString(out.resolve("pqc-policy.csv"),csv);
    }
    static void functional(Path out)throws Exception {
        StringBuilder csv=new StringBuilder("profile,iteration,kem_secret_match,aead_roundtrip,signature_valid,wrong_context_rejected,changed_message_rejected,changed_encapsulation_aead_rejected,kem_ciphertext_bytes,signature_bytes\n");
        List<Snapshot> history=new ArrayList<>();List<Keys> keyHistory=new ArrayList<>();List<byte[]> signatures=new ArrayList<>();byte[] message="PQC policy transition continuity".getBytes(StandardCharsets.UTF_8);
        for(Profile p:List.of(P3,P5)){
            Snapshot s=new Snapshot(p,CONTEXT);Keys keys=generate(s);history.add(s);keyHistory.add(keys);signatures.add(sign(s,keys.signature.getPrivate(),message));
            for(int i=0;i<20;i++){
                permit(s,p,CONTEXT);byte[] plain=new byte[4096],salt=new byte[32],nonce=new byte[12];RNG.nextBytes(plain);RNG.nextBytes(salt);RNG.nextBytes(nonce);
                byte[] extracted=null,k1=null,k2=null,ct=null,restored=null,signature=null,badSecret=null,badKey=null;
                try(Capsule enc=encapsulate(p,keys.kem.getPublic())){
                    extracted=decapsulate(p,keys.kem.getPrivate(),enc.ciphertext);require(MessageDigest.isEqual(enc.secret,extracted),"KEM shared key agreement");
                    byte[] aad=binding(s);k1=derive(enc.secret,salt,aad);k2=derive(extracted,salt,aad);ct=crypt(true,k1,nonce,aad,plain);restored=crypt(false,k2,nonce,aad,ct);require(Arrays.equals(plain,restored),"KEM derived AES roundtrip");
                    signature=sign(s,keys.signature.getPrivate(),plain);require(verify(s,keys.signature.getPublic(),plain,signature),"valid ML-DSA signature");
                    Snapshot wrong=new Snapshot(p,"tenant-B/document-1");require(!verify(wrong,keys.signature.getPublic(),plain,signature),"wrong ML-DSA context rejected");
                    byte[] changed=plain.clone();changed[0]^=1;require(!verify(s,keys.signature.getPublic(),changed,signature),"changed message rejected");wipe(changed);
                    byte[] altered=enc.ciphertext.clone();altered[0]^=1;badSecret=decapsulate(p,keys.kem.getPrivate(),altered);require(!MessageDigest.isEqual(enc.secret,badSecret),"invalid encapsulation produces different secret, not authenticated plaintext");badKey=derive(badSecret,salt,aad);
                    boolean returned=false;try{byte[] invalid=crypt(false,badKey,nonce,aad,ct);returned=true;wipe(invalid);throw new AssertionError("Changed encapsulation accepted");}catch(AEADBadTagException expected){require(!returned,"changed encapsulation rejected downstream before plaintext return");}
                    try{byte[] invalid=crypt(false,k2,nonce,binding(wrong),ct);wipe(invalid);throw new AssertionError("Wrong AAD accepted");}catch(AEADBadTagException expected){require(true,"AES AAD rejection");}
                    csv.append(p.kem).append('+').append(p.signature).append(',').append(i).append(",true,true,true,true,true,true,").append(enc.ciphertext.length).append(',').append(signature.length).append('\n');
                }finally{wipe(plain,salt,extracted,k1,k2,ct,restored,signature,badSecret,badKey);}
            }
        }
        // Retain original snapshots/public keys: switching current signing policy must not relabel history.
        Snapshot current=history.get(1);require(current.profile.equals(P5) && history.get(0).profile.equals(P3),"immutable snapshot continuity");
        for(int i=0;i<history.size();i++)require(verify(history.get(i),keyHistory.get(i).signature.getPublic(),message,signatures.get(i)),"previous/new signature still verifies under original profile");
        // Decrypt old/new KEM-derived payloads after the current approved profile has advanced.
        List<byte[]> ctHistory=new ArrayList<>(),encHistory=new ArrayList<>(),salts=new ArrayList<>(),nonces=new ArrayList<>();
        try{
            for(int i=0;i<history.size();i++){
                Snapshot original=history.get(i);byte[] salt=new byte[32],nonce=new byte[12];RNG.nextBytes(salt);RNG.nextBytes(nonce);salts.add(salt);nonces.add(nonce);
                try(Capsule capsule=encapsulate(original.profile,keyHistory.get(i).kem.getPublic())){
                    encHistory.add(capsule.ciphertext.clone());byte[] derived=derive(capsule.secret,salt,binding(original));
                    try{ctHistory.add(crypt(true,derived,nonce,binding(original),message));}finally{wipe(derived);}
                }
            }
            for(int i=0;i<history.size();i++){
                Snapshot original=history.get(i);byte[] raw=decapsulate(original.profile,keyHistory.get(i).kem.getPrivate(),encHistory.get(i)),derived=null,restored=null;
                try{derived=derive(raw,salts.get(i),binding(original));restored=crypt(false,derived,nonces.get(i),binding(original),ctHistory.get(i));require(Arrays.equals(restored,message),"original/new encrypted payload readable after approved profile transition");}
                finally{wipe(raw,derived,restored);}
            }
        }finally{for(List<byte[]> list:List.of(ctHistory,encHistory,salts,nonces))for(byte[] a:list)wipe(a);}
        wipe(message);for(byte[] signature:signatures)wipe(signature);
        Files.writeString(out.resolve("pqc-functional.csv"),csv);
    }
    @FunctionalInterface interface Operation{byte[] run()throws Exception;}
    static void measure(StringBuilder csv,String profile,String component,Operation op)throws Exception {
        var bean=(com.sun.management.ThreadMXBean)java.lang.management.ManagementFactory.getThreadMXBean();if(!bean.isThreadAllocatedMemorySupported())throw new IllegalStateException("allocation unsupported");bean.setThreadAllocatedMemoryEnabled(true);long thread=Thread.currentThread().getId();
        long[] times=new long[101],allocated=new long[101];
        for(int i=-100;i<101;i++){
            long before=bean.getThreadAllocatedBytes(thread),start=System.nanoTime();byte[] result=op.run();long ns=System.nanoTime()-start,bytes=bean.getThreadAllocatedBytes(thread)-before;
            sink=result.length;if(i>=0){times[i]=ns;allocated[i]=bytes;}wipe(result);
        }
        for(int i=0;i<101;i++)csv.append(profile).append(',').append(component).append(',').append(i).append(',').append(times[i]).append(',').append(allocated[i]).append('\n');
    }
    static void benchmark(Path out,int offset)throws Exception {
        StringBuilder csv=new StringBuilder("profile,component,sample,ns,thread_allocated_bytes\n");List<Profile> profiles=offset%2==0?List.of(P3,P5):List.of(P5,P3);
        for(Profile p:profiles){Snapshot s=new Snapshot(p,CONTEXT);Keys keys=generate(s);byte[] message=new byte[4096];RNG.nextBytes(message);byte[] signature=sign(s,keys.signature.getPrivate(),message);
            try(Capsule capsule=encapsulate(p,keys.kem.getPublic())){
                measure(csv,p.kem,"keygen_public_encoding",()->kemKeys(p).getPublic().getEncoded());
                measure(csv,p.kem,"encapsulate",()->{try(Capsule e=encapsulate(p,keys.kem.getPublic())){return e.secret.clone();}});
                measure(csv,p.kem,"decapsulate",()->decapsulate(p,keys.kem.getPrivate(),capsule.ciphertext));
                measure(csv,p.signature,"keygen_public_encoding",()->signatureKeys(p).getPublic().getEncoded());
                measure(csv,p.signature,"sign_4096",()->sign(s,keys.signature.getPrivate(),message));
                measure(csv,p.signature,"verify_4096",()->{if(!verify(s,keys.signature.getPublic(),message,signature))throw new AssertionError("benchmark verification failed");return new byte[0];});
            }finally{wipe(message,signature);}
        }
        Files.writeString(out.resolve("pqc-cost.csv"),csv);
    }
    /** Only an Engine can create this request; it owns validated keys and fixed context. */
    public static final class Prepared {
        private final Engine owner;private final State state;private final boolean readOnly;
        private final java.util.concurrent.atomic.AtomicBoolean used=new java.util.concurrent.atomic.AtomicBoolean();
        private Prepared(Engine owner,State state){this(owner,state,false);}
        private Prepared(Engine owner,State state,boolean readOnly){this.owner=owner;this.state=state;this.readOnly=readOnly;}
    }
    private static final class State {
        volatile boolean retired;final Snapshot snapshot;final Keys keys;final byte[] bound;final NonceReservations cursor;final byte[] prefix;final String fingerprint;
        State(Snapshot snapshot,Keys keys,byte[] bound,NonceReservations cursor,String fingerprint){this.snapshot=snapshot;this.keys=keys;this.bound=bound;this.cursor=cursor;this.prefix=Arrays.copyOf(bound,4);this.fingerprint=fingerprint;}
    }
    public static final class Packet {
        private static final int[] MIN={32,1088,32,12,16,3309},MAX={32,1568,32,12,16*1024*1024+16,4627};
        private final byte[] bound,encapsulation,salt,nonce,ciphertext,signature;
        private Packet(byte[] bound,byte[] encapsulation,byte[] salt,byte[] nonce,byte[] ciphertext,byte[] signature){this.bound=bound;this.encapsulation=encapsulation;this.salt=salt;this.nonce=nonce;this.ciphertext=ciphertext;this.signature=signature;}
        public byte[] encode()throws java.io.IOException {
            // Private packet arrays have fixed lengths. Allocate the exact wire length once.
            int length=28+bound.length+encapsulation.length+salt.length+nonce.length+ciphertext.length+signature.length;
            ByteBuffer out=ByteBuffer.allocate(length);out.putInt(0x50514334);
            out.putInt(bound.length).put(bound);out.putInt(encapsulation.length).put(encapsulation);
            out.putInt(salt.length).put(salt);out.putInt(nonce.length).put(nonce);
            out.putInt(ciphertext.length).put(ciphertext);out.putInt(signature.length).put(signature);
            return out.array();
        }
        // Trusted file adapter only; views are read-only and never expose owned arrays.
        void writeTo(java.nio.channels.GatheringByteChannel channel)throws java.io.IOException {
            byte[][] fields={bound,encapsulation,salt,nonce,ciphertext,signature};
            ByteBuffer header=ByteBuffer.allocate(28);header.putInt(0x50514334);
            for(byte[] field:fields)header.putInt(field.length);
            ByteBuffer[] parts=new ByteBuffer[13];
            parts[0]=ByteBuffer.wrap(header.array(),0,4).asReadOnlyBuffer();
            for(int i=0;i<fields.length;i++){
                parts[1+2*i]=ByteBuffer.wrap(header.array(),4+4*i,4).asReadOnlyBuffer();
                parts[2+2*i]=ByteBuffer.wrap(fields[i]).asReadOnlyBuffer();
            }
            int first=0;
            while(first<parts.length){
                if(channel.write(parts,first,parts.length-first)<=0)throw new java.io.IOException("Packet output made no progress");
                while(first<parts.length && !parts[first].hasRemaining())first++;
            }
        }
        public static Packet decode(byte[] encoded)throws java.io.IOException {
            if(encoded==null || encoded.length>16*1024*1024+10000)throw new java.io.IOException("Packet size");
            // Inspect the complete layout before allocating any packet payload arrays.
            ByteBuffer input=ByteBuffer.wrap(encoded);int[] offsets=new int[6],lengths=new int[6];

            if(input.remaining()<4 || input.getInt()!=0x50514334)throw new java.io.IOException("Packet version");
            for(int i=0;i<6;i++){
                if(input.remaining()<4)throw new java.io.IOException("Packet field header");int len=input.getInt();
                if(len<MIN[i] || len>MAX[i] || len>input.remaining() || (i==1 && len!=1088 && len!=1568) || (i==5 && len!=3309 && len!=4627))throw new java.io.IOException("Packet field bounds");
                offsets[i]=input.position();lengths[i]=len;input.position(input.position()+len);
            }
            if(input.hasRemaining())throw new java.io.IOException("Packet trailing bytes");byte[][] fields=new byte[6][];
            for(int i=0;i<6;i++)fields[i]=Arrays.copyOfRange(encoded,offsets[i],offsets[i]+lengths[i]);
            return new Packet(fields[0],fields[1],fields[2],fields[3],fields[4],fields[5]);
        }
        public int ciphertextBytes(){return ciphertext.length;}
        public int signatureBytes(){return signature.length;}
        // Defensive regression fixtures; no caller receives the packet's owned arrays.
        Packet changedCiphertext(){byte[] changed=ciphertext.clone();changed[0]^=1;return new Packet(bound.clone(),encapsulation.clone(),salt.clone(),nonce.clone(),changed,signature.clone());}
        Packet changedCapsule(){byte[] changed=encapsulation.clone();changed[0]^=1;return new Packet(bound.clone(),changed,salt.clone(),nonce.clone(),ciphertext.clone(),signature.clone());}
    }
    enum Step{AFTER_RESERVATION,BEFORE_ENCAPSULATION,BEFORE_SIGNATURE,BEFORE_VERIFICATION,BEFORE_DECRYPTION}
    @FunctionalInterface interface Fault{void at(Step step)throws GeneralSecurityException;}
    public static final class Engine implements AutoCloseable {
        private final Path directory;private final String context;private final Fault fault;
        private TrustedStateStore store;private final java.util.NavigableMap<Long,State> history=new java.util.TreeMap<>();
        private final java.util.concurrent.atomic.AtomicReference<State> active=new java.util.concurrent.atomic.AtomicReference<>();
        private final java.util.concurrent.atomic.AtomicBoolean closed=new java.util.concurrent.atomic.AtomicBoolean();
        public Engine(Profile approved,String context,Path directory)throws Exception {this(approved,context,directory,step->{});}
        Engine(Profile approved,String context,Path directory,Fault fault)throws Exception {
            this.directory=directory;this.context=context;this.fault=Objects.requireNonNull(fault);validateContext(context);activate(approved);
        }
        private Engine(String context,Path directory,TrustedStateStore store)throws Exception {
            this.directory=directory;this.context=context;this.fault=step->{};this.store=store;validateContext(context);
        }
        public static Engine createPersistent(Profile approved,String context,Path directory,Path trustedAnchor,byte[] masterKey)throws Exception {
            if(!listed(approved))throw new SecurityException("Unapproved profile");validateContext(context);TrustedStateStore store=new TrustedStateStore(directory,trustedAnchor,masterKey,true,false);
            try{Engine engine=new Engine(context,directory,store);engine.activate(approved);return engine;}catch(Exception e){try{store.close();}catch(Exception cleanup){if(cleanup!=e)e.addSuppressed(cleanup);}throw e;}
        }
        public static Engine reopen(String context,Path directory,Path trustedAnchor,byte[] masterKey,boolean repairMirror)throws Exception {
            validateContext(context);TrustedStateStore store=TrustedStateStore.openForEngine(directory,trustedAnchor,masterKey,repairMirror);
            try{Engine engine=new Engine(context,directory,store);byte[] encoded=store.load();try{engine.restore(encoded);store.repairMirror();}finally{wipe(encoded);}return engine;}catch(Exception e){try{store.close();}catch(Exception cleanup){if(cleanup!=e)e.addSuppressed(cleanup);}throw e;}
        }
        private State makeState(Snapshot snapshot,Keys keys)throws Exception {
            checkKey(snapshot.profile,keys);MessageDigest digest=MessageDigest.getInstance("SHA-256","SUN");digest.update(keys.kem.getPublic().getEncoded());byte[] fingerprint=digest.digest(keys.signature.getPublic().getEncoded());digest.update(binding(snapshot));byte[] bound=digest.digest(fingerprint);
            String identity=HexFormat.of().formatHex(fingerprint);return new State(snapshot,keys,bound,store==null?new NonceReservations(directory,identity,128):null,identity);
        }
        private byte[] checkpoint(java.util.NavigableMap<Long,State> states,long current)throws Exception {
            try(SecretBuffer bytes=new SecretBuffer();java.io.DataOutputStream out=new java.io.DataOutputStream(bytes)){
                out.writeInt(0x454e4734);out.writeUTF(context);out.writeLong(current);out.writeInt(states.size());
                for(State st:states.values()){
                    Profile p=st.snapshot.profile;out.writeLong(p.policyVersion);out.writeLong(p.keyVersion);out.writeInt(p.category);
                    // Encode one key at a time; exceptions leave no unvisited encoded-key arrays.
                    for(java.security.Key key:List.of(st.keys.kem.getPublic(),st.keys.kem.getPrivate(),st.keys.signature.getPublic(),st.keys.signature.getPrivate())){
                        byte[] field=key.getEncoded();try{out.writeInt(field.length);out.write(field);}finally{wipe(field);}
                    }
                }
                out.flush();return bytes.copy();
            }
        }
        private void save(java.util.NavigableMap<Long,State> states,long current)throws Exception {if(store!=null){byte[] encoded=checkpoint(states,current);try{store.save(encoded);}catch(Exception e){closed.set(true);throw e;}finally{wipe(encoded);}}}
        private void restore(byte[] encoded)throws Exception {
            if(encoded==null)throw new java.io.IOException("No checkpoint");
            try(java.io.DataInputStream in=new java.io.DataInputStream(new java.io.ByteArrayInputStream(encoded))){
                if(in.readInt()!=0x454e4734 || !context.equals(in.readUTF()))throw new SecurityException("Checkpoint context/version");long current=in.readLong();int n=in.readInt();if(n<1 || n>32)throw new java.io.IOException("History bounds");long previousPolicy=0,previousKey=0;int previousCategory=0;
                for(int i=0;i<n;i++){long pv=in.readLong(),kv=in.readLong();int cat=in.readInt();Profile p=new Profile(pv,kv,cat==3?"ML-KEM-768":"ML-KEM-1024",cat==3?"ML-DSA-65":"ML-DSA-87",cat,"BC",true);if(!listed(p) || pv<=previousPolicy || kv<=previousKey || cat<previousCategory)throw new SecurityException("Checkpoint policy ordering");previousPolicy=pv;previousKey=kv;previousCategory=cat;
                    byte[][] f=new byte[4][];try{for(int j=0;j<4;j++){int len=in.readInt();if(len<1 || len>32768 || len>in.available())throw new java.io.IOException("Key bounds");f[j]=new byte[len];in.readFully(f[j]);}KeyFactory kem=KeyFactory.getInstance("ML-KEM",BC),sig=KeyFactory.getInstance("ML-DSA",BC);Keys keys=new Keys(new KeyPair(kem.generatePublic(new java.security.spec.X509EncodedKeySpec(f[0])),kem.generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(f[1]))),new KeyPair(sig.generatePublic(new java.security.spec.X509EncodedKeySpec(f[2])),sig.generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(f[3]))));State state=makeState(new Snapshot(p,context),keys);
                        // Check imported private/public pairs, not merely their parameter labels.
                        byte[] probe=new byte[]{1,2,3};byte[] signature=sign(state.snapshot,keys.signature.getPrivate(),probe);try{if(!verify(state.snapshot,keys.signature.getPublic(),probe,signature))throw new SecurityException("Signature key pair mismatch");}finally{wipe(signature);}
                        try(Capsule cap=encapsulate(p,keys.kem.getPublic())){byte[] raw=decapsulate(p,keys.kem.getPrivate(),cap.ciphertext);try{if(!MessageDigest.isEqual(raw,cap.secret))throw new SecurityException("KEM key pair mismatch");}finally{wipe(raw);}}
                        history.put(pv,state);
                    }finally{wipe(f);}
                }
                if(in.read()!=-1 || current!=history.lastKey())throw new SecurityException("Checkpoint active state");active.set(history.get(current));
            }
        }
        public synchronized Prepared prepareHistorical(long policyVersion){available();State state=history.get(policyVersion);if(state==null || state.retired)throw new SecurityException("Unknown/retired state");return new Prepared(this,state,true);}
        public synchronized Profile currentProfile(){available();return active.get().snapshot.profile;}
        public synchronized void retire(long policyVersion)throws Exception {
            available();State state=history.get(policyVersion);if(state==null || state==active.get())throw new SecurityException("Unknown or active state cannot retire");java.util.NavigableMap<Long,State> updated=new java.util.TreeMap<>(history);updated.remove(policyVersion);save(updated,active.get().snapshot.profile.policyVersion);state.retired=true;history.remove(policyVersion);
        }
        private void available(){if(closed.get() || store!=null && !store.usable())throw new IllegalStateException("Engine closed or persistence failed");}
        // Administrative operation. Request callers use prepare, not activate.
        public synchronized void activate(Profile approved)throws Exception {
            available();if(!listed(approved))throw new SecurityException("Unapproved profile");State prior=active.get();
            if(prior!=null && (approved.category<prior.snapshot.profile.category || approved.policyVersion<=prior.snapshot.profile.policyVersion || approved.keyVersion<=prior.snapshot.profile.keyVersion))throw new SecurityException("Security category must not decrease; policy/key versions must advance");
            if(history.size()>=32)throw new SecurityException("History limit; retire old state first");
            Snapshot snapshot=new Snapshot(approved,context);State next=makeState(snapshot,generate(snapshot));java.util.NavigableMap<Long,State> updated=new java.util.TreeMap<>(history);updated.put(approved.policyVersion,next);save(updated,approved.policyVersion);history.put(approved.policyVersion,next);active.set(next);
        }
        public synchronized Prepared prepare(Profile requested,String requestedContext){
            available();State state=active.get();if(state==null)throw new IllegalStateException("Engine closed");permit(state.snapshot,requested,requestedContext);return new Prepared(this,state);
        }
        private State state(Prepared request){available();if(request==null || request.owner!=this)throw new SecurityException("Foreign/unvalidated request");if(request.state.retired)throw new SecurityException("State retired");return request.state;}
        public synchronized Packet seal(Prepared request,byte[] message)throws Exception {
            State state=state(request);if(request.readOnly)throw new SecurityException("Historical request is read-only");if(message==null || message.length>16*1024*1024)throw new IllegalArgumentException("Invalid message bounds");
            if(!request.used.compareAndSet(false,true))throw new SecurityException("Request already consumed");
            long sequence=store==null?state.cursor.next():store.next(state.fingerprint);
            return sealOwned(state,message.clone(),sequence,()->false);
        }
        /** Explicit authenticated application identity; callers must supply the same expected AAD on open. */
        public synchronized Packet sealWithAad(Prepared request,byte[] message,byte[] applicationAad)throws Exception {
            State state=state(request);if(request.readOnly)throw new SecurityException("Historical request is read-only");
            if(message==null || message.length>16*1024*1024)throw new IllegalArgumentException("Invalid message bounds");
            byte[] aad=applicationAad(state,applicationAad);
            if(!request.used.compareAndSet(false,true))throw new SecurityException("Request already consumed");
            long sequence=store==null?state.cursor.next():store.next(state.fingerprint);
            return sealOwned(state,message.clone(),sequence,()->false,aad);
        }
        private static byte[] applicationAad(State state,byte[] additional) {
            if(additional==null || additional.length==0 || additional.length>2048)throw new IllegalArgumentException("Application AAD bounds");
            byte[] domain="JCA-PQC-DOC-AAD-v1".getBytes(StandardCharsets.US_ASCII);
            return ByteBuffer.allocate(state.bound.length+domain.length+4+additional.length).put(state.bound).put(domain).putInt(additional.length).put(additional).array();
        }
        // Takes only privately owned plaintext; the public API retains its defensive clone.
        private Packet sealOwned(State state,byte[] input,long sequence,java.util.function.BooleanSupplier cancelled)throws Exception {
            return sealOwned(state,input,sequence,cancelled,state.bound);
        }
        private Packet sealOwned(State state,byte[] input,long sequence,java.util.function.BooleanSupplier cancelled,byte[] aad)throws Exception {
            byte[] secret=null,derived=null;boolean transferred=false;byte[] salt=new byte[32],nonce=null,encapsulation=null,ciphertext=null,signature=null;
            try{
                nonce=ByteBuffer.allocate(12).put(state.prefix).putLong(sequence).array();fault.at(Step.AFTER_RESERVATION);checkBatchCancellation(cancelled);RNG.nextBytes(salt);fault.at(Step.BEFORE_ENCAPSULATION);checkBatchCancellation(cancelled);
                try(Capsule capsule=encapsulate(state.snapshot.profile,state.keys.kem.getPublic())){
                    encapsulation=capsule.ciphertext;secret=capsule.secret;checkBatchCancellation(cancelled);derived=derive(secret,salt,state.bound);ciphertext=crypt(true,derived,nonce,aad,input);
                    Packet unsigned=new Packet(state.bound,encapsulation,salt,nonce,ciphertext,new byte[0]);fault.at(Step.BEFORE_SIGNATURE);checkBatchCancellation(cancelled);signature=frameSign(state,unsigned);
                    Packet result=new Packet(state.bound,encapsulation,salt,nonce,ciphertext,signature);transferred=true;return result;
                }
            }finally{wipe(input,derived);if(!transferred)wipe(salt,nonce,encapsulation,ciphertext,signature);}
        }
        // Internal offline adapter. Holding the monitor for the complete batch pins
        // policy/key lifetime; workers never call synchronized Engine operations.
        synchronized int sealFiles(List<Path> inputPaths,List<Path> outputPaths,int workers)throws Exception {
            available();if(workers!=1 && workers!=2 && workers!=4)throw new IllegalArgumentException("Workers must be 1, 2 or 4");
            if(Thread.currentThread().isInterrupted())throw new InterruptedException("Batch already interrupted");
            List<Path> inputs=List.copyOf(inputPaths);List<Path> supplied=List.copyOf(outputPaths);
            if(inputs.isEmpty() || inputs.size()>64 || inputs.size()!=supplied.size())throw new IllegalArgumentException("Batch bounds");
            List<Path> outputs=new ArrayList<>();Set<Path> unique=new HashSet<>();
            for(Path path:supplied){Path checked=CryptoCli.target(path.toString());if(!unique.add(checked))throw new java.io.IOException("Duplicate output");outputs.add(checked);}
            long largest=0;for(Path input:inputs)largest=Math.max(largest,CryptoCli.inputSize(input,16*1024*1024,true));
            State state=active.get();long[] sequences=new long[inputs.size()];
            for(int i=0;i<sequences.length;i++)sequences[i]=store==null?state.cursor.next():store.next(state.fingerprint);
            int effective=batchWorkerLimit(workers,inputs.size(),largest,Runtime.getRuntime().maxMemory());
            int inputLimit=(int)largest;
            if(effective==1){
                try{for(int i=0;i<inputs.size();i++){if(Thread.currentThread().isInterrupted())throw new InterruptedException("Batch interrupted");sealFile(state,sequences[i],inputs.get(i),outputs.get(i),inputLimit,()->Thread.currentThread().isInterrupted());}}
                catch(java.util.concurrent.CancellationException e){if(Thread.currentThread().isInterrupted()){InterruptedException interrupted=new InterruptedException("Batch interrupted before next stage");interrupted.initCause(e);throw interrupted;}throw e;}
                return effective;
            }
            var stop=new java.util.concurrent.atomic.AtomicBoolean();var next=new java.util.concurrent.atomic.AtomicInteger();
            var firstFailure=new java.util.concurrent.atomic.AtomicReference<Throwable>();
            var pool=java.util.concurrent.Executors.newFixedThreadPool(effective);
            var completed=new java.util.concurrent.ExecutorCompletionService<Void>(pool);boolean interrupted=false;
            try{
                for(int worker=0;worker<effective;worker++)completed.submit(()->{
                    try{while(!stop.get()){
                        int i=next.getAndIncrement();if(i>=inputs.size())break;
                        if(stop.get())break;sealFile(state,sequences[i],inputs.get(i),outputs.get(i),inputLimit,stop::get);
                    }return null;}catch(Exception|Error e){firstFailure.compareAndSet(null,e);stop.set(true);throw e;}
                });
                for(int worker=0;worker<effective;worker++)try{completed.take().get();}catch(java.util.concurrent.ExecutionException e){
                    Throwable cause=firstFailure.get();if(cause==null)cause=e.getCause();if(cause instanceof Exception exception)throw exception;if(cause instanceof Error error)throw error;throw new IllegalStateException(cause);
                }
            }catch(InterruptedException e){stop.set(true);interrupted=true;throw e;}
            finally{
                stop.set(true);pool.shutdown();
                // Do not close keys/lease or delete staging while a worker is alive.
                while(!pool.isTerminated())try{pool.awaitTermination(1,java.util.concurrent.TimeUnit.SECONDS);}catch(InterruptedException e){interrupted=true;}
                if(interrupted)Thread.currentThread().interrupt();
            }
            return effective;
        }
        static int batchWorkerLimit(int requested,int files,long largest,long maxHeap){
            if((requested!=1 && requested!=2 && requested!=4) || files<1 || files>64 || largest<0 || largest>16*1024*1024 || maxHeap<1)throw new IllegalArgumentException("Batch planning bounds");
            // A concurrency estimate, not a heap/RSS guarantee. Reserve heap room for
            // engine/provider/GC; account for three input-sized buffers plus overhead.
            long budget=Math.min(128L*1024*1024,maxHeap/4),perFile=3*largest+1024*1024;
            return (int)Math.min(Math.min(requested,files),Math.max(1,budget/perFile));
        }
        private static void checkBatchCancellation(java.util.function.BooleanSupplier cancelled){
            if(cancelled.getAsBoolean())throw new java.util.concurrent.CancellationException("Batch stopped before next stage");
        }
        private void sealFile(State state,long sequence,Path input,Path output,int inputLimit,java.util.function.BooleanSupplier cancelled)throws Exception {
            checkBatchCancellation(cancelled);byte[] plaintext=CryptoCli.read(input.toString(),inputLimit,true);
            try{checkBatchCancellation(cancelled);Packet packet=sealOwned(state,plaintext,sequence,cancelled);checkBatchCancellation(cancelled);CryptoCli.publish(output,packet);}finally{wipe(plaintext);}
        }
        public synchronized byte[] open(Prepared request,Packet packet)throws Exception {
            return openInternal(request,packet,null);
        }
        public synchronized byte[] openWithAad(Prepared request,Packet packet,byte[] expectedApplicationAad)throws Exception {
            return openInternal(request,packet,applicationAad(state(request),expectedApplicationAad));
        }
        private byte[] openInternal(Prepared request,Packet packet,byte[] aad)throws Exception {
            State state=state(request);if(packet==null || !MessageDigest.isEqual(state.bound,packet.bound) || packet.salt.length!=32 || packet.nonce.length!=12 || packet.encapsulation.length!=(state.snapshot.profile.category==3?1088:1568) || packet.signature.length!=(state.snapshot.profile.category==3?3309:4627) || packet.ciphertext.length<16 || packet.ciphertext.length>16*1024*1024+16)throw new SecurityException("Packet/profile bounds mismatch");
            fault.at(Step.BEFORE_VERIFICATION);if(!frameVerify(state,packet))throw new SignatureException("Packet authentication failed");
            byte[] raw=null,derived=null;
            try{raw=decapsulate(state.snapshot.profile,state.keys.kem.getPrivate(),packet.encapsulation);derived=derive(raw,packet.salt,state.bound);fault.at(Step.BEFORE_DECRYPTION);return crypt(false,derived,packet.nonce,aad==null?state.bound:aad,packet.ciphertext);}
            finally{wipe(raw,derived);}
        }
        public synchronized long reservationWrites(Prepared request){State state=state(request);return store==null?state.cursor.reservationWrites():store.writes();}
        @Override public synchronized void close(){closed.set(true);active.set(null);for(State state:history.values())state.retired=true;history.clear();if(store!=null){try{store.close();}catch(java.io.IOException e){throw new java.io.UncheckedIOException(e);}store=null;}}
    }
    private static void validateContext(String context)throws Exception {
        if(context==null || context.isEmpty())throw new IllegalArgumentException("Empty context");
        java.nio.charset.CharsetEncoder encoder=StandardCharsets.UTF_8.newEncoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT).onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT);
        ByteBuffer bytes=encoder.encode(java.nio.CharBuffer.wrap(context));if(bytes.remaining()>64 || context.indexOf('\0')>=0)throw new IllegalArgumentException("Context bounds");
    }
    private static Signature frameSignature(State state,boolean signing)throws Exception {
        Signature s=Signature.getInstance("ML-DSA",BC);s.setParameter(new ContextParameterSpec(state.bound));
        if(signing)s.initSign(state.keys.signature.getPrivate(),RNG);else s.initVerify(state.keys.signature.getPublic());return s;
    }
    static void putFrameInt(byte[] word,int value){word[0]=(byte)(value>>>24);word[1]=(byte)(value>>>16);word[2]=(byte)(value>>>8);word[3]=(byte)value;}
    private static void updateFrame(Signature s,Packet p)throws SignatureException {
        byte[] word={0x50,0x51,0x43,3};s.update(word);s.update(p.bound);putFrameInt(word,p.encapsulation.length);s.update(word);s.update(p.encapsulation);s.update(p.salt);s.update(p.nonce);putFrameInt(word,p.ciphertext.length);s.update(word);s.update(p.ciphertext);
    }
    private static byte[] frameSign(State state,Packet packet)throws Exception {Signature s=frameSignature(state,true);updateFrame(s,packet);return s.sign();}
    private static boolean frameVerify(State state,Packet packet)throws Exception {Signature s=frameSignature(state,false);updateFrame(s,packet);return s.verify(packet.signature);}
    public static byte[] uncachedBinding(Profile p,String context){return binding(new Snapshot(p,context));}
    public static final class BindingCache {
        private final byte[] bytes;
        public BindingCache(Profile approved,String context)throws Exception {if(!listed(approved))throw new SecurityException("Invalid profile");validateContext(context);bytes=binding(new Snapshot(approved,context));}
        // Public copies preserve ownership; internal hot paths use their private cached bytes.
        public byte[] copy(){return bytes.clone();}
    }

    public static void main(String[] args)throws Exception {
        Path out=Path.of(args[0]);Files.createDirectories(out);policyTests(out);functional(out);int functionalAssertions=assertions.get();benchmark(out,args.length>1?Integer.parseInt(args[1]):0);
        Files.writeString(out.resolve("pqc-environment.txt"),"Java="+System.getProperty("java.runtime.version")+"\nBCVersion="+BC.getVersionStr()+"\nBCClass="+BC.getClass().getName()+"\nGlobalProviderRegistered="+(Security.getProvider("BC")!=null)+"\nFunctionalAssertions="+functionalAssertions+"\nTotalAssertionsIncludingBenchmark="+assertions+"\n");
        System.out.println("PASS PQC functional_assertions="+functionalAssertions+"; policy_rows=22; functional_rows=40; cost_rows=1212; no classical fallback");
    }
}
