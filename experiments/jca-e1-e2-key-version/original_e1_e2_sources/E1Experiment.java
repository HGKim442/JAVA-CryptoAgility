import java.io.*;
import java.nio.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/** Isolated synthetic PoCs; never compiled onto the production CLI classpath. */
public final class E1Experiment {
    enum Mode { VULNERABLE, ALLOWLIST, PROPOSED }
    static final Provider TRUSTED=Security.getProvider("SunJCE"),DIGEST=Security.getProvider("SUN");
    static final byte[] KEY=new byte[32],MASTER=new byte[32],A=new byte[32],B=new byte[32];
    static {Arrays.fill(KEY,(byte)31);Arrays.fill(MASTER,(byte)73);Arrays.fill(A,(byte)65);Arrays.fill(B,(byte)66);}
    static final class Reject extends GeneralSecurityException {
        private static final long serialVersionUID=1L;
        Reject(String m){super(m);}
    }
    static final class Config {
        String algorithm="AES/GCM/NoPadding";Provider provider=TRUSTED;int bits=256,version=1;
        Config copy(){Config c=new Config();c.algorithm=algorithm;c.provider=provider;c.bits=bits;c.version=version;return c;}
    }
    record Packet(byte[] nonce,byte[] ciphertext,String tenant,String document,int version,String algorithm,int bits) {}
    static byte[] aad(String tenant,String document,int version,String algorithm,int bits) {
        byte[] t=tenant.getBytes(java.nio.charset.StandardCharsets.UTF_8),d=document.getBytes(java.nio.charset.StandardCharsets.UTF_8),a=algorithm.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        return ByteBuffer.allocate(20+t.length+d.length+a.length).putInt(t.length).put(t).putInt(d.length).put(d).putInt(version).putInt(a.length).put(a).putInt(bits).array();
    }
    static final class Pipeline {
        final Mode mode;final TrustedStateStore store;long counter;
        Pipeline(Mode m,TrustedStateStore s){mode=m;store=s;}
        void gate(Config c)throws Reject {
            if(mode!=Mode.VULNERABLE && (!c.algorithm.equals("AES/GCM/NoPadding") || c.provider!=TRUSTED || (c.bits!=128 && c.bits!=256)))throw new Reject("Unapproved configuration");
        }
        Packet seal(Config caller,byte[] plain,String tenant,String document,Runnable interleave,boolean preferredFailure)throws Exception {
            gate(caller);Config execution=mode==Mode.PROPOSED?caller.copy():caller;
            interleave.run();
            Cipher cipher;
            try {cipher=Cipher.getInstance(preferredFailure?"FixtureUnavailablePreferredCipher":execution.algorithm,execution.provider);}
            catch(GeneralSecurityException failure) {
                if(mode==Mode.PROPOSED)throw new Reject("Preferred implementation failed: "+failure.getClass().getSimpleName());
                // Actual JCA factory failure followed by an allowlisted but request-weaker AES-128 fallback.
                execution=execution.copy();execution.bits=128;cipher=Cipher.getInstance(execution.algorithm,execution.provider);
            }
            long n=mode==Mode.PROPOSED?store.next(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256",DIGEST).digest(Arrays.copyOf(KEY,execution.bits/8)))):counter++;
            byte[] nonce=ByteBuffer.allocate(12).putInt(0).putLong(n).array();
            SecretKeySpec key=new SecretKeySpec(Arrays.copyOf(KEY,execution.bits/8),"AES");
            if(execution.algorithm.contains("GCM"))cipher.init(Cipher.ENCRYPT_MODE,key,new GCMParameterSpec(128,nonce));else cipher.init(Cipher.ENCRYPT_MODE,key);
            if(mode==Mode.PROPOSED)cipher.updateAAD(aad(tenant,document,execution.version,execution.algorithm,execution.bits));
            return new Packet(nonce,cipher.doFinal(plain),tenant,document,execution.version,execution.algorithm,execution.bits);
        }
        byte[] open(Packet p,String tenant,String document,int expectedVersion)throws Exception {
            if(mode==Mode.PROPOSED && (p.version!=expectedVersion || !p.tenant.equals(tenant) || !p.document.equals(document)))throw new Reject("Identity/version mismatch");
            Cipher cipher=Cipher.getInstance(p.algorithm,TRUSTED);SecretKeySpec key=new SecretKeySpec(Arrays.copyOf(KEY,p.bits/8),"AES");
            if(p.algorithm.contains("GCM"))cipher.init(Cipher.DECRYPT_MODE,key,new GCMParameterSpec(128,p.nonce));else cipher.init(Cipher.DECRYPT_MODE,key);
            if(mode==Mode.PROPOSED)cipher.updateAAD(aad(tenant,document,expectedVersion,p.algorithm,p.bits));
            return cipher.doFinal(p.ciphertext);
        }
        byte[] digest(byte[] bytes,Provider requested)throws Exception {
            if(mode!=Mode.VULNERABLE && requested!=DIGEST)throw new Reject("Untrusted digest Provider");
            return MessageDigest.getInstance("SHA-256",mode==Mode.PROPOSED?DIGEST:requested).digest(bytes);
        }
    }
    public static final class ObservingDigest extends MessageDigestSpi {
        static byte[] observed;final ByteArrayOutputStream input=new ByteArrayOutputStream();
        @Override protected void engineUpdate(byte v){input.write(v);}
        @Override protected void engineUpdate(byte[] b,int off,int len){input.write(b,off,len);}
        @Override protected byte[] engineDigest(){observed=input.toByteArray();try{return MessageDigest.getInstance("SHA-256",DIGEST).digest(observed);}catch(GeneralSecurityException e){throw new IllegalStateException(e);}finally{input.reset();}}
        @Override protected void engineReset(){input.reset();}
    }
    static final class TrialProvider extends Provider {
        private static final long serialVersionUID=1L;
        TrialProvider(){super("SyntheticObservation","1.0","Fixture-only synthetic input observer");putService(new Service(this,"MessageDigest","SHA-256",ObservingDigest.class.getName(),List.of(),Map.of()));}
    }
    static final class Fixture implements AutoCloseable {
        final Path root,data,anchor;TrustedStateStore store;
        Fixture()throws Exception {
            var perms=PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"));
            root=Files.createTempDirectory("e1-synthetic-",perms);data=Files.createDirectory(root.resolve("data"),perms);anchor=Files.createDirectory(root.resolve("anchor"),perms);
            store=new TrustedStateStore(data,anchor,MASTER,true,false);store.save(new byte[]{1});
        }
        void restart()throws Exception {store.close();store=new TrustedStateStore(data,anchor,MASTER,false,false);}
        @Override public void close()throws IOException {try{store.close();}finally{try(var paths=Files.walk(root)){for(Path p:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(p);}}}
    }
    static boolean xorLeak(Packet a,Packet b) {
        if(!Arrays.equals(a.nonce,b.nonce))return false;
        for(int i=0;i<A.length;i++)if((byte)(a.ciphertext[i]^b.ciphertext[i])!=(byte)(A[i]^B[i]))return false;
        return true;
    }
    static boolean attack(Pipeline p,int scenario,Fixture fixture)throws Exception {
        Config c=new Config();
        switch(scenario) {
            case 1: {
                c.algorithm="AES/ECB/NoPadding";Packet x=p.seal(c,A,"t1","d1",()->{},false);
                return Arrays.equals(Arrays.copyOf(x.ciphertext,16),Arrays.copyOfRange(x.ciphertext,16,32));
            }
            case 2: {
                ObservingDigest.observed=null;byte[] hash=p.digest(A,new TrialProvider());
                return Arrays.equals(hash,MessageDigest.getInstance("SHA-256",DIGEST).digest(A)) && Arrays.equals(ObservingDigest.observed,A);
            }
            case 3: {Packet x=p.seal(c,A,"t1","d1",()->{},true);return x.bits<256 && Arrays.equals(p.open(x,"t1","d1",1),A);}
            case 4: {
                Packet x=p.seal(c,A,"t1","d1",()->{},false);fixture.restart();Pipeline recreated=new Pipeline(p.mode,fixture.store);
                Packet y=recreated.seal(c,B,"t1","d1",()->{},false);
                return xorLeak(x,y);
            }
            case 5: {
                // v1 binds metadata in every implementation. The transition to v2 drops
                // that binding in the two baselines, while rotating AES-128 to AES-256.
                byte[] nonce=new byte[12];nonce[11]=91;
                byte[] old=metadataCrypt(true,128,1,nonce,A,"t1","d1",true);
                check(Arrays.equals(metadataCrypt(false,128,1,nonce,old,"t1","d1",true),A),"Pre-transition normal control");
                try{metadataCrypt(false,128,1,nonce,old,"t2","d2",true);throw new IllegalStateException("Pre-transition metadata control failed");}
                catch(AEADBadTagException expected) { /* Valid v1 control. */ }
                nonce[11]=92;boolean retainBinding=p.mode==Mode.PROPOSED;
                byte[] current=metadataCrypt(true,256,2,nonce,A,"t1","d1",retainBinding);
                check(Arrays.equals(metadataCrypt(false,256,2,nonce,current,"t1","d1",retainBinding),A),"Post-transition normal control");
                return Arrays.equals(metadataCrypt(false,256,2,nonce,current,"t2","d2",retainBinding),A);
            }
            case 6: {
                Packet x=p.seal(c,A,"t1","d1",()->{c.algorithm="AES/ECB/NoPadding";c.version=2;},false);
                return x.version!=1 || !x.algorithm.equals("AES/GCM/NoPadding");
            }
            default:throw new IllegalArgumentException();
        }
    }
    static byte[] metadataCrypt(boolean encrypt,int bits,int version,byte[] nonce,byte[] input,String tenant,String document,boolean bind)throws Exception {
        Cipher c=Cipher.getInstance("AES/GCM/NoPadding",TRUSTED);
        c.init(encrypt?Cipher.ENCRYPT_MODE:Cipher.DECRYPT_MODE,new SecretKeySpec(Arrays.copyOf(KEY,bits/8),"AES"),new GCMParameterSpec(128,nonce));
        if(bind)c.updateAAD(aad(tenant,document,version,"AES/GCM/NoPadding",bits));
        return c.doFinal(input);
    }
    static boolean normal(Pipeline p,int scenario)throws Exception {
        if(scenario==2)return Arrays.equals(p.digest(A,DIGEST),MessageDigest.getInstance("SHA-256",DIGEST).digest(A));
        Config c=new Config();c.bits=128;Packet a=p.seal(c,A,"t1","d1",()->{},false);
        c.bits=256;c.version=2;Packet b=p.seal(c,B,"t1","d1",()->{},false);
        return Arrays.equals(p.open(a,"t1","d1",1),A) && Arrays.equals(p.open(b,"t1","d1",2),B);
    }
    static void check(boolean x,String message){if(!x)throw new AssertionError(message);}
    public static void main(String[] args)throws Exception {
        Path output=Path.of(args[0]);Files.createDirectories(output);int fork=Integer.parseInt(args[1]);
        try(PrintWriter attack=new PrintWriter(Files.newBufferedWriter(output.resolve("attacks.csv")));PrintWriter cost=new PrintWriter(Files.newBufferedWriter(output.resolve("normal-cost.csv")))) {
            attack.println("fork,mode,scenario,trial,attack_effect,blocked,normal_success,reason");cost.println("fork,mode,sample,ns,normal_success");
            for(int shift=0;shift<3;shift++) {
                Mode mode=Mode.values()[(shift+fork-1)%3];
                for(int scenario=1;scenario<=6;scenario++)for(int trial=0;trial<5;trial++) {
                    boolean effect=false,known=true;String reason="predicate";
                    try(Fixture f=new Fixture()) {
                        Pipeline pipeline=new Pipeline(mode,f.store);boolean normalOk;try{normalOk=normal(pipeline,scenario);}catch(Exception e){normalOk=false;}
                        // Reset process-local counters so a normal control cannot mask restart reuse.
                        pipeline=new Pipeline(mode,f.store);
                        try{effect=attack(pipeline,scenario,f);}catch(Reject e){reason="policy_rejection";}catch(AEADBadTagException e){reason="authentication_rejection";}catch(Exception e){known=false;reason="unexpected_failure";}
                        // Outcomes are observations: a successful attack on PROPOSED is
                        // retained in the CSV and never aborts or disappears from the experiment.
                        attack.printf(Locale.ROOT,"%d,%s,%02d,%d,%s,%s,%s,%s%n",fork,mode,scenario,trial,known?String.valueOf(effect):"unknown",known?String.valueOf(!effect):"unknown",normalOk,reason);
                    }
                }
                try(Fixture f=new Fixture()) {
                    Pipeline p=new Pipeline(mode,f.store);byte[] plain=new byte[4096];Arrays.fill(plain,(byte)17);
                    for(int sample=-20;sample<50;sample++) {
                        long started=System.nanoTime();Config c=new Config();c.bits=128;Packet before=p.seal(c,plain,"tenant","document",()->{},false);
                        c.bits=256;c.version=2;Packet after=p.seal(c,plain,"tenant","document",()->{},false);
                        boolean ok=Arrays.equals(p.open(before,"tenant","document",1),plain) && Arrays.equals(p.open(after,"tenant","document",2),plain);
                        long ns=System.nanoTime()-started;check(ok,"Transition roundtrip");
                        if(sample>=0)cost.printf(Locale.ROOT,"%d,%s,%d,%d,true%n",fork,mode,sample,ns);
                    }
                }
            }
            if(attack.checkError()||cost.checkError())throw new java.io.IOException("Raw CSV write failed");
        }
        System.out.println("PASS E1 actual PoCs fork="+fork+" attack_rows=90 normal_cost_rows=150");
    }
}
