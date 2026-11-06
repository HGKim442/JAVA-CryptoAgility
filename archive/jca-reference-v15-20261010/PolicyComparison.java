import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/** Defensive policy ablation. Invalid configurations are inspected, never executed. */
public final class PolicyComparison {
    enum Mode { NO_GATE_MODEL, ALLOWLIST_MODEL, SNAPSHOT_STATE_CONTEXT }
    record Config(long policyVersion,String transformation,String provider,int keyBits,int tagBits,long keyVersion) {}
    record Attempt(Config execution,String context,boolean implementationFailed,boolean fallbackRequested,long nonceSequence) {}
    record Decision(boolean allowed,String reason) {}
    static final String ALGORITHM="AES/GCM/NoPadding",CHACHA="ChaCha20-Poly1305",CONTEXT="tenant-A/document-1";
    static final Provider TRUSTED=Objects.requireNonNull(Security.getProvider("SunJCE"));
    static final SecureRandom RANDOM=new SecureRandom();
    static int assertions;static volatile int sink;
    static void require(boolean value,String label){assertions++;if(!value)throw new AssertionError(label);}
    static Config approved(long policy,long key,int bits){return new Config(policy,ALGORITHM,TRUSTED.getName(),bits,128,key);}
    static boolean listed(Config c){return c.provider.equals(TRUSTED.getName()) && c.tagBits==128 && (c.transformation.equals(ALGORITHM) && (c.keyBits==128 || c.keyBits==256) || c.transformation.equals(CHACHA) && c.keyBits==256);}
    static final class Gate {
        final Mode mode;final Config snapshot;final String context;final Set<Long> reserved=new HashSet<>();
        Gate(Mode mode,Config snapshot,String context){this.mode=mode;this.snapshot=snapshot;this.context=context;}
        // The stateful mode's reservation is atomic for the lifetime of this gate.
        synchronized Decision admit(Attempt a){
            if(mode==Mode.NO_GATE_MODEL)return new Decision(true,"no policy gate in model");
            if(!listed(a.execution))return new Decision(false,"unapproved algorithm/provider/parameters");
            if(mode==Mode.ALLOWLIST_MODEL)return new Decision(true,"listed tuple; state/context omitted by ablation");
            if(!snapshot.equals(a.execution))return new Decision(false,"execution differs from immutable policy/key snapshot");
            if(a.implementationFailed || a.fallbackRequested)return new Decision(false,"implementation failure or fallback request");
            if(!context.equals(a.context))return new Decision(false,"context differs from request binding");
            if(a.nonceSequence<0 || !reserved.add(a.nonceSequence))return new Decision(false,"invalid or already reserved nonce sequence");
            return new Decision(true,"snapshot, state and context accepted");
        }
    }
    static Attempt valid(Config c,long seq){return new Attempt(c,CONTEXT,false,false,seq);}
    static List<Map.Entry<String,Attempt>> negatives(Config c){
        return List.of(
            Map.entry("algorithm_downgrade",new Attempt(new Config(c.policyVersion,"DISALLOWED_ALGORITHM",c.provider,c.keyBits,c.tagBits,c.keyVersion),CONTEXT,false,false,1)),
            Map.entry("provider_change",new Attempt(new Config(c.policyVersion,c.transformation,"UNTRUSTED_PROVIDER_LABEL",c.keyBits,c.tagBits,c.keyVersion),CONTEXT,false,false,1)),
            Map.entry("failure_fallback",new Attempt(c,CONTEXT,true,true,1)),
            Map.entry("nonce_reuse_candidate",valid(c,0)),
            Map.entry("metadata_mismatch",new Attempt(c,"tenant-B/document-1",false,false,1)),
            Map.entry("policy_execution_mismatch",valid(approved(c.policyVersion+1,c.keyVersion+1,256),1)));
    }
    static byte[] aad(Config c,String context){
        return (c.policyVersion+"|"+c.transformation+"|"+c.provider+"|"+c.keyBits+"|"+c.tagBits+"|"+c.keyVersion+"|"+context).getBytes(StandardCharsets.UTF_8);
    }
    static byte[] nonce(byte[] prefix,long seq){
        return java.nio.ByteBuffer.allocate(12).put(prefix).putLong(seq).array();
    }
    static Cipher cipher(Config config)throws GeneralSecurityException {
        Cipher c=Cipher.getInstance(config.transformation,TRUSTED);
        require(c.getProvider()==TRUSTED && c.getAlgorithm().equals(config.transformation),"actual provider/transformation");return c;
    }
    static byte[] seal(Config c,byte[] key,byte[] nonce,byte[] plain,String context)throws Exception {
        // Hard safety boundary shared by all modes: only approved actual crypto is executable.
        require(listed(c) && key.length*8==c.keyBits && nonce.length==12 && CONTEXT.equals(context),"safe execution boundary");
        Cipher e=cipher(c);e.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,c.transformation.equals(ALGORITHM)?"AES":"ChaCha20"),c.transformation.equals(ALGORITHM)?new GCMParameterSpec(c.tagBits,nonce):new IvParameterSpec(nonce));e.updateAAD(aad(c,context));return e.doFinal(plain);
    }
    static byte[] open(Config c,byte[] key,byte[] nonce,byte[] ciphertext,String context)throws Exception {
        require(listed(c) && key.length*8==c.keyBits && nonce.length==12,"safe decrypt boundary");
        Cipher d=cipher(c);d.init(Cipher.DECRYPT_MODE,new SecretKeySpec(key,c.transformation.equals(ALGORITHM)?"AES":"ChaCha20"),c.transformation.equals(ALGORITHM)?new GCMParameterSpec(c.tagBits,nonce):new IvParameterSpec(nonce));d.updateAAD(aad(c,context));return d.doFinal(ciphertext);
    }
    static void actualTransitions(Path out)throws Exception {
        StringBuilder csv=new StringBuilder("mode,transition,iteration,roundtrip,provider,algorithm,key_bits,policy_version,key_version\n");
        for(Mode mode:Mode.values())for(Config c:List.of(approved(1,1,128),approved(2,2,256),new Config(3,CHACHA,TRUSTED.getName(),256,128,3))){
            int bits=c.keyBits;Gate gate=new Gate(mode,c,CONTEXT);
            byte[] key=new byte[bits/8],prefix=new byte[4],plain=new byte[4096];RANDOM.nextBytes(key);RANDOM.nextBytes(prefix);RANDOM.nextBytes(plain);
            try{
                for(int i=0;i<50;i++){
                    require(gate.admit(valid(c,i)).allowed,"normal transition admitted");byte[] n=nonce(prefix,i),ct=seal(c,key,n,plain,CONTEXT),restored=null;
                    try{restored=open(c,key,n,ct,CONTEXT);require(Arrays.equals(plain,restored),"normal roundtrip");csv.append(mode).append(',').append(c.policyVersion==1?"initial128":c.policyVersion==2?"rekey256":"algorithm_to_chacha").append(',').append(i).append(",true,").append(TRUSTED.getName()).append(',').append(c.transformation).append(',').append(bits).append(',').append(c.policyVersion).append(',').append(c.keyVersion).append('\n');}
                    finally{Arrays.fill(ct,(byte)0);if(restored!=null)Arrays.fill(restored,(byte)0);}
                }
                byte[] n=nonce(prefix,50),ct=seal(c,key,n,plain,CONTEXT);boolean returned=false;
                try{byte[] wrong=open(c,key,n,ct,"tenant-B/document-1");returned=true;Arrays.fill(wrong,(byte)0);throw new AssertionError("Wrong AAD accepted");}
                catch(AEADBadTagException expected){require(!returned,"no plaintext returned for wrong context");}
                finally{Arrays.fill(ct,(byte)0);}
            }finally{Arrays.fill(key,(byte)0);Arrays.fill(plain,(byte)0);}
        }
        // Old ciphertext remains readable under its original authenticated configuration after a new request uses v2.
        Config old=approved(1,1,128),next=approved(2,2,256);byte[] k1=new byte[16],k2=new byte[32],p1=new byte[4],p2=new byte[4],message="transition continuity".getBytes(StandardCharsets.UTF_8);
        RANDOM.nextBytes(k1);RANDOM.nextBytes(k2);RANDOM.nextBytes(p1);RANDOM.nextBytes(p2);
        byte[] oldCt=null,newCt=null,oldPlain=null,newPlain=null;
        try{
            Config retainedSnapshot=old;Config livePolicy=next;
            require(retainedSnapshot.keyVersion==1 && livePolicy.keyVersion==2,"snapshot retained despite live policy update");
            oldCt=seal(retainedSnapshot,k1,nonce(p1,0),message,CONTEXT);newCt=seal(livePolicy,k2,nonce(p2,0),message,CONTEXT);
            oldPlain=open(old,k1,nonce(p1,0),oldCt,CONTEXT);newPlain=open(next,k2,nonce(p2,0),newCt,CONTEXT);
            require(Arrays.equals(oldPlain,message)&&Arrays.equals(newPlain,message),"old/new configuration ciphertext continuity");
        }finally{for(byte[] a:new byte[][]{k1,k2,message,oldCt,newCt,oldPlain,newPlain})if(a!=null)Arrays.fill(a,(byte)0);}
        Config aes=approved(2,2,256),chacha=new Config(3,CHACHA,TRUSTED.getName(),256,128,3);
        byte[] aKey=new byte[32],cKey=new byte[32],aPrefix=new byte[4],cPrefix=new byte[4],plain="algorithm continuity".getBytes(StandardCharsets.UTF_8);
        RANDOM.nextBytes(aKey);RANDOM.nextBytes(cKey);RANDOM.nextBytes(aPrefix);RANDOM.nextBytes(cPrefix);
        byte[] aCt=null,cCt=null,aPlain=null,cPlain=null;
        try{
            aCt=seal(aes,aKey,nonce(aPrefix,0),plain,CONTEXT);cCt=seal(chacha,cKey,nonce(cPrefix,0),plain,CONTEXT);
            aPlain=open(aes,aKey,nonce(aPrefix,0),aCt,CONTEXT);cPlain=open(chacha,cKey,nonce(cPrefix,0),cCt,CONTEXT);
            require(Arrays.equals(aPlain,plain)&&Arrays.equals(cPlain,plain),"AES to ChaCha original/new ciphertext continuity");
        }finally{for(byte[] a:new byte[][]{aKey,cKey,plain,aCt,cCt,aPlain,cPlain})if(a!=null)Arrays.fill(a,(byte)0);}
        Files.writeString(out.resolve("normal-transitions.csv"),csv);
    }
    static void guardCoverage()throws Exception {
        Config c=approved(1,1,128);
        List<Attempt> cases=List.of(
            valid(new Config(1,ALGORITHM,TRUSTED.getName(),192,128,1),1),
            valid(new Config(1,ALGORITHM,TRUSTED.getName(),128,96,1),1),
            valid(approved(2,1,128),1),valid(approved(1,2,128),1),
            new Attempt(c,CONTEXT,true,false,1),new Attempt(c,CONTEXT,false,true,1),valid(c,-1));
        for(Attempt a:cases)require(!new Gate(Mode.SNAPSHOT_STATE_CONTEXT,c,CONTEXT).admit(a).allowed,"individual guard rejects");
        Gate gate=new Gate(Mode.SNAPSHOT_STATE_CONTEXT,c,CONTEXT);require(gate.admit(valid(c,0)).allowed,"first reservation");require(!gate.admit(valid(c,0)).allowed,"duplicate reservation");
        // Concurrent reservations for the same key-scoped sequence: exactly one succeeds.
        Gate concurrent=new Gate(Mode.SNAPSHOT_STATE_CONTEXT,c,CONTEXT);
        var pool=java.util.concurrent.Executors.newFixedThreadPool(4);List<java.util.concurrent.Future<Boolean>> futures=new ArrayList<>();
        try{for(int i=0;i<16;i++)futures.add(pool.submit(()->concurrent.admit(valid(c,7)).allowed));int accepted=0;for(var f:futures)if(f.get())accepted++;require(accepted==1,"atomic concurrent reservation");}finally{pool.shutdownNow();}
    }
    static void decisions(Path out)throws Exception {
        StringBuilder csv=new StringBuilder("mode,case,policy_version,key_bits,allowed,reason,actual_invalid_crypto_executed\n");
        for(Mode mode:Mode.values())for(int bits:new int[]{128,256})for(long version:new long[]{1,2,3}){
            Config c=approved(version,version,bits);
            for(var e:negatives(c)){
                Gate gate=new Gate(mode,c,CONTEXT);require(gate.admit(valid(c,0)).allowed,"valid control");Decision d=gate.admit(e.getValue());
                boolean expected=mode==Mode.NO_GATE_MODEL || mode==Mode.ALLOWLIST_MODEL && !Set.of("algorithm_downgrade","provider_change").contains(e.getKey());
                require(d.allowed==expected,"ablation decision "+mode+" "+e.getKey());
                csv.append(mode).append(',').append(e.getKey()).append(',').append(version).append(',').append(bits).append(',').append(d.allowed).append(',').append(d.reason).append(",false\n");
            }
        }
        Files.writeString(out.resolve("policy-decisions.csv"),csv);
    }
    static void costs(Path out,int offset)throws Exception {
        var bean=(com.sun.management.ThreadMXBean)java.lang.management.ManagementFactory.getThreadMXBean();
        if(!bean.isThreadAllocatedMemorySupported())throw new IllegalStateException("thread allocation unsupported");bean.setThreadAllocatedMemoryEnabled(true);long tid=Thread.currentThread().getId();
        StringBuilder csv=new StringBuilder("mode,sample,batch_operations,ns,thread_allocated_bytes\n");Config c=approved(1,1,128);
        // Measures a fresh gate and one valid reservation, not end-to-end crypto or attack cost.
        for(int position=0;position<Mode.values().length;position++){
        Mode mode=Mode.values()[(position+offset)%Mode.values().length];
        for(int sample=-1000;sample<101;sample++){
            long allocated=bean.getThreadAllocatedBytes(tid),start=System.nanoTime();int consumed=0;
            for(int i=0;i<100;i++){Gate gate=new Gate(mode,c,CONTEXT);if(gate.admit(valid(c,i)).allowed)consumed++;}
            long ns=System.nanoTime()-start,bytes=bean.getThreadAllocatedBytes(tid)-allocated;sink=consumed;
            if(sample>=0)csv.append(mode).append(',').append(sample).append(",100,").append(ns).append(',').append(bytes).append('\n');
        }
        }
        Files.writeString(out.resolve("gate-cost.csv"),csv);
    }
    public static void main(String[] args)throws Exception {
        Path out=Path.of(args[0]);Files.createDirectories(out);guardCoverage();decisions(out);actualTransitions(out);costs(out,args.length>1?Integer.parseInt(args[1]):0);
        Files.writeString(out.resolve("environment.txt"),"Java="+System.getProperty("java.runtime.version")+"\nProvider="+TRUSTED.getName()+"\nProviderClass="+TRUSTED.getClass().getName()+"\nProviderVersion="+TRUSTED.getVersionStr()+"\nAssertions="+assertions+"\n");
        System.out.println("PASS assertions="+assertions+"; policy rows=108; normal roundtrips=450; wrong-AAD rejection=9; continuity=2; cost rows=303");
    }
}
