import java.nio.*;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;

public final class StabilityTest {
    private static int checks;
    private static void check(boolean condition,String label){checks++;if(!condition)throw new AssertionError(label);}
    @FunctionalInterface interface Task{void run()throws Exception;}
    private static void reject(Task task)throws Exception {try{task.run();throw new AssertionError("Rejected operation succeeded");}catch(SecurityException|GeneralSecurityException|java.io.IOException|IllegalArgumentException|IllegalStateException expected){checks++;}}
    static final String FP="a".repeat(64);
    static Path privateDir(Path parent,String name)throws Exception {return Files.createDirectory(parent.resolve(name),PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));}
    public static void main(String[] args)throws Exception {
        Path root=Files.createTempDirectory("pqc-stability-",PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));List<String> events=new ArrayList<>();
        try{
            Path counters=privateDir(root,"counters");Set<Long> used=ConcurrentHashMap.newKeySet();
            NonceReservations a=new NonceReservations(counters,FP,128);for(int i=0;i<5;i++)check(used.add(a.next()),"initial uniqueness");check(a.reservationWrites()==1,"one durable block");
            NonceReservations restarted=new NonceReservations(counters,FP,128);long next=restarted.next();check(next==128 && used.add(next),"restart burns remaining reserved values");
            var pool=Executors.newFixedThreadPool(4);List<Future<?>> tasks=new ArrayList<>();
            try{for(int worker=0;worker<4;worker++)tasks.add(pool.submit(()->{try{NonceReservations cursor=new NonceReservations(counters,FP,32);for(int i=0;i<100;i++)if(!used.add(cursor.next()))throw new AssertionError("Duplicate nonce");}catch(Exception e){throw new RuntimeException(e);}}));for(var f:tasks)f.get();}finally{pool.shutdownNow();}
            check(used.size()==406,"multiple cursors reserve nonoverlapping ranges");
            Path corrupt=privateDir(root,"corrupt");NonceReservations c=new NonceReservations(corrupt,FP,1);c.next();Path state=corrupt.resolve(FP+".counter");byte[] prior=Files.readAllBytes(state);prior[15]^=1;Files.write(state,prior);reject(()->new NonceReservations(corrupt,FP,1).next());check(Arrays.equals(prior,Files.readAllBytes(state)),"corrupt state preserved");
            Path missing=privateDir(root,"missing");new NonceReservations(missing,FP,1).next();Files.delete(missing.resolve(FP+".counter"));reject(()->new NonceReservations(missing,FP,1).next());check(!Files.exists(missing.resolve(FP+".counter")),"missing enrolled state not reset");
            Path overflow=privateDir(root,"overflow");new NonceReservations(overflow,FP,1).next();byte[] data=ByteBuffer.allocate(12).putInt(0x4e525633).putLong(Long.MAX_VALUE).array();byte[] digest=MessageDigest.getInstance("SHA-256","SUN").digest(data);Files.write(overflow.resolve(FP+".counter"),ByteBuffer.allocate(44).put(data).put(digest).array());reject(()->new NonceReservations(overflow,FP,128).next());
            Path shared=privateDir(root,"shared");Files.setPosixFilePermissions(shared,PosixFilePermissions.fromString("rwxr-x---"));reject(()->new NonceReservations(shared,FP,128));
            Path links=privateDir(root,"links");Path target=root.resolve("target");Files.write(target,new byte[]{1,2,3});Files.createSymbolicLink(links.resolve(FP+".counter"),target);reject(()->new NonceReservations(links,FP,128).next());check(Arrays.equals(Files.readAllBytes(target),new byte[]{1,2,3}),"symlink target preserved");events.add("nonce: restart, concurrent cursors, checksum, missing state, overflow, permissions and symlink passed");
            for(PqcExtension.Profile profile:List.of(PqcExtension.P3,PqcExtension.P5)){
                Path directory=privateDir(root,"engine-"+profile.category());
                try(PqcExtension.Engine engine=new PqcExtension.Engine(profile,PqcExtension.CONTEXT,directory)){
                    byte[] message=new byte[4096];new SecureRandom().nextBytes(message);
                    PqcExtension.Prepared first=engine.prepare(profile,PqcExtension.CONTEXT);PqcExtension.Packet historical=engine.seal(first,message);check(Arrays.equals(message,engine.open(first,historical)),"authenticated packet roundtrip");
                    reject(()->engine.seal(first,message));reject(()->engine.open(first,historical.changedCiphertext()));reject(()->engine.open(first,historical.changedCapsule()));reject(()->engine.prepare(profile,"wrong-context"));reject(()->engine.prepare(new PqcExtension.Profile(profile.policyVersion(),profile.keyVersion(),"X25519",profile.signature(),profile.category(),profile.provider(),true),PqcExtension.CONTEXT));
                    reject(()->engine.seal(null,message));reject(()->engine.seal(engine.prepare(profile,PqcExtension.CONTEXT),null));
                    for(int i=0;i<10;i++){PqcExtension.Prepared prepared=engine.prepare(profile,PqcExtension.CONTEXT);PqcExtension.Packet packet=engine.seal(prepared,message);check(Arrays.equals(message,engine.open(prepared,packet)),"repeated authenticated operations");}
                    for(int size:new int[]{0,1,16*1024*1024}){byte[] boundary=new byte[size];PqcExtension.Prepared prepared=engine.prepare(profile,PqcExtension.CONTEXT);PqcExtension.Packet packet=engine.seal(prepared,boundary);check(Arrays.equals(boundary,engine.open(prepared,packet)),"packet size boundary");}
                    reject(()->engine.seal(engine.prepare(profile,PqcExtension.CONTEXT),new byte[16*1024*1024+1]));
                    check(engine.reservationWrites(first)==1,"block reservation amortizes I/O");
                    try(PqcExtension.Engine other=new PqcExtension.Engine(profile,PqcExtension.CONTEXT,privateDir(root,"foreign-"+profile.category()))){reject(()->other.seal(first,message));reject(()->other.open(first,historical));}
                    // Active policy changes only affect new requests; captured approved request remains stable.
                    PqcExtension.Prepared captured=engine.prepare(profile,PqcExtension.CONTEXT);
                    PqcExtension.Profile nextProfile=new PqcExtension.Profile(profile.policyVersion()+10,profile.keyVersion()+10,profile.kem(),profile.signature(),profile.category(),profile.provider(),true);engine.activate(nextProfile);reject(()->engine.prepare(profile,PqcExtension.CONTEXT));
                    PqcExtension.Packet capturedPacket=engine.seal(captured,message);check(Arrays.equals(message,engine.open(captured,capturedPacket)),"captured snapshot executes unchanged after administrative update");check(Arrays.equals(message,engine.open(first,historical)),"historical packet readable under original snapshot");
                    PqcExtension.Prepared current=engine.prepare(nextProfile,PqcExtension.CONTEXT);PqcExtension.Packet fresh=engine.seal(current,message);check(Arrays.equals(message,engine.open(current,fresh)),"new policy works");reject(()->engine.open(current,historical));reject(()->engine.activate(profile));
                    PqcExtension.Prepared concurrent=engine.prepare(nextProfile,PqcExtension.CONTEXT);var workers=Executors.newFixedThreadPool(4);List<Future<Boolean>> results=new ArrayList<>();
                    try{for(int i=0;i<8;i++)results.add(workers.submit(()->{try{engine.seal(concurrent,message);return true;}catch(SecurityException expected){return false;}}));int accepted=0;for(var f:results)if(f.get())accepted++;check(accepted==1,"concurrent single-use request");}finally{workers.shutdownNow();}
                    Arrays.fill(message,(byte)0);
                }
                events.add("profile "+profile.category()+": validated request, authenticated packet, policy rotation, ownership and concurrent single-use passed");
            }
            try(PqcExtension.Engine migrating=new PqcExtension.Engine(PqcExtension.P3,PqcExtension.CONTEXT,privateDir(root,"pqc-profile-migration"))){
                PqcExtension.Prepared old=migrating.prepare(PqcExtension.P3,PqcExtension.CONTEXT);PqcExtension.Packet packet=migrating.seal(old,new byte[64]);migrating.activate(PqcExtension.P5);check(migrating.open(old,packet).length==64,"P3 history preserved after P5 transition");
                PqcExtension.Prepared current=migrating.prepare(PqcExtension.P5,PqcExtension.CONTEXT);PqcExtension.Packet fresh=migrating.seal(current,new byte[64]);check(migrating.open(current,fresh).length==64,"P5 normal execution after migration");reject(()->migrating.prepare(PqcExtension.P3,PqcExtension.CONTEXT));
                reject(()->migrating.activate(new PqcExtension.Profile(3,3,PqcExtension.P3.kem(),PqcExtension.P3.signature(),3,"BC",true)));
            }
            for(PqcExtension.Step fail:List.of(PqcExtension.Step.AFTER_RESERVATION,PqcExtension.Step.BEFORE_ENCAPSULATION,PqcExtension.Step.BEFORE_SIGNATURE)){
                try(PqcExtension.Engine engine=new PqcExtension.Engine(PqcExtension.P3,PqcExtension.CONTEXT,privateDir(root,"fault-"+fail),step->{if(step==fail)throw new GeneralSecurityException("Synthetic execution adapter failure");})){
                    PqcExtension.Prepared request=engine.prepare(PqcExtension.P3,PqcExtension.CONTEXT);reject(()->engine.seal(request,new byte[1]));check(engine.reservationWrites(request)==1,"failure burns reserved range");reject(()->engine.seal(request,new byte[1]));
                }
            }
            for(PqcExtension.Step failure:List.of(PqcExtension.Step.BEFORE_VERIFICATION,PqcExtension.Step.BEFORE_DECRYPTION)){
                java.util.concurrent.atomic.AtomicBoolean enabled=new java.util.concurrent.atomic.AtomicBoolean();
                try(PqcExtension.Engine engine=new PqcExtension.Engine(PqcExtension.P3,PqcExtension.CONTEXT,privateDir(root,"read-fault-"+failure),step->{if(enabled.get() && step==failure)throw new GeneralSecurityException("Synthetic read adapter failure");})){
                    PqcExtension.Prepared request=engine.prepare(PqcExtension.P3,PqcExtension.CONTEXT);PqcExtension.Packet packet=engine.seal(request,new byte[32]);enabled.set(true);reject(()->engine.open(request,packet));enabled.set(false);check(engine.open(request,packet).length==32,"read after transient adapter failure");
                }
            }
            reject(()->new PqcExtension.Engine(PqcExtension.P3,"\ud800",privateDir(root,"bad-utf")));reject(()->new PqcExtension.Engine(PqcExtension.P3,"a".repeat(65),privateDir(root,"long-context")));
            PqcExtension.Engine closed=new PqcExtension.Engine(PqcExtension.P3,PqcExtension.CONTEXT,privateDir(root,"closed"));PqcExtension.Prepared token=closed.prepare(PqcExtension.P3,PqcExtension.CONTEXT);closed.close();reject(()->closed.prepare(PqcExtension.P3,PqcExtension.CONTEXT));reject(()->closed.seal(token,new byte[0]));events.add("execution adapter faults and strict context/closed-engine refusal passed");
            for(var constructor:PqcExtension.Prepared.class.getDeclaredConstructors())check(java.lang.reflect.Modifier.isPrivate(constructor.getModifiers()),"request cannot be constructed externally");
            reject(()->new NonceReservations(counters,null,128));
            check(!PqcExtension.listed(new PqcExtension.Profile(1,1,null,null,3,null,true)),"null profile fields reject");
            Path output=Path.of(args[0]);Files.createDirectories(output);Files.writeString(output.resolve("stability.log"),String.join("\n",events)+"\nPASS checks="+checks+"\n");System.out.println("PASS integrated stability checks="+checks);
        }finally{try(var walk=Files.walk(root)){for(Path p:walk.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}}
    }
}
