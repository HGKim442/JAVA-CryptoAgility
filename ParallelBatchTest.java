import java.nio.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

/** Normal concurrent operation and benign coordination/failure fixtures. */
public final class ParallelBatchTest {
    static int checks;static final String CONTEXT="parallel-normal";
    static void check(boolean value){if(!value)throw new AssertionError("Parallel batch");checks++;}
    static Path directory(Path root,String name)throws Exception{return Files.createDirectory(root.resolve(name),PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));}
    static List<Path> inputs(Path root,int count,int size)throws Exception {
        List<Path> result=new ArrayList<>();byte[] data=new byte[size];new Random(27).nextBytes(data);
        for(int i=0;i<count;i++){Path path=root.resolve("in-"+i);Files.write(path,data);Files.setPosixFilePermissions(path,PosixFilePermissions.fromString("rw-------"));result.add(path);}PqcExtension.wipe(data);return result;
    }
    static List<Path> outputs(Path root,int count,String prefix){List<Path> result=new ArrayList<>();for(int i=0;i<count;i++)result.add(root.resolve(prefix+i));return result;}
    static long nonce(PqcExtension.Packet packet)throws Exception {var f=PqcExtension.Packet.class.getDeclaredField("nonce");f.setAccessible(true);return ByteBuffer.wrap((byte[])f.get(packet),4,8).getLong();}
    static void verify(PqcExtension.Engine engine,List<Path> inputs,List<Path> outputs,Set<Long> seen)throws Exception {
        long previous=-1;
        for(int i=0;i<outputs.size();i++){
            var packet=PqcExtension.Packet.decode(Files.readAllBytes(outputs.get(i)));long n=nonce(packet);check(seen.add(n));check(n>previous);previous=n;
            byte[] plain=engine.open(engine.prepareHistorical(engine.currentProfile().policyVersion()),packet),source=Files.readAllBytes(inputs.get(i));
            try{check(Arrays.equals(plain,source));}finally{PqcExtension.wipe(plain,source);}
            check(Files.getPosixFilePermissions(outputs.get(i)).equals(PosixFilePermissions.fromString("rw-------")));
        }
    }
    static void blocked(Thread thread)throws Exception {
        long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(10);
        while(thread.getState()!=Thread.State.BLOCKED && System.nanoTime()<end)Thread.sleep(1);
        check(thread.getState()==Thread.State.BLOCKED);
    }
    static void lifetime(Path root,String action)throws Exception {
        Path dir=directory(root,action);List<Path> inputs=inputs(dir,2,4096),outputs=outputs(dir,2,"out-");
        CountDownLatch entered=new CountDownLatch(2),release=new CountDownLatch(1);AtomicBoolean armed=new AtomicBoolean();
        PqcExtension.Fault fault=step->{if(armed.get() && step==PqcExtension.Step.AFTER_RESERVATION){entered.countDown();try{if(!release.await(10,TimeUnit.SECONDS))throw new java.security.GeneralSecurityException("Fixture timeout");}catch(InterruptedException e){Thread.currentThread().interrupt();throw new java.security.GeneralSecurityException(e);}}};
        var engine=new PqcExtension.Engine(PqcExtension.P3,CONTEXT,dir,fault);
        try{
            if(action.equals("retire"))engine.activate(PqcExtension.P5);
            armed.set(true);AtomicReference<Throwable> batchFailure=new AtomicReference<>(),adminFailure=new AtomicReference<>();AtomicBoolean interruptRestored=new AtomicBoolean();
            Thread batch=new Thread(()->{try{engine.sealFiles(inputs,outputs,2);}catch(Throwable e){batchFailure.set(e);interruptRestored.set(Thread.currentThread().isInterrupted());}},"batch-fixture");batch.start();
            try{
                check(entered.await(10,TimeUnit.SECONDS));
                if(action.equals("interrupt"))batch.interrupt();
                Thread admin=new Thread(()->{try{if(action.equals("activate"))engine.activate(PqcExtension.P5);else if(action.equals("retire"))engine.retire(1);else engine.close();}catch(Throwable e){adminFailure.set(e);}},"admin-fixture");admin.start();blocked(admin);check(batch.isAlive());
                if(action.equals("interrupt")){long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(10);while(batch.getState()!=Thread.State.TIMED_WAITING && System.nanoTime()<end)Thread.sleep(1);if(batch.getState()!=Thread.State.TIMED_WAITING)throw new AssertionError("Coordinator did not enter drain");}
                release.countDown();batch.join(10000);admin.join(10000);check(!batch.isAlive() && !admin.isAlive());check(adminFailure.get()==null);
                if(action.equals("interrupt")){check(batchFailure.get() instanceof InterruptedException);check(interruptRestored.get());}
                else check(batchFailure.get()==null);
                for(Path output:outputs)check(Files.exists(output)!=action.equals("interrupt"));
            }finally{release.countDown();batch.join(10000);}
        }finally{engine.close();}
    }
    public static void main(String[] args)throws Exception {
        Path root=Files.createTempDirectory("parallel-test-",PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));byte[] master=new byte[32];Arrays.fill(master,(byte)57);
        try{
            for(var profile:List.of(PqcExtension.P3,PqcExtension.P5)){
                Path data=directory(root,"data-"+profile.category()),anchor=directory(root,"anchor-"+profile.category());List<Path> input=inputs(data,8,4096);Set<Long> seen=new HashSet<>();
                try(var engine=PqcExtension.Engine.createPersistent(profile,CONTEXT,data,anchor,master)){
                    for(int workers:new int[]{1,2,4}){List<Path> out=outputs(data,8,"w"+workers+"-");engine.sealFiles(input,out,workers);verify(engine,input,out,seen);}
                    long before=engine.reservationWrites(engine.prepare(profile,CONTEXT));
                    for(int workers:new int[]{0,3,5})try{engine.sealFiles(input,outputs(data,8,"invalid-"),workers);throw new AssertionError();}catch(IllegalArgumentException expected){check(true);}
                    for(List<Path> bad:List.of(List.<Path>of(),Collections.nCopies(65,input.get(0)),input.subList(0,7)))try{engine.sealFiles(bad,outputs(data,8,"invalid-count-"),4);throw new AssertionError();}catch(IllegalArgumentException expected){check(true);}
                    try{engine.sealFiles(input,Collections.nCopies(8,data.resolve("duplicate")),4);throw new AssertionError();}catch(java.io.IOException expected){check(true);}
                    check(engine.reservationWrites(engine.prepare(profile,CONTEXT))==before);
                    List<Path> missing=new ArrayList<>(input);missing.set(0,data.resolve("missing"));
                    try{engine.sealFiles(missing,outputs(data,8,"missing-out-"),4);throw new AssertionError();}catch(java.io.IOException expected){check(true);}
                    List<Path> after=outputs(data,8,"after-failure-");engine.sealFiles(input,after,4);check(nonce(PqcExtension.Packet.decode(Files.readAllBytes(after.get(0))))==24);verify(engine,input,after,seen);
                    List<Path> full=Collections.nCopies(64,input.get(0));
                    for(int round=0;round<2;round++){List<Path> out=outputs(data,64,"full-"+round+"-");engine.sealFiles(full,out,4);verify(engine,full,out,seen);}
                    check(engine.reservationWrites(engine.prepare(profile,CONTEXT))==2);
                    try(var files=Files.list(data)){check(files.noneMatch(p->p.getFileName().toString().startsWith(".pqc-output-")));}
                }
                try(var reopened=PqcExtension.Engine.reopen(CONTEXT,data,anchor,master,false)){
                    List<Path> out=outputs(data,8,"reopened-");reopened.sealFiles(input,out,4);verify(reopened,input,out,seen);
                }
            }
            Path large=directory(root,"max-size");List<Path> input=inputs(large,4,16*1024*1024),out=outputs(large,4,"large-");
            try(var engine=new PqcExtension.Engine(PqcExtension.P5,CONTEXT,large)){engine.sealFiles(input,out,4);verify(engine,input,out,new HashSet<>());}
            for(String action:List.of("activate","retire","close","interrupt"))lifetime(root,action);
            Path failed=directory(root,"signature-failure");AtomicBoolean armed=new AtomicBoolean(true);
            try(var engine=new PqcExtension.Engine(PqcExtension.P3,CONTEXT,failed,step->{if(armed.get() && step==PqcExtension.Step.BEFORE_SIGNATURE)throw new java.security.SignatureException("Synthetic signing failure");})){
                List<Path> in=inputs(failed,4,4096);
                try{engine.sealFiles(in,outputs(failed,4,"failed-"),4);throw new AssertionError();}catch(java.security.SignatureException expected){check(true);}
                armed.set(false);List<Path> after=outputs(failed,4,"after-");engine.sealFiles(in,after,4);check(nonce(PqcExtension.Packet.decode(Files.readAllBytes(after.get(0))))==4);verify(engine,in,after,new HashSet<>());
            }
        }finally{PqcExtension.wipe(master);try(var files=Files.walk(root)){for(Path path:files.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(path);}}
        Path out=Path.of(args[0]);Files.createDirectories(out);Files.writeString(out.resolve("parallel-batch-checks.json"),"{\"passed\":true,\"checks\":"+checks+",\"scope\":\"P3/P5 workers1/2/4 authenticated roundtrips, nonce order/uniqueness and reopen, 4x16MiB, invalid arguments, missing input, synthetic signing failure, policy/retirement/close pinning and interrupted coordinator drain\"}\n");
        System.out.println("PASS parallel batch checks="+checks);
    }
}
