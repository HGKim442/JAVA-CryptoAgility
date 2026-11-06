import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

/** Bounded-memory planning, mutable input refusal and cooperative failure. */
public final class ParallelRiskTest {
    static int checks;
    static void check(boolean value){if(!value)throw new AssertionError("Parallel risk regression");checks++;}
    static void await(CountDownLatch latch)throws java.security.GeneralSecurityException {
        try{if(!latch.await(10,TimeUnit.SECONDS))throw new java.security.GeneralSecurityException("Fixture timeout");}
        catch(InterruptedException e){Thread.currentThread().interrupt();throw new java.security.GeneralSecurityException(e);}
    }
    public static void main(String[] args)throws Exception {
        long mib=1024L*1024;
        check(PqcExtension.Engine.batchWorkerLimit(4,8,mib,512*mib)==4);
        check(PqcExtension.Engine.batchWorkerLimit(4,8,16*mib,512*mib)==2);
        check(PqcExtension.Engine.batchWorkerLimit(4,8,16*mib,256*mib)==1);
        check(PqcExtension.Engine.batchWorkerLimit(4,1,0,512*mib)==1);
        check(PqcExtension.Engine.batchWorkerLimit(1,8,16*mib,512*mib)==1);
        for(long[] invalid:new long[][]{{3,8,1,512*mib},{4,0,1,512*mib},{4,8,16*mib+1,512*mib},{4,8,1,0}})
            try{PqcExtension.Engine.batchWorkerLimit((int)invalid[0],(int)invalid[1],invalid[2],invalid[3]);throw new AssertionError();}catch(IllegalArgumentException expected){check(true);}
        Path root=Files.createTempDirectory("parallel-risk-",java.nio.file.attribute.PosixFilePermissions.asFileAttribute(java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")));
        try{
            Path growing=ParallelBatchTest.directory(root,"growing");List<Path> in=ParallelBatchTest.inputs(growing,2,4096),out=ParallelBatchTest.outputs(growing,2,"out-");AtomicBoolean changed=new AtomicBoolean();
            try(var engine=new PqcExtension.Engine(PqcExtension.P3,"risk",growing,step->{if(step==PqcExtension.Step.AFTER_RESERVATION && changed.compareAndSet(false,true))try{Files.write(in.get(1),new byte[8192]);}catch(java.io.IOException e){throw new java.security.GeneralSecurityException(e);}})){
                try{engine.sealFiles(in,out,1);throw new AssertionError();}catch(java.io.IOException expected){check(true);}
                check(Files.exists(out.get(0)));check(!Files.exists(out.get(1)));
                byte[] plain=engine.open(engine.prepareHistorical(1),PqcExtension.Packet.decode(Files.readAllBytes(out.get(0))));
                try{check(Arrays.equals(plain,Files.readAllBytes(in.get(0))));}finally{PqcExtension.wipe(plain);}
            }
            Path failed=ParallelBatchTest.directory(root,"failure");List<Path> sources=ParallelBatchTest.inputs(failed,8,4096),outputs=ParallelBatchTest.outputs(failed,8,"out-");
            CountDownLatch entered=new CountDownLatch(2),release=new CountDownLatch(1);AtomicInteger reservations=new AtomicInteger(),encapsulations=new AtomicInteger(),signatures=new AtomicInteger();AtomicReference<Throwable> failure=new AtomicReference<>();
            var engine=new PqcExtension.Engine(PqcExtension.P3,"risk",failed,step->{
                if(step==PqcExtension.Step.AFTER_RESERVATION){int slot=reservations.incrementAndGet();entered.countDown();await(entered);if(slot==2)await(release);}
                if(step==PqcExtension.Step.BEFORE_ENCAPSULATION)encapsulations.incrementAndGet();
                if(step==PqcExtension.Step.BEFORE_SIGNATURE){signatures.incrementAndGet();throw new java.security.SignatureException("Synthetic original failure");}
            });
            Thread coordinator=new Thread(()->{try{engine.sealFiles(sources,outputs,2);}catch(Throwable error){failure.set(error);}},"risk-coordinator");
            try{
                coordinator.start();check(entered.await(10,TimeUnit.SECONDS));long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(10);
                while(coordinator.getState()!=Thread.State.TIMED_WAITING && System.nanoTime()<end)Thread.sleep(1);
                check(coordinator.getState()==Thread.State.TIMED_WAITING);check(coordinator.isAlive());
                release.countDown();coordinator.join(10000);check(!coordinator.isAlive());
                check(failure.get() instanceof java.security.SignatureException);check(reservations.get()==2);check(encapsulations.get()==1);check(signatures.get()==1);
                for(Path output:outputs)check(!Files.exists(output));
            }finally{release.countDown();coordinator.join(10000);engine.close();}
            Path api=ParallelBatchTest.directory(root,"public-api");byte[] caller=new byte[4096];Arrays.fill(caller,(byte)93);byte[] expected=caller.clone();
            try(var publicEngine=new PqcExtension.Engine(PqcExtension.P3,"risk",api)){
                var packet=publicEngine.seal(publicEngine.prepare(PqcExtension.P3,"risk"),caller);check(Arrays.equals(caller,expected));
                byte[] restored=publicEngine.open(publicEngine.prepareHistorical(1),packet);try{check(Arrays.equals(restored,expected));}finally{PqcExtension.wipe(restored);}
            }finally{PqcExtension.wipe(caller,expected);}
        }finally{try(var files=Files.walk(root)){for(Path path:files.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(path);}}
        Path out=Path.of(args[0]);Files.createDirectories(out);Files.writeString(out.resolve("parallel-risk-checks.json"),"{\"passed\":true,\"checks\":"+checks+",\"scope\":\"heap/size worker bounds, enlarged input refusal before allocation, actual earlier output roundtrip, gated signing failure preserves original cause and stops later crypto/publication, public input ownership\"}\n");
        System.out.println("PASS parallel risk checks="+checks);
    }
}
