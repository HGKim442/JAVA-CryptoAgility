import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

public final class ParallelFollowupTest {
    static int checks;
    static void check(boolean value){if(!value)throw new AssertionError("Parallel followup");checks++;}
    public static void main(String[] args)throws Exception {
        Path root=Files.createTempDirectory("parallel-followup-",java.nio.file.attribute.PosixFilePermissions.asFileAttribute(java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")));
        try{
            for(var profile:List.of(PqcExtension.P3,PqcExtension.P5)){
                Path dir=ParallelBatchTest.directory(root,"preflight-"+profile.category());List<Path> in=ParallelBatchTest.inputs(dir,4,4096);
                try(var engine=new PqcExtension.Engine(profile,"followup",dir)){
                    List<Path> missing=new ArrayList<>(in);missing.set(3,dir.resolve("missing"));
                    try{engine.sealFiles(missing,ParallelBatchTest.outputs(dir,4,"bad-"),4);throw new AssertionError();}catch(java.io.IOException expected){check(true);}
                    check(engine.reservationWrites(engine.prepare(profile,"followup"))==0);
                    List<Path> out=ParallelBatchTest.outputs(dir,4,"good-");check(engine.sealFiles(in,out,4)==4);
                    check(ParallelBatchTest.nonce(PqcExtension.Packet.decode(Files.readAllBytes(out.get(0))))==0);
                    for(int i=0;i<4;i++){
                        byte[] plain=engine.open(engine.prepareHistorical(profile.policyVersion()),PqcExtension.Packet.decode(Files.readAllBytes(out.get(i))));
                        try{check(Arrays.equals(plain,Files.readAllBytes(in.get(i))));}finally{PqcExtension.wipe(plain);}
                    }
                }
                Path dir2=ParallelBatchTest.directory(root,"interrupt-"+profile.category());List<Path> one=ParallelBatchTest.inputs(dir2,1,4096);Path output=dir2.resolve("packet");
                CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);AtomicBoolean armed=new AtomicBoolean(true),restored=new AtomicBoolean();AtomicReference<Throwable> failure=new AtomicReference<>();
                var engine=new PqcExtension.Engine(profile,"followup",dir2,step->{if(armed.get() && step==PqcExtension.Step.AFTER_RESERVATION){entered.countDown();try{release.await();}catch(InterruptedException e){Thread.currentThread().interrupt();}}});
                Thread thread=new Thread(()->{try{engine.sealFiles(one,List.of(output),4);}catch(Throwable e){failure.set(e);restored.set(Thread.currentThread().isInterrupted());}});
                try{
                    thread.start();check(entered.await(10,TimeUnit.SECONDS));thread.interrupt();release.countDown();thread.join(10000);
                    check(!thread.isAlive());check(failure.get() instanceof InterruptedException);check(restored.get());check(!Files.exists(output));
                    armed.set(false);List<Path> retry=List.of(dir2.resolve("retry"));check(engine.sealFiles(one,retry,4)==1);
                    check(ParallelBatchTest.nonce(PqcExtension.Packet.decode(Files.readAllBytes(retry.get(0))))==1);
                }finally{release.countDown();thread.join(10000);engine.close();}
            }
        }finally{try(var paths=Files.walk(root)){for(Path path:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(path);}}
        Path output=Path.of(args[0]);Files.createDirectories(output);Files.writeString(output.resolve("parallel-followup-checks.json"),"{\"passed\":true,\"checks\":"+checks+",\"scope\":\"P3/P5 missing-last-input rejects without nonce commit, normal authenticated retry; requested4/effective1 interruption has InterruptedException and flag, no publication, consumed nonce skipped\"}\n");
        System.out.println("PASS parallel followup checks="+checks);
    }
}
