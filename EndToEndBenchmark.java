import java.nio.file.*;
import java.nio.file.attribute.*;
import java.util.*;
public final class EndToEndBenchmark {
    private static volatile Object sink;
    public static void main(String[] args)throws Exception {
        Path out=Path.of(args[0]);Files.createDirectories(out);var bean=(com.sun.management.ThreadMXBean)java.lang.management.ManagementFactory.getThreadMXBean();if(!bean.isThreadAllocatedMemorySupported())throw new IllegalStateException("Allocation unsupported");bean.setThreadAllocatedMemoryEnabled(true);long thread=Thread.currentThread().getId();
        StringBuilder csv=new StringBuilder("profile,component,sample,ns,thread_allocated_bytes\n");Path temp=Files.createTempDirectory("pqc-request-cost-",PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        List<PqcExtension.Profile> profiles=Integer.parseInt(args[1])%2==0?List.of(PqcExtension.P3,PqcExtension.P5):List.of(PqcExtension.P5,PqcExtension.P3);
        try{
            for(var profile:profiles){Path dir=Files.createDirectory(temp.resolve("p"+profile.category()),PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));byte[] message=new byte[4096];
                try(PqcExtension.Engine engine=new PqcExtension.Engine(profile,PqcExtension.CONTEXT,dir)){
                    for(int i=-20;i<31;i++){
                        long before=bean.getThreadAllocatedBytes(thread),start=System.nanoTime();var request=engine.prepare(profile,PqcExtension.CONTEXT);var packet=engine.seal(request,message);long ns=System.nanoTime()-start,bytes=bean.getThreadAllocatedBytes(thread)-before;sink=packet;
                        if(i>=0)csv.append(profile.category()).append(",prepare_seal_4096,").append(i).append(',').append(ns).append(',').append(bytes).append('\n');
                    }
                    var request=engine.prepare(profile,PqcExtension.CONTEXT);var packet=engine.seal(request,message);
                    for(int i=-20;i<31;i++){
                        long before=bean.getThreadAllocatedBytes(thread),start=System.nanoTime();byte[] opened=engine.open(request,packet);long ns=System.nanoTime()-start,bytes=bean.getThreadAllocatedBytes(thread)-before;
                        if(!Arrays.equals(message,opened))throw new AssertionError("Integrated request roundtrip");sink=opened.length;Arrays.fill(opened,(byte)0);
                        if(i>=0)csv.append(profile.category()).append(",verify_open_4096,").append(i).append(',').append(ns).append(',').append(bytes).append('\n');
                    }
                }
            }
        }finally{try(var walk=Files.walk(temp)){for(Path p:walk.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}}
        Files.writeString(out.resolve("request-cost.csv"),csv);System.out.println("PASS warm integrated request cost rows=124");
    }
}
