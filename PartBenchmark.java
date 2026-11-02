import java.nio.file.*;
import java.nio.file.attribute.*;
import java.util.*;

public final class PartBenchmark {
    private static volatile int sink;private static volatile byte[] sinkBytes;
    private static final String FP="b".repeat(64);
    public static void main(String[] args)throws Exception {
        if(args[0].equals("worker")){
            NonceReservations cursor=new NonceReservations(Path.of(args[1]),FP,128);StringJoiner values=new StringJoiner(",");for(int i=0;i<Integer.parseInt(args[2]);i++)values.add(Long.toString(cursor.next()));System.out.println(values);return;
        }
        if(args[0].equals("crash")){
            NonceReservations cursor=new NonceReservations(Path.of(args[1]),FP,128);System.out.println("RESERVED="+cursor.next());System.out.flush();new java.util.concurrent.CountDownLatch(1).await();return;
        }
        Path out=Path.of(args[0]);Files.createDirectories(out);
        var bean=(com.sun.management.ThreadMXBean)java.lang.management.ManagementFactory.getThreadMXBean();if(!bean.isThreadAllocatedMemorySupported())throw new IllegalStateException("Allocation unsupported");bean.setThreadAllocatedMemoryEnabled(true);long thread=Thread.currentThread().getId();
        StringBuilder csv=new StringBuilder("part,variant,sample,batch_operations,ns,thread_allocated_bytes,durable_reservations\n");
        for(int index=0;index<2;index++){
            boolean cached=(index+Integer.parseInt(args[1]))%2==1;PqcExtension.BindingCache binding=new PqcExtension.BindingCache(PqcExtension.P3,PqcExtension.CONTEXT);
            if(!Arrays.equals(binding.copy(),PqcExtension.uncachedBinding(PqcExtension.P3,PqcExtension.CONTEXT)))throw new AssertionError("Binding bytes differ");
            for(int sample=-1000;sample<101;sample++){
                long before=bean.getThreadAllocatedBytes(thread),start=System.nanoTime();int consumed=0;
                for(int i=0;i<100;i++){byte[] value=cached?binding.copy():PqcExtension.uncachedBinding(PqcExtension.P3,PqcExtension.CONTEXT);sinkBytes=value;consumed+=value.length+value[0];}
                long ns=System.nanoTime()-start,bytes=bean.getThreadAllocatedBytes(thread)-before;sink=consumed;
                if(sample>=0)csv.append("binding,").append(cached?"cached_copy":"format_each_call").append(',').append(sample).append(",100,").append(ns).append(',').append(bytes).append(",0\n");
            }
        }
        Path temp=Files.createTempDirectory("nonce-cost-",PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        try{
            for(int index=0;index<2;index++){
                int block=(index+Integer.parseInt(args[1]))%2==0?1:128;Path dir=Files.createDirectory(temp.resolve("block-"+block),PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));NonceReservations cursor=new NonceReservations(dir,FP,block);
                for(int sample=-10;sample<31;sample++){
                    long count=cursor.reservationWrites(),before=bean.getThreadAllocatedBytes(thread),start=System.nanoTime();long consumed=0;for(int i=0;i<32;i++)consumed^=cursor.next();long ns=System.nanoTime()-start,bytes=bean.getThreadAllocatedBytes(thread)-before;long writes=cursor.reservationWrites()-count;sink=(int)consumed;
                    if(sample>=0)csv.append("nonce,block_").append(block).append(',').append(sample).append(",32,").append(ns).append(',').append(bytes).append(',').append(writes).append('\n');
                }
            }
        }finally{try(var walk=Files.walk(temp)){for(Path p:walk.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}}
        Files.writeString(out.resolve("part-cost.csv"),csv);System.out.println("PASS binding byte equivalence; measured rows=264");
    }
}
