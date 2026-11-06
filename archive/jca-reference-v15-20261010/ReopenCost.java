import java.nio.file.*;
import java.util.*;

/** Compile this unchanged against both v14 and v15; identical normal checkpoint fixture. */
public final class ReopenCost {
    public static void main(String[] args)throws Exception {
        Path root=Path.of(args[0]),out=Path.of(args[1]);String variant=args[2];int fork=Integer.parseInt(args[3]);byte[] master=Files.readAllBytes(root.resolve("master.key"));StringBuilder rows=new StringBuilder("fork,variant,profile,sample,ns,allocated_bytes\n");
        var bean=(com.sun.management.ThreadMXBean)java.lang.management.ManagementFactory.getThreadMXBean();boolean supported=bean.isThreadAllocatedMemorySupported();if(supported)bean.setThreadAllocatedMemoryEnabled(true);long id=Thread.currentThread().getId();
        try{for(int profile:new int[]{3,5}){
            Path data=root.resolve("data"+profile),anchor=root.resolve("anchor"+profile);
            for(int sample=-20;sample<31;sample++){
                long allocated=supported?bean.getThreadAllocatedBytes(id):0,start=System.nanoTime();PqcExtension.Engine e=PqcExtension.Engine.reopen("normal-reopen-v15",data,anchor,master,false);
                long ns=System.nanoTime()-start,bytes=supported?bean.getThreadAllocatedBytes(id)-allocated:-1;
                try(e){if(e.currentProfile().category()!=profile)throw new AssertionError("Profile recovery");}
                if(sample>=0)rows.append(fork).append(',').append(variant).append(',').append(profile).append(',').append(sample).append(',').append(ns).append(',').append(bytes).append('\n');
            }
        }}finally{Arrays.fill(master,(byte)0);}
        Files.writeString(out,rows);System.out.println("PASS normal reopen cost rows=62 variant="+variant+" fork="+fork);
    }
}
