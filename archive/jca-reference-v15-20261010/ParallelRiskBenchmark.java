import java.nio.file.*;
import java.util.*;
import java.lang.management.*;
import java.io.*;
import java.lang.reflect.*;

/** Identical harness compiled against original and revised engines. */
public final class ParallelRiskBenchmark {
    public static void main(String[] args)throws Exception {
        Path out=Path.of(args[0]),fixture=Path.of(args[3]);int requested=Integer.parseInt(args[1]),size=Integer.parseInt(args[2]);
        byte[] master=CryptoCli.read(fixture.resolve("master.key").toString(),32,true);
        Files.createDirectories(out);Files.setPosixFilePermissions(out,java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));
        Path work=Files.createTempDirectory(out,".parallel-work-",java.nio.file.attribute.PosixFilePermissions.asFileAttribute(java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")));
        List<Path> inputs=new ArrayList<>();for(int i=0;i<8;i++)inputs.add(fixture.resolve("input-"+size+"-"+i));
        var heaps=ManagementFactory.getMemoryPoolMXBeans().stream().filter(p->p.getType()==MemoryType.HEAP).toList();
        Method batch=PqcExtension.Engine.class.getDeclaredMethod("sealFiles",List.class,List.class,int.class);
        try(var engine=PqcExtension.Engine.reopen("parallel-risk-cost",fixture.resolve("data"),fixture.resolve("anchor"),master,false);
            PrintWriter csv=new PrintWriter(Files.newBufferedWriter(out.resolve("cost.csv")))){
            csv.println("profile,requested_workers,effective_workers,message_bytes,files,sample,wall_ns,heap_pool_peak_sum_bytes,rss_hwm_bytes");
            for(int sample=-1;sample<3;sample++){
                List<Path> outputs=new ArrayList<>();for(int i=0;i<8;i++)outputs.add(work.resolve("out-"+sample+"-"+i));
                System.gc();for(var heap:heaps)heap.resetPeakUsage();
                long start=System.nanoTime();Object returned;
                try{returned=batch.invoke(engine,inputs,outputs,requested);}catch(InvocationTargetException error){throw new IllegalStateException("Benchmark engine failed",error.getCause());}
                long elapsed=System.nanoTime()-start;int effective=returned==null?requested:((Integer)returned).intValue();
                long peak=heaps.stream().mapToLong(p->p.getPeakUsage().getUsed()).sum(),rss=0;
                for(String line:Files.readAllLines(Path.of("/proc/self/status")))if(line.startsWith("VmHWM:"))rss=Long.parseLong(line.trim().split("\\s+")[1])*1024;
                if(sample>=0)csv.printf(Locale.ROOT,"%d,%d,%d,%d,8,%d,%d,%d,%d%n",engine.currentProfile().category(),requested,effective,size,sample,elapsed,peak,rss);
                for(int i=0;i<8;i++){
                    var packet=PqcExtension.Packet.decode(Files.readAllBytes(outputs.get(i)));byte[] plain=engine.open(engine.prepareHistorical(engine.currentProfile().policyVersion()),packet),source=Files.readAllBytes(inputs.get(i));
                    try{if(!Arrays.equals(plain,source))throw new AssertionError("Risk benchmark roundtrip");}finally{PqcExtension.wipe(plain,source);}
                    Files.delete(outputs.get(i));
                }
            }
            PacketCodecBenchmark.requireOutput(csv);
        }finally{PqcExtension.wipe(master);try(var files=Files.walk(work)){for(Path path:files.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(path);}}
        Files.writeString(out.resolve("checks.json"),"{\"passed\":true,\"normal_decryptions\":32,\"rows\":3}\n");
        System.out.println("PASS risk cost workers="+requested+" bytes="+size);
    }
}
