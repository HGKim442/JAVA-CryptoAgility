import java.nio.file.*;
import java.util.*;
import java.lang.management.*;
import java.io.*;

/** Fresh JVM for each worker/profile/size condition, shared live store without cloning. */
public final class ParallelBatchBenchmark {
    public static void main(String[] args)throws Exception {
        Path out=Path.of(args[0]);int workers=Integer.parseInt(args[1]),size=Integer.parseInt(args[2]);
        Path fixture=Path.of(args[3]);byte[] master=CryptoCli.read(fixture.resolve("master.key").toString(),32,true);
        Files.createDirectories(out);Files.setPosixFilePermissions(out,java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));List<Path> inputs=new ArrayList<>();for(int i=0;i<8;i++)inputs.add(fixture.resolve("input-"+size+"-"+i));
        Path work=Files.createTempDirectory(out,".parallel-work-",java.nio.file.attribute.PosixFilePermissions.asFileAttribute(java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")));
        List<MemoryPoolMXBean> heaps=ManagementFactory.getMemoryPoolMXBeans().stream().filter(p->p.getType()==MemoryType.HEAP).toList();
        try(var engine=PqcExtension.Engine.reopen("parallel-cost",fixture.resolve("data"),fixture.resolve("anchor"),master,false);
            PrintWriter csv=new PrintWriter(Files.newBufferedWriter(out.resolve("parallel-cost.csv")))){
            csv.println("profile,workers,message_bytes,files,sample,wall_ns,heap_pool_peak_sum_bytes,rss_hwm_bytes");
            for(int sample=-1;sample<3;sample++){
                List<Path> outputs=new ArrayList<>();for(int i=0;i<8;i++)outputs.add(work.resolve("packet-"+sample+"-"+i));
                System.gc();for(var heap:heaps)heap.resetPeakUsage();
                long start=System.nanoTime();engine.sealFiles(inputs,outputs,workers);long elapsed=System.nanoTime()-start;
                long heapPeak=heaps.stream().mapToLong(p->p.getPeakUsage().getUsed()).sum();
                long rss=0;for(String line:Files.readAllLines(Path.of("/proc/self/status")))if(line.startsWith("VmHWM:"))rss=Long.parseLong(line.trim().split("\\s+")[1])*1024;
                if(sample>=0)csv.printf(Locale.ROOT,"%d,%d,%d,8,%d,%d,%d,%d%n",engine.currentProfile().category(),workers,size,sample,elapsed,heapPeak,rss);
                // Verify every file outside timing, then remove the published fixtures.
                for(int i=0;i<8;i++){
                    var packet=PqcExtension.Packet.decode(Files.readAllBytes(outputs.get(i)));byte[] plain=engine.open(engine.prepareHistorical(engine.currentProfile().policyVersion()),packet),source=Files.readAllBytes(inputs.get(i));
                    try{if(!Arrays.equals(plain,source))throw new AssertionError("Parallel benchmark output");}finally{PqcExtension.wipe(plain,source);}
                    Files.delete(outputs.get(i));
                }
            }
            PacketCodecBenchmark.requireOutput(csv);
        }finally{
            PqcExtension.wipe(master);
            try(var files=Files.walk(work)){for(Path path:files.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(path);}
            try(var channel=java.nio.channels.FileChannel.open(out,StandardOpenOption.READ)){channel.force(true);}
        }
        Files.writeString(out.resolve("parallel-normal-checks.json"),"{\"passed\":true,\"normal_decryptions\":32,\"measured_rows\":3}\n");
        System.out.println("PASS parallel normal cost workers="+workers+" bytes="+size);
    }
}
