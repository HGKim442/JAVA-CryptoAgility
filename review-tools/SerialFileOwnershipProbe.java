import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.lang.management.ManagementFactory;
import java.util.*;
import java.io.PrintWriter;

/** Same engine, input and publisher: legacy defensive clone versus owned file adapter. */
public final class SerialFileOwnershipProbe {
    public static void main(String[] args)throws Exception {
        int fork=Integer.parseInt(args[1]);
        var meter=(com.sun.management.ThreadMXBean)ManagementFactory.getThreadMXBean();
        if(!meter.isThreadAllocatedMemorySupported())throw new IllegalStateException("Allocation meter unavailable");
        meter.setThreadAllocatedMemoryEnabled(true);long thread=Thread.currentThread().getId();
        var dirPerm=PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"));
        Path root=Files.createTempDirectory("serial-owned-",dirPerm);int checks=0;
        try(PrintWriter csv=new PrintWriter(Files.newBufferedWriter(Path.of(args[0])))) {
            csv.println("fork,profile,bytes,sample,variant,ns,thread_allocated_bytes");
            for(var profile:List.of(PqcExtension.P3,PqcExtension.P5)) {
                Path state=Files.createDirectory(root.resolve("p"+profile.category()),dirPerm);
                try(var engine=new PqcExtension.Engine(profile,"serial-file-review",state)) {
                    for(int size:new int[]{4096,1048576,16777216}) {
                        byte[] message=new byte[size];new Random(42).nextBytes(message);
                        Path input=state.resolve("input"),output=state.resolve("output");Files.write(input,message);Files.setPosixFilePermissions(input,PosixFilePermissions.fromString("rw-------"));
                        for(int sample=-2;sample<5;sample++) {
                            List<String> variants=((sample+fork)&1)==0?List.of("defensive_clone","owned_file"):List.of("owned_file","defensive_clone");
                            for(String variant:variants) {
                                long before=meter.getThreadAllocatedBytes(thread),start=System.nanoTime();
                                if(variant.equals("defensive_clone")) {
                                    byte[] plain=CryptoCli.read(input.toString(),16*1024*1024,true);
                                    try{CryptoCli.publish(output,engine.seal(engine.prepare(profile,"serial-file-review"),plain));}finally{PqcExtension.wipe(plain);}
                                }else engine.sealFiles(List.of(input),List.of(output),1);
                                long elapsed=System.nanoTime()-start,allocated=meter.getThreadAllocatedBytes(thread)-before;
                                if(sample>=0)csv.printf(Locale.ROOT,"%d,%d,%d,%d,%s,%d,%d%n",fork,profile.category(),size,sample,variant,elapsed,allocated);
                                byte[] encoded=Files.readAllBytes(output),opened=engine.open(engine.prepareHistorical(profile.policyVersion()),PqcExtension.Packet.decode(encoded));
                                if(!Arrays.equals(opened,message))throw new AssertionError("Roundtrip");checks++;
                                if(!Files.getPosixFilePermissions(output).equals(PosixFilePermissions.fromString("rw-------")))throw new AssertionError("Output privacy");checks++;
                                PqcExtension.wipe(opened,encoded);Files.delete(output);
                            }
                        }
                        PqcExtension.wipe(message);Files.delete(input);
                    }
                }
            }
            csv.flush();if(csv.checkError())throw new java.io.IOException("Probe output failure");
        }finally{try(var paths=Files.walk(root)){for(Path p:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}}
        System.out.println("PASS serial ownership fork="+fork+" checks="+checks);
    }
}
