import java.io.*;
import java.lang.reflect.Field;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import java.lang.management.ManagementFactory;

/** Normal packet serialization comparison; legacy reference is the v7 encoder body. */
public final class PacketCodecBenchmark {
    static void requireOutput(PrintWriter writer)throws IOException {
        if(writer.checkError())throw new IOException("Codec measurement output failed");
    }
    private static volatile byte[] sink;
    private static int checks;
    private static void check(boolean value){if(!value)throw new AssertionError();checks++;}
    private static byte[][] fields(PqcExtension.Packet p)throws Exception {
        String[] names={"bound","encapsulation","salt","nonce","ciphertext","signature"};byte[][] result=new byte[6][];
        for(int i=0;i<names.length;i++){Field f=PqcExtension.Packet.class.getDeclaredField(names[i]);f.setAccessible(true);result[i]=(byte[])f.get(p);}return result;
    }
    private static byte[] legacy(byte[][] fields)throws IOException {
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();try(DataOutputStream out=new DataOutputStream(bytes)){
            out.writeInt(0x50514334);for(byte[] field:List.of(fields[0],fields[1],fields[2],fields[3],fields[4],fields[5])){out.writeInt(field.length);out.write(field);}
        }return bytes.toByteArray();
    }
    private static final com.sun.management.ThreadMXBean MEMORY=(com.sun.management.ThreadMXBean)ManagementFactory.getThreadMXBean();
    private static void measure(PrintWriter out,int profile,int size,int sample,String method,PqcExtension.Packet packet,byte[][] fields)throws Exception {
        long thread=Thread.currentThread().getId(),before=MEMORY.getThreadAllocatedBytes(thread),start=System.nanoTime();
        sink=method.equals("legacy")?legacy(fields):packet.encode();long elapsed=System.nanoTime()-start,allocated=MEMORY.getThreadAllocatedBytes(thread)-before;
        out.printf(Locale.ROOT,"%d,%d,%d,%s,%d,%d,%d%n",profile,size,sample,method,elapsed,allocated,sink.length);
    }
    public static void main(String[] args)throws Exception {
        Path out=Path.of(args[0]);Files.createDirectories(out);int order=Integer.parseInt(args[1]);
        if(!MEMORY.isThreadAllocatedMemorySupported())throw new IllegalStateException("Thread allocation measurement unavailable");MEMORY.setThreadAllocatedMemoryEnabled(true);
        Path root=Files.createTempDirectory("codec-v8-",PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        PrintWriter csv=new PrintWriter(Files.newBufferedWriter(out.resolve("codec-cost.csv")));
        try(csv) {
            csv.println("profile,message_bytes,sample,method,ns,allocated_bytes,encoded_bytes");
            for(int cat:new int[]{3,5}){
                Path dir=Files.createDirectory(root.resolve("p"+cat),PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
                PqcExtension.Profile profile=cat==3?PqcExtension.P3:PqcExtension.P5;
                try(PqcExtension.Engine engine=new PqcExtension.Engine(profile,"codec-research",dir)){
                    for(int size:new int[]{0,4096,1024*1024,16*1024*1024}){
                        byte[] message=new byte[size];new Random(42).nextBytes(message);
                        PqcExtension.Packet packet=engine.seal(engine.prepare(profile,"codec-research"),message);byte[][] f=fields(packet);
                        byte[] reference=legacy(f),encoded=packet.encode();check(Arrays.equals(reference,encoded));
                        check(Arrays.equals(message,engine.open(engine.prepare(profile,"codec-research"),PqcExtension.Packet.decode(encoded))));
                        encoded[0]^=1;check(Arrays.equals(reference,packet.encode()));
                        for(int warm=0;warm<(size>=1024*1024?4:64);warm++){sink=legacy(f);sink=packet.encode();}
                        int samples=size>=16*1024*1024?6:size>=1024*1024?20:100;
                        for(int sample=0;sample<samples;sample++){
                            String first=((sample+order)&1)==0?"legacy":"exact",second=first.equals("legacy")?"exact":"legacy";
                            measure(csv,cat,size,sample,first,packet,f);measure(csv,cat,size,sample,second,packet,f);
                        }
                        PqcExtension.wipe(message,reference,encoded);
                    }
                }
            }
            requireOutput(csv);
        }finally{sink=null;try(var tree=Files.walk(root)){for(Path p:tree.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}}
        requireOutput(csv);
        Files.writeString(out.resolve("codec-checks.json"),"{\"passed\":true,\"checks\":"+checks+",\"reference\":\"v7 encoder body; same immutable authenticated packet; field reflection outside timing\"}\n");
        System.out.println("PASS codec byte equivalence, roundtrip and output ownership checks="+checks);
    }
}
