import java.io.*;
import java.nio.*;
import java.nio.channels.GatheringByteChannel;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import java.lang.management.ManagementFactory;

/** Same authenticated packet, same durable publisher; only the serialization differs. */
public final class PacketFileOutputTest {
    static int checks;
    static void check(boolean value){if(!value)throw new AssertionError("Packet file output");checks++;}
    static final class PartialChannel implements GatheringByteChannel {
        final ByteArrayOutputStream bytes=new ByteArrayOutputStream();
        final int mode;boolean readonly=true;int calls;
        PartialChannel(int mode){this.mode=mode;}
        public long write(ByteBuffer[] parts,int offset,int length)throws IOException {
            calls++;if(mode==1 && calls==2)throw new IOException("Synthetic output failure");if(mode==2)return 0;
            int budget=7,written=0;
            for(int i=offset;i<offset+length && budget>0;i++){
                ByteBuffer p=parts[i];readonly&=p.isReadOnly() && !p.hasArray();
                if(p.hasRemaining())try{p.put(p.position(),(byte)0);readonly=false;}catch(ReadOnlyBufferException expected){}
                while(p.hasRemaining() && budget>0){bytes.write(p.get());budget--;written++;}
            }
            return written;
        }
        public long write(ByteBuffer[] parts)throws IOException{return write(parts,0,parts.length);}
        public int write(ByteBuffer part)throws IOException{return (int)write(new ByteBuffer[]{part});}
        public boolean isOpen(){return true;}
        public void close(){}
    }
    static void failureChecks(PqcExtension.Packet packet)throws Exception {
        byte[] expected=packet.encode();PartialChannel partial=new PartialChannel(0);packet.writeTo(partial);
        check(partial.calls>1);check(partial.readonly);check(Arrays.equals(expected,partial.bytes.toByteArray()));
        for(int mode:new int[]{1,2}){
            PartialChannel failed=new PartialChannel(mode);
            try{packet.writeTo(failed);throw new AssertionError("Failure hidden");}catch(IOException expectedFailure){check(true);}
            check(Arrays.equals(expected,packet.encode()));
        }
    }
    public static void main(String[] args)throws Exception {
        Path out=Path.of(args[0]);Files.createDirectories(out);int fork=Integer.parseInt(args[1]);
        var memory=(com.sun.management.ThreadMXBean)ManagementFactory.getThreadMXBean();
        if(!memory.isThreadAllocatedMemorySupported())throw new IllegalStateException("Allocation measurement unavailable");
        memory.setThreadAllocatedMemoryEnabled(true);long thread=Thread.currentThread().getId();
        Path root=Files.createTempDirectory("packet-file-",PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        try(PrintWriter csv=new PrintWriter(Files.newBufferedWriter(out.resolve("file-output-cost.csv")))){
            csv.println("profile,message_bytes,sample,variant,ns,allocated_bytes");
            for(var profile:fork%2==0?List.of(PqcExtension.P3,PqcExtension.P5):List.of(PqcExtension.P5,PqcExtension.P3)){
                Path state=Files.createDirectory(root.resolve("p"+profile.category()),PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
                try(var engine=new PqcExtension.Engine(profile,"packet-file-normal",state)){
                    for(int size:new int[]{0,4096,1048576,16777216}){
                        byte[] message=new byte[size];new Random(91).nextBytes(message);
                        var request=engine.prepare(profile,"packet-file-normal");var packet=engine.seal(request,message);
                        Path a=root.resolve("encoded"),b=root.resolve("gathered");
                        CryptoCli.publish(a,packet.encode());CryptoCli.publish(b,packet);
                        byte[] encoded=Files.readAllBytes(a),gathered=Files.readAllBytes(b);
                        check(Arrays.equals(encoded,gathered));check(Files.getPosixFilePermissions(b).equals(PosixFilePermissions.fromString("rw-------")));
                        byte[] opened=engine.open(request,PqcExtension.Packet.decode(gathered));check(Arrays.equals(message,opened));PqcExtension.wipe(opened);
                        try{CryptoCli.publish(b,packet);throw new AssertionError("Existing output replaced");}catch(FileAlreadyExistsException expected){check(true);}
                        check(Arrays.equals(gathered,Files.readAllBytes(b)));
                        try(var files=Files.list(root)){check(files.noneMatch(p->p.getFileName().toString().startsWith(".pqc-output-")));}
                        Files.delete(a);Files.delete(b);
                        if(size==4096)failureChecks(packet);
                        int warm=size>=1048576?2:8,samples=size>=1048576?7:31;
                        for(int i=-warm;i<samples;i++){
                            for(String variant:((i+fork)&1)==0?List.of("encode_then_publish","gather_publish"):List.of("gather_publish","encode_then_publish")){
                                long before=memory.getThreadAllocatedBytes(thread),start=System.nanoTime();
                                if(variant.equals("encode_then_publish"))CryptoCli.publish(a,packet.encode());else CryptoCli.publish(a,packet);
                                long ns=System.nanoTime()-start,allocated=memory.getThreadAllocatedBytes(thread)-before;
                                if(i>=0)csv.printf(Locale.ROOT,"%d,%d,%d,%s,%d,%d%n",profile.category(),size,i,variant,ns,allocated);
                                Files.delete(a);
                            }
                        }
                        PqcExtension.wipe(message,encoded,gathered);
                    }
                }
            }
            PacketCodecBenchmark.requireOutput(csv);
        }finally{try(var paths=Files.walk(root)){for(Path p:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}}
        Files.writeString(out.resolve("file-output-checks.json"),"{\"passed\":true,\"checks\":"+checks+",\"scope\":\"same packet durable file output equivalence, real decrypt, owner-only permissions, no overwrite, temp cleanup, read-only views, partial/failed/zero-progress writes\"}\n");
        System.out.println("PASS packet file output checks="+checks);
    }
}
