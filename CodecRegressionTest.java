import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import java.util.concurrent.*;

/** Additional normal boundary/concurrency checks and synthetic measurement-output failures. */
public final class CodecRegressionTest {
    private static int checks,boundaries,concurrent;
    private static void check(boolean value){if(!value)throw new AssertionError();checks++;}
    private static boolean layout(byte[] wire,int category,int size)throws IOException {
        int[] lengths={32,category==3?1088:1568,32,12,size+16,category==3?3309:4627};
        int total=28;for(int length:lengths)total+=length;if(wire.length!=total)return false;
        try(DataInputStream in=new DataInputStream(new ByteArrayInputStream(wire))){
            if(in.readInt()!=0x50514334)return false;for(int length:lengths){if(in.readInt()!=length)return false;in.skipNBytes(length);}return in.read()==-1;
        }
    }
    private static void outputFailure(PrintWriter writer)throws Exception {
        try{PacketCodecBenchmark.requireOutput(writer);throw new AssertionError("Write failure hidden");}catch(IOException expected){checks++;}
    }
    public static void main(String[] args)throws Exception {
        PrintWriter good=new PrintWriter(new StringWriter());good.print("normal");PacketCodecBenchmark.requireOutput(good);check(!good.checkError());good.close();
        PrintWriter writeFailure=new PrintWriter(new Writer(){public void write(char[] b,int o,int n)throws IOException{throw new IOException("synthetic write failure");}public void flush(){}public void close(){}});writeFailure.print("row");outputFailure(writeFailure);writeFailure.close();
        PrintWriter closeFailure=new PrintWriter(new Writer(){public void write(char[] b,int o,int n){}public void flush(){}public void close()throws IOException{throw new IOException("synthetic close failure");}});closeFailure.close();outputFailure(closeFailure);
        Path root=Files.createTempDirectory("codec-regression-",PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        try {
            for(var profile:List.of(PqcExtension.P3,PqcExtension.P5)){
                int category=profile.category();Path dir=Files.createDirectory(root.resolve("p"+category),PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
                try(PqcExtension.Engine engine=new PqcExtension.Engine(profile,PqcExtension.CONTEXT,dir)){
                    for(int size:new int[]{0,1,15,16,255,256,4095,4096,65535,65536,1048576,16777216}){
                        byte[] message=new byte[size];new Random(88).nextBytes(message);var request=engine.prepare(profile,PqcExtension.CONTEXT);var packet=engine.seal(request,message);
                        byte[] wire=packet.encode(),again=packet.encode();check(layout(wire,category,size));check(wire!=again && Arrays.equals(wire,again));
                        var decoded=PqcExtension.Packet.decode(wire);byte[] plaintext=engine.open(request,decoded);try{check(Arrays.equals(message,plaintext));}finally{PqcExtension.wipe(plaintext);}
                        wire[wire.length-1]^=1;plaintext=engine.open(request,decoded);try{check(Arrays.equals(message,plaintext) && Arrays.equals(again,packet.encode()));}finally{PqcExtension.wipe(plaintext);}
                        boundaries++;PqcExtension.wipe(message,wire,again);
                    }
                    byte[] message=new byte[4096];var request=engine.prepare(profile,PqcExtension.CONTEXT);var packet=engine.seal(request,message);byte[] reference=packet.encode();ExecutorService pool=Executors.newFixedThreadPool(8);
                    List<byte[]> copies=new ArrayList<>();
                    try{List<Future<List<byte[]>>> jobs=new ArrayList<>();for(int worker=0;worker<8;worker++)jobs.add(pool.submit(()->{List<byte[]> result=new ArrayList<>();for(int i=0;i<64;i++)result.add(packet.encode());return result;}));for(var job:jobs)copies.addAll(job.get(30,TimeUnit.SECONDS));}
                    finally{pool.shutdownNow();if(!pool.awaitTermination(30,TimeUnit.SECONDS))throw new IOException("Worker timeout");}
                    check(copies.size()==512);check(copies.stream().allMatch(copy->Arrays.equals(copy,reference)));
                    Set<byte[]> identities=Collections.newSetFromMap(new IdentityHashMap<>());identities.addAll(copies);check(identities.size()==512);
                    copies.get(0)[0]^=1;check(Arrays.equals(reference,packet.encode()));byte[] plaintext=engine.open(request,PqcExtension.Packet.decode(reference));try{check(Arrays.equals(message,plaintext));}finally{PqcExtension.wipe(plaintext);}
                    concurrent+=copies.size();for(byte[] copy:copies)PqcExtension.wipe(copy);PqcExtension.wipe(reference,message);
                }
            }
        }finally{try(var paths=Files.walk(root)){for(Path p:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}}
        Path out=Path.of(args[0]);Files.createDirectories(out);Files.writeString(out.resolve("codec-regression.json"),"{\"passed\":true,\"checks\":"+checks+",\"boundary_cases\":"+boundaries+",\"concurrent_encodes\":"+concurrent+",\"writer_failure_checks\":2}\n");
        System.out.println("PASS codec regression checks="+checks+" boundaries="+boundaries+" concurrent="+concurrent);
    }
}
