import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Synthetic already-sealed bytes; compares v9 serialization body only, excluding MAC/fsync timing. */
public final class AnchorCodecBenchmark {
    private static volatile byte[] sink;
    private static int checks;
    private static void check(boolean ok){if(!ok)throw new AssertionError();checks++;}
    private static byte[] legacy(long generation,byte[] sealed,Map<String,Long> high)throws IOException {
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();try(DataOutputStream out=new DataOutputStream(bytes)){out.writeInt(0x54534134);out.writeLong(generation);out.writeInt(sealed.length);out.write(sealed);out.writeInt(high.size());for(var e:high.entrySet()){out.writeUTF(e.getKey());out.writeLong(e.getValue());}}
        byte[] content=bytes.toByteArray();return ByteBuffer.allocate(content.length+32).put(content).put(new byte[32]).array();
    }
    private static byte[] mac(byte[] record,boolean range)throws Exception {
        byte[] testKey=new byte[32],derived=null;Arrays.fill(testKey,(byte)0x35);Mac m=Mac.getInstance("HmacSHA256","SunJCE");
        try{m.init(new SecretKeySpec(testKey,"HmacSHA256"));derived=m.doFinal("JCA-PQC-ANCHOR-MAC-v4".getBytes(StandardCharsets.US_ASCII));m.init(new SecretKeySpec(derived,"HmacSHA256"));if(range){m.update(record,0,record.length-32);return m.doFinal();}return m.doFinal(Arrays.copyOf(record,record.length-32));}
        finally{Arrays.fill(testKey,(byte)0);if(derived!=null)Arrays.fill(derived,(byte)0);}
    }
    public static void main(String[] args)throws Exception {
        Path out=Path.of(args[0]);Files.createDirectories(out);int order=Integer.parseInt(args[1]);var bean=(com.sun.management.ThreadMXBean)java.lang.management.ManagementFactory.getThreadMXBean();if(!bean.isThreadAllocatedMemorySupported())throw new IllegalStateException("Allocation unsupported");bean.setThreadAllocatedMemoryEnabled(true);long thread=Thread.currentThread().getId();
        PrintWriter csv=new PrintWriter(Files.newBufferedWriter(out.resolve("anchor-cost.csv")));
        try(csv){csv.println("sealed_bytes,keys,sample,method,ns,allocated_bytes,record_bytes");
            for(int[] spec:new int[][]{{28,0},{8192,1},{65536,32},{1048604,4096}}){
                byte[] sealed=new byte[spec[0]];new Random(98).nextBytes(sealed);Map<String,Long> high=new TreeMap<>();for(int i=0;i<spec[1];i++)high.put(String.format(Locale.ROOT,"%064x",i),(long)i*128);
                long generation=Long.MAX_VALUE;byte[] old=legacy(generation,sealed,high),exact=AnchorCodec.record(generation,sealed,high);check(Arrays.equals(old,exact));check(Arrays.equals(mac(old,false),mac(exact,true)));
                try(DataInputStream in=new DataInputStream(new ByteArrayInputStream(exact))){check(in.readInt()==0x54534134 && in.readLong()==generation && in.readInt()==sealed.length);in.skipNBytes(sealed.length);check(in.readInt()==high.size());boolean entries=true;for(var e:high.entrySet())entries&=in.readUTF().equals(e.getKey()) && in.readLong()==e.getValue();check(entries && in.available()==32);}
                for(int warm=0;warm<20;warm++){sink=legacy(generation,sealed,high);sink=AnchorCodec.record(generation,sealed,high);}
                int samples=spec[0]>1000000?12:spec[0]>60000?40:100;
                for(int sample=0;sample<samples;sample++)for(int step=0;step<2;step++){
                    boolean baseline=((sample+order+step)&1)==0;long before=bean.getThreadAllocatedBytes(thread),start=System.nanoTime();sink=baseline?legacy(generation,sealed,high):AnchorCodec.record(generation,sealed,high);long elapsed=System.nanoTime()-start,allocated=bean.getThreadAllocatedBytes(thread)-before;
                    csv.printf(Locale.ROOT,"%d,%d,%d,%s,%d,%d,%d%n",spec[0],spec[1],sample,baseline?"legacy":"exact",elapsed,allocated,sink.length);
                }
            }
            PacketCodecBenchmark.requireOutput(csv);
        }finally{sink=null;}
        PacketCodecBenchmark.requireOutput(csv);
        Files.writeString(out.resolve("anchor-checks.json"),"{\"passed\":true,\"checks\":"+checks+",\"scope\":\"synthetic sealed checkpoint serialization and HMAC prefix equivalence; excludes filesystem durability timing\"}\n");System.out.println("PASS anchor encoding and HMAC prefix equivalence checks="+checks);
    }
}
