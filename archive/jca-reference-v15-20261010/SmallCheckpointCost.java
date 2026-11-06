import java.nio.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/** More warmup/repetitions for the unresolved 8KiB component question; synthetic data only. */
public final class SmallCheckpointCost {
    static volatile byte[] sink;
    static Cipher cipher(int sequence)throws Exception {byte[] nonce=ByteBuffer.allocate(12).putInt(0).putLong(sequence).array();Cipher c=Cipher.getInstance("AES/GCM/NoPadding","SunJCE");c.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(new byte[32],"AES"),new GCMParameterSpec(128,nonce));c.updateAAD("JCA-PQC-KEYSTORE-v4".getBytes(java.nio.charset.StandardCharsets.US_ASCII));return c;}
    static byte[] reference(Cipher c,byte[] nonce,byte[] plain)throws Exception {byte[] encrypted=c.doFinal(plain);return ByteBuffer.allocate(encrypted.length+12).put(nonce).put(encrypted).array();}
    public static void main(String[] args)throws Exception {
        int fork=Integer.parseInt(args[1]);Path out=Path.of(args[0]);byte[] plaintext=new byte[8192];StringBuilder rows=new StringBuilder("fork,variant,sample,ns,allocated_bytes\n");var bean=(com.sun.management.ThreadMXBean)java.lang.management.ManagementFactory.getThreadMXBean();boolean supported=bean.isThreadAllocatedMemorySupported();if(supported)bean.setThreadAllocatedMemoryEnabled(true);long id=Thread.currentThread().getId();
        for(int sample=-200;sample<101;sample++){
            byte[] nonce=ByteBuffer.allocate(12).putInt(0).putLong(sample+200).array();
            for(String variant:((fork+sample)%2==0?List.of("v13_reference","direct_output"):List.of("direct_output","v13_reference"))){Cipher c=cipher(sample+200);long allocated=supported?bean.getThreadAllocatedBytes(id):0,start=System.nanoTime();sink=variant.equals("direct_output")?CheckpointCodec.seal(c,nonce,plaintext):reference(c,nonce,plaintext);long ns=System.nanoTime()-start,bytes=supported?bean.getThreadAllocatedBytes(id)-allocated:-1;
                if(sample>=0)rows.append(fork).append(',').append(variant).append(',').append(sample).append(',').append(ns).append(',').append(bytes).append('\n');
            }
            byte[] a=reference(cipher(sample+200),nonce,plaintext),b=CheckpointCodec.seal(cipher(sample+200),nonce,plaintext);if(!Arrays.equals(a,b))throw new AssertionError("Cipher output equivalence");
        }
        Files.writeString(out,rows);System.out.println("PASS small checkpoint cost rows=202 fork="+fork);
    }
}
