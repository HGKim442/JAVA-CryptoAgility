import java.io.*;
import java.nio.*;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.util.*;

/** Patched-path defensive tests; synthetic secrets only, no heap-dump or exploit tooling. */
public final class SecurityAuditTest {
    static int checks;
    static void check(boolean ok,String name){if(!ok)throw new AssertionError(name);checks++;}
    static byte[] backing(SecretBuffer buffer)throws Exception {var field=SecretBuffer.class.getDeclaredField("buffer");field.setAccessible(true);return (byte[])field.get(buffer);}
    static boolean zero(byte[] bytes){for(byte value:bytes)if(value!=0)return false;return true;}
    @FunctionalInterface interface Action{void run()throws Exception;}
    static long allocation(Action action)throws Exception {var bean=(com.sun.management.ThreadMXBean)java.lang.management.ManagementFactory.getThreadMXBean();check(bean.isThreadAllocatedMemorySupported(),"allocation supported");bean.setThreadAllocatedMemoryEnabled(true);long id=Thread.currentThread().getId(),before=bean.getThreadAllocatedBytes(id);action.run();return bean.getThreadAllocatedBytes(id)-before;}
    static void refused(Action action)throws Exception {try{action.run();}catch(IOException|SecurityException|IllegalStateException expected){return;}throw new AssertionError("Expected defensive refusal");}
    static int[] offsets(byte[] encoded){ByteBuffer b=ByteBuffer.wrap(encoded);b.getInt();int[] offsets=new int[6];for(int i=0;i<6;i++){int len=b.getInt();offsets[i]=b.position();b.position(b.position()+len);}return offsets;}
    public static void main(String[] args)throws Exception {
        Path out=Path.of(args[0]);Files.createDirectories(out);byte[] synthetic=new byte[512];Arrays.fill(synthetic,(byte)91);SecretBuffer buffer=new SecretBuffer();byte[] original=backing(buffer);buffer.write(synthetic,0,128);byte[] first=buffer.copy();check(Arrays.equals(first,Arrays.copyOf(synthetic,128)),"copy before close");buffer.write(synthetic,0,512);check(zero(original),"growth zeroes prior storage");byte[] latest=backing(buffer),returned=buffer.copy();buffer.close();check(zero(latest),"close zeroes final storage");check(returned.length==640 && returned[0]==91,"returned copy remains owned by caller");refused(buffer::copy);checks++;refused(()->buffer.write(1));checks++;buffer.close();check(zero(latest),"close idempotent");
        SecretBuffer failed=new SecretBuffer();byte[] failedBacking=backing(failed);try(SecretBuffer owned=failed;DataOutputStream writer=new DataOutputStream(owned)){writer.write(synthetic,0,128);throw new IOException("synthetic writer failure");}catch(IOException expected){check(zero(failedBacking),"exception closes and wipes");}
        SecretBuffer bound=new SecretBuffer();try{refused(()->{try{bound.write(new byte[1024*1024+1]);}catch(IllegalArgumentException expected){throw new IOException(expected);}});checks++;}finally{bound.close();}
        Path dir=Files.createTempDirectory("audit-v6-",PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));long tokenBytes,parserBytes;
        try(PqcExtension.Engine e=new PqcExtension.Engine(PqcExtension.P3,PqcExtension.CONTEXT,dir)){
            PqcExtension.Prepared used=e.prepare(PqcExtension.P3,PqcExtension.CONTEXT);e.seal(used,new byte[1]);byte[] large=new byte[16*1024*1024];
            for(int i=0;i<10;i++)refused(()->e.seal(used,large));tokenBytes=allocation(()->refused(()->e.seal(used,large)));check(tokenBytes<1024*1024,"reused request rejected before large clone");
            PqcExtension.Prepared token=e.prepare(PqcExtension.P3,PqcExtension.CONTEXT);PqcExtension.Packet packet=e.seal(token,large);byte[] encoded=packet.encode(),invalid=encoded.clone();int[] offsets=offsets(invalid);ByteBuffer.wrap(invalid).putInt(offsets[5]-4,Integer.MAX_VALUE);
            for(int i=0;i<10;i++)refused(()->PqcExtension.Packet.decode(invalid));parserBytes=allocation(()->refused(()->PqcExtension.Packet.decode(invalid)));check(parserBytes<1024*1024,"layout rejected before ciphertext copy");
            PqcExtension.Packet decoded=PqcExtension.Packet.decode(encoded);check(e.open(token,decoded).length==large.length,"max size roundtrip");encoded[8]^=1;check(e.open(token,decoded).length==large.length,"decoded fields own their bytes");
        }finally{try(var files=Files.walk(dir)){for(Path p:files.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}}
        PqcExtension.wipe(synthetic,first,returned);Files.writeString(out.resolve("security-audit-tests.json"),"{\"passed\":true,\"checks\":"+checks+",\"reused_request_allocated_bytes\":"+tokenBytes+",\"malformed_tail_allocated_bytes\":"+parserBytes+",\"scope\":\"owned Java array cleanup and bounded patched-path rejection; no complete JVM zeroization guarantee\"}\n");System.out.println("PASS security audit checks="+checks+" reused_alloc="+tokenBytes+" parser_alloc="+parserBytes);
    }
}
