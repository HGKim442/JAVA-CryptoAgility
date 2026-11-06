import java.io.*;
import java.nio.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/** Normal equivalence fixtures and component costs; all keys/payloads are synthetic. */
public final class OptimizationCheck {
    private static int checks;
    private static volatile Object sink;
    private static final byte[] KEY=new byte[32];
    private static void check(boolean yes){if(!yes)throw new AssertionError("Optimization regression");checks++;}
    @FunctionalInterface interface Action {Object run()throws Exception;}
    private static void refused(Action action)throws Exception {try{action.run();}catch(IOException|GeneralSecurityException expected){checks++;return;}throw new AssertionError("Expected refusal");}
    private static Cipher cipher(byte[] nonce)throws Exception {Cipher c=Cipher.getInstance("AES/GCM/NoPadding","SunJCE");c.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(KEY,"AES"),new GCMParameterSpec(128,nonce));c.updateAAD("JCA-PQC-KEYSTORE-v4".getBytes(java.nio.charset.StandardCharsets.US_ASCII));return c;}
    private static byte[] legacySeal(Cipher cipher,byte[] nonce,byte[] plaintext)throws Exception {byte[] encrypted=cipher.doFinal(plaintext);return ByteBuffer.allocate(12+encrypted.length).put(nonce).put(encrypted).array();}
    // Exact v13 body parsing operations, including the prefix copy and regex.
    private static AnchorCodec.Decoded legacyRead(byte[] bytes,int length,Map<String,Long> high)throws Exception {
        byte[] content=Arrays.copyOf(bytes,length);bytes=content;
        try(DataInputStream in=new DataInputStream(new ByteArrayInputStream(bytes))){if(in.readInt()!=0x54534134)throw new IOException();long generation=in.readLong();if(generation<=0)throw new IOException();int len=in.readInt();if(len<28 || len>1024*1024+28)throw new IOException();byte[] sealed=in.readNBytes(len);if(sealed.length!=len)throw new EOFException();int n=in.readInt();if(n<0 || n>4096)throw new IOException();for(int i=0;i<n;i++){String fp=in.readUTF();long h=in.readLong();if(!fp.matches("[0-9a-f]{64}") || h<0 || high.put(fp,h)!=null)throw new IOException();}if(in.read()!=-1)throw new IOException();return new AnchorCodec.Decoded(generation,sealed);}
    }
    private static long allocated(){var bean=(com.sun.management.ThreadMXBean)java.lang.management.ManagementFactory.getThreadMXBean();if(!bean.isThreadAllocatedMemorySupported())return -1;bean.setThreadAllocatedMemoryEnabled(true);return bean.getThreadAllocatedBytes(Thread.currentThread().getId());}
    private static void measure(PrintWriter out,int fork,String operation,String variant,int bytes,int keys,int sample,Action action)throws Exception {long before=allocated(),start=System.nanoTime();sink=action.run();long ns=System.nanoTime()-start,after=allocated();out.printf(Locale.ROOT,"%d,%s,%s,%d,%d,%d,%d,%d%n",fork,operation,variant,bytes,keys,sample,ns,before<0?-1:after-before);}
    public static void main(String[] args)throws Exception {
        Path output=Path.of(args[0]);Files.createDirectories(output);int fork=Integer.parseInt(args[1]);
        byte[] valid=new byte[32];check(PqcExtension.checkedSharedSecret(valid)==valid);
        for(int size:new int[]{0,1,31,33,64}){byte[] bad=new byte[size];Arrays.fill(bad,(byte)91);refused(()->PqcExtension.checkedSharedSecret(bad));for(byte v:bad)if(v!=0)throw new AssertionError("Secret cleanup");checks++;}
        refused(()->PqcExtension.checkedSharedSecret(null));
        for(int value:new int[]{0,1,1088,1568,16*1024*1024+16,Integer.MAX_VALUE,-1}){byte[] word=new byte[4];PqcExtension.putFrameInt(word,value);check(Arrays.equals(word,ByteBuffer.allocate(4).putInt(value).array()));}
        try(PrintWriter csv=new PrintWriter(Files.newBufferedWriter(output.resolve("cost.csv")))){
            csv.println("fork,operation,variant,bytes,keys,sample,ns,allocated_bytes");
            for(int size:new int[]{0,8192,1024*1024}){
                byte[] plaintext=new byte[size],nonce=new byte[12];nonce[0]=1;
                byte[] a=legacySeal(cipher(nonce),nonce,plaintext),b=CheckpointCodec.seal(cipher(nonce),nonce,plaintext);check(Arrays.equals(a,b));check(b.length==size+28);
                for(int warm=0;warm<7;warm++){sink=legacySeal(cipher(nonce),nonce,plaintext);sink=CheckpointCodec.seal(cipher(nonce),nonce,plaintext);}
                for(int sample=0;sample<7;sample++)for(String variant:(fork%2==1?List.of("v13_reference","v15"):List.of("v15","v13_reference"))){Cipher c=cipher(nonce);measure(csv,fork,"checkpoint_seal",variant,size,0,sample,()->variant.equals("v15")?CheckpointCodec.seal(c,nonce,plaintext):legacySeal(c,nonce,plaintext));}
            }
            for(int i=0;i<3;i++){
                int size=new int[]{28,8192,1024*1024+28}[i],count=new int[]{0,32,4096}[i];byte[] sealed=new byte[size];Map<String,Long> counters=new TreeMap<>();for(int k=0;k<count;k++)counters.put(String.format(Locale.ROOT,"%064x",k),(long)k);
                byte[] record=AnchorCodec.record(7,sealed,counters);int length=record.length-32;Map<String,Long> old=new TreeMap<>(),fresh=new TreeMap<>();var a=legacyRead(record,length,old);var b=AnchorCodec.readBody(record,length,fresh);check(a.generation()==b.generation());check(Arrays.equals(a.sealed(),b.sealed()));check(old.equals(fresh));record[16]^=1;check(b.sealed()[0]==0);record[16]^=1;
                for(int warm=0;warm<7;warm++){sink=legacyRead(record,length,new TreeMap<>());sink=AnchorCodec.readBody(record,length,new TreeMap<>());}
                for(int sample=0;sample<7;sample++)for(String variant:(fork%2==1?List.of("v13_reference","v15"):List.of("v15","v13_reference")))measure(csv,fork,"anchor_parse",variant,size,count,sample,()->variant.equals("v15")?AnchorCodec.readBody(record,length,new TreeMap<>()):legacyRead(record,length,new TreeMap<>()));
            }
        }
        byte[] empty=AnchorCodec.record(1,new byte[28],Map.of());
        refused(()->AnchorCodec.readBody(empty,empty.length-33,new TreeMap<>()));
        byte[] trailing=Arrays.copyOf(empty,empty.length+1);refused(()->AnchorCodec.readBody(trailing,empty.length-31,new TreeMap<>()));
        refused(()->AnchorCodec.readBody(empty,empty.length-32,new TreeMap<>(Map.of("x",1L))));
        refused(()->CheckpointCodec.seal(cipher(new byte[12]),new byte[11],new byte[0]));
        Files.writeString(output.resolve("checks.json"),"{\"passed\":true,\"checks\":"+checks+",\"rows\":84,\"scope\":\"synthetic normal equivalence and component allocation; not end-to-end RSS or cryptographic certification\"}\n");
        System.out.println("PASS optimization equivalence checks="+checks+" rows=84 fork="+fork);
    }
}
