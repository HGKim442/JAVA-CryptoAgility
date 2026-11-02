import java.io.*;
import java.nio.*;
import java.nio.channels.*;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/** Reference trusted anchor. Operator must protect anchor and master key from rollback. */
public final class TrustedStateStore implements AutoCloseable {
    private static final SecureRandom RNG=new SecureRandom();
    private static final byte[] KEYSTORE_AAD="JCA-PQC-KEYSTORE-v4".getBytes(java.nio.charset.StandardCharsets.US_ASCII),MAC_DOMAIN="JCA-PQC-ANCHOR-MAC-v4".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    private static final byte[] CHECKPOINT_V5="JCA-PQC-CKPT-v5!".getBytes(java.nio.charset.StandardCharsets.US_ASCII),DERIVE_V5="JCA-PQC-CKPT-KEY-v5".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    // Enrollment-wide upper bound; v5 uses one GCM encryption per salt-derived key.
    static final long MAX_CHECKPOINTS=1L<<32;
    private static final Set<PosixFilePermission> PRIVATE=PosixFilePermissions.fromString("rw-------");
    private final Path data,anchor;
    private final FileChannel leaseChannel;
    private final FileLock lease;
    private final byte[] key;
    private byte[] macKey,pendingPlain;
    private byte[] sealed=new byte[0];
    private final Map<String,Long> high=new TreeMap<>();
    private final Map<String,long[]> cursors=new HashMap<>();
    private long generation,writes;
    private boolean closed,failed,needsRepair;
    public TrustedStateStore(Path dataDirectory,Path trustedDirectory,byte[] masterKey,boolean initialize,boolean repairMirror)throws Exception {
        this(dataDirectory,trustedDirectory,masterKey,initialize,repairMirror,false);
    }
    static TrustedStateStore openForEngine(Path data,Path anchor,byte[] master,boolean repair)throws Exception {return new TrustedStateStore(data,anchor,master,false,repair,true);}
    private TrustedStateStore(Path dataDirectory,Path trustedDirectory,byte[] masterKey,boolean initialize,boolean repairMirror,boolean transferPlain)throws Exception {
        if(masterKey==null || masterKey.length!=32)throw new IllegalArgumentException("External 256-bit master key required");
        data=privateDirectory(dataDirectory);anchor=privateDirectory(trustedDirectory);
        if(data.startsWith(anchor) || anchor.startsWith(data))throw new IOException("Independent nonnested directories required");
        key=masterKey.clone();FileChannel channel=null;FileLock acquired=null;
        try {
            Mac derivation=Mac.getInstance("HmacSHA256","SunJCE");derivation.init(new SecretKeySpec(key,"HmacSHA256"));macKey=derivation.doFinal(MAC_DOMAIN);
            Path lock=anchor.resolve("engine.lock");checkFile(lock);
            channel=FileChannel.open(lock,Set.of(StandardOpenOption.CREATE,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS),PosixFilePermissions.asFileAttribute(PRIVATE));
            try{acquired=channel.tryLock();}catch(OverlappingFileLockException e){throw new IOException("Engine already leased",e);}
            if(acquired==null)throw new IOException("Engine already leased");
            Path trusted=anchor.resolve("anchor.bin");checkFile(trusted);
            if(initialize){
                // Existing marker prevents silently reinitializing an enrolled anchor.
                if(Files.exists(trusted,LinkOption.NOFOLLOW_LINKS) || channel.size()!=0 || Files.exists(data.resolve("engine.bin"),LinkOption.NOFOLLOW_LINKS))throw new IOException("Already enrolled or recovery required");
                channel.write(ByteBuffer.wrap(new byte[]{1}),0);channel.force(true);forceDirectory(anchor);
            } else {
                if(channel.size()==0 || !Files.exists(trusted,LinkOption.NOFOLLOW_LINKS))throw new IOException("Trusted anchor missing; never initialize implicitly");
                readAnchor(read(trusted));
                // Authenticate before repair: a wrong key must not modify any data.
                byte[] plain=decrypt(sealed);if(transferPlain)pendingPlain=plain;else Arrays.fill(plain,(byte)0);
                Path mirror=data.resolve("engine.bin");checkFile(mirror);
                boolean same=Files.exists(mirror,LinkOption.NOFOLLOW_LINKS) && MessageDigest.isEqual(read(mirror),sealed);
                if(!same){if(!repairMirror)throw new IOException("Mirror missing/changed/stale; explicit trusted recovery required");needsRepair=true;}
            }
            leaseChannel=channel;lease=acquired;
        } catch(Exception e){wipe(macKey);wipe(pendingPlain);pendingPlain=null;cleanupAfterFailure(e,key,acquired,channel);throw e;}
    }
    // Cleanup must not trigger initialization of the PQC engine or its provider.
    private static void wipe(byte[] secret){if(secret!=null)Arrays.fill(secret,(byte)0);}
    static void cleanupAfterFailure(Exception original,byte[] secret,AutoCloseable first,AutoCloseable second) {
        try {for(AutoCloseable resource:new AutoCloseable[]{first,second}) {
            if(resource!=null)try{resource.close();}catch(Exception cleanup){if(cleanup!=original)original.addSuppressed(cleanup);}
        }} finally {Arrays.fill(secret,(byte)0);}
    }
    static Path privateDirectory(Path directory)throws IOException {
        if(Files.isSymbolicLink(directory) || !Files.isDirectory(directory,LinkOption.NOFOLLOW_LINKS))throw new IOException("Private existing directory required");
        if(Files.getPosixFilePermissions(directory,LinkOption.NOFOLLOW_LINKS).stream().anyMatch(p->p.name().startsWith("GROUP_") || p.name().startsWith("OTHERS_")))throw new IOException("Directory must be owner-only");return directory.toRealPath();
    }
    private static void checkFile(Path path)throws IOException {
        if(Files.isSymbolicLink(path))throw new IOException("Symlink refused");
        if(Files.exists(path,LinkOption.NOFOLLOW_LINKS) && (!Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS) || Files.getPosixFilePermissions(path,LinkOption.NOFOLLOW_LINKS).stream().anyMatch(p->p.name().startsWith("GROUP_") || p.name().startsWith("OTHERS_"))))throw new IOException("Unsafe file");
    }
    private static byte[] read(Path path)throws IOException {
        try(FileChannel ch=FileChannel.open(path,Set.of(StandardOpenOption.READ,LinkOption.NOFOLLOW_LINKS))){long size=ch.size();if(size>2*1024*1024)throw new IOException("State bounds");ByteBuffer b=ByteBuffer.allocate((int)size);while(b.hasRemaining())if(ch.read(b)<0)throw new EOFException();if(ch.read(ByteBuffer.allocate(1))!=-1)throw new IOException("State changed during read");return b.array();}
    }
    private static void forceDirectory(Path dir)throws IOException {try(FileChannel ch=FileChannel.open(dir,StandardOpenOption.READ)){ch.force(true);}}
    private static void atomic(Path dir,Path target,byte[] bytes)throws IOException {
        checkFile(target);Path tmp=Files.createTempFile(dir,".state-",".tmp",PosixFilePermissions.asFileAttribute(PRIVATE));
        try{try(FileChannel ch=FileChannel.open(tmp,StandardOpenOption.WRITE)){ByteBuffer b=ByteBuffer.wrap(bytes);while(b.hasRemaining())ch.write(b);ch.force(true);}Files.move(tmp,target,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);forceDirectory(dir);}finally{Files.deleteIfExists(tmp);}
    }
    synchronized boolean usable(){return !closed && !failed;}
    private void available()throws IOException {if(closed || failed)throw new IOException("Store closed or failed; reopen required");}
    synchronized void repairMirror()throws IOException {available();if(needsRepair){try{atomic(data,data.resolve("engine.bin"),sealed);needsRepair=false;}catch(IOException e){failed=true;throw e;}}}
    synchronized byte[] load()throws Exception {available();if(pendingPlain!=null){byte[] owned=pendingPlain;pendingPlain=null;return owned;}return sealed.length==0?null:decrypt(sealed);}
    synchronized void save(byte[] plaintext)throws Exception {
        available();if(plaintext==null || plaintext.length>1024*1024 || generation>=MAX_CHECKPOINTS)throw new IOException("Checkpoint bounds/exhausted");wipe(pendingPlain);pendingPlain=null;
        byte[] salt=new byte[32],nonce=new byte[12],derived=null;RNG.nextBytes(salt);RNG.nextBytes(nonce);
        try {
            derived=checkpointKey(salt);Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding","SunJCE");
            cipher.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(derived,"AES"),new GCMParameterSpec(128,nonce));
            cipher.updateAAD(KEYSTORE_AAD);cipher.updateAAD(CHECKPOINT_V5);cipher.updateAAD(salt);
            byte[] body=CheckpointCodec.seal(cipher,nonce,plaintext);
            sealed=ByteBuffer.allocate(CHECKPOINT_V5.length+salt.length+body.length).put(CHECKPOINT_V5).put(salt).put(body).array();generation++;
            try{persistAnchor();atomic(data,data.resolve("engine.bin"),sealed);}catch(Exception e){failed=true;throw e;}
        }finally{wipe(derived);}
    }
    private byte[] checkpointKey(byte[] salt)throws GeneralSecurityException {
        Mac m=Mac.getInstance("HmacSHA256","SunJCE");m.init(new SecretKeySpec(key,"HmacSHA256"));m.update(DERIVE_V5);return m.doFinal(salt);
    }
    private byte[] decrypt(byte[] bytes)throws Exception {
        if(bytes.length<28)throw new IOException("Sealed checkpoint bounds");
        boolean modern=bytes.length>=CHECKPOINT_V5.length && MessageDigest.isEqual(CHECKPOINT_V5,Arrays.copyOf(bytes,CHECKPOINT_V5.length));
        int offset=modern?CHECKPOINT_V5.length+32:0;
        if(bytes.length<offset+28)throw new IOException("Sealed checkpoint bounds");
        byte[] derived=modern?checkpointKey(Arrays.copyOfRange(bytes,CHECKPOINT_V5.length,offset)):null;
        try{
            Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding","SunJCE");
            cipher.init(Cipher.DECRYPT_MODE,new SecretKeySpec(modern?derived:key,"AES"),new GCMParameterSpec(128,Arrays.copyOfRange(bytes,offset,offset+12)));
            cipher.updateAAD(KEYSTORE_AAD);
            if(modern){cipher.updateAAD(CHECKPOINT_V5);cipher.updateAAD(bytes,CHECKPOINT_V5.length,32);}
            return cipher.doFinal(bytes,offset+12,bytes.length-offset-12);
        }finally{wipe(derived);}
    }

    synchronized long next(String fingerprint)throws IOException {
        available();long[] cursor=cursors.computeIfAbsent(fingerprint,k->new long[2]);
        if(cursor[0]==cursor[1]){
            if(!high.containsKey(fingerprint) && high.size()>=4096)throw new IOException("Lifetime key limit");long start=high.getOrDefault(fingerprint,0L);if(start>Long.MAX_VALUE-128)throw new IOException("Nonce exhausted");
            high.put(fingerprint,start+128);try{persistAnchor();}catch(IOException e){failed=true;throw e;}
            cursor[0]=start;cursor[1]=start+128;writes++;
        }
        return cursor[0]++;
    }
    synchronized long writes(){return writes;}
    private void persistAnchor()throws IOException {
        byte[] record=AnchorCodec.record(generation,sealed,high);int contentLength=record.length-32;
        byte[] mac=authenticate(record,contentLength);System.arraycopy(mac,0,record,contentLength,32);
        atomic(anchor,anchor.resolve("anchor.bin"),record);
    }
    private byte[] authenticate(byte[] bytes,int length)throws IOException {
        try{Mac m=Mac.getInstance("HmacSHA256","SunJCE");m.init(new SecretKeySpec(macKey,"HmacSHA256"));m.update(bytes,0,length);return m.doFinal();}catch(GeneralSecurityException e){throw new IOException(e);}
    }
    private void readAnchor(byte[] bytes)throws IOException {
        if(bytes.length<32)throw new IOException("Anchor authentication bounds");int contentLength=bytes.length-32;
        if(!MessageDigest.isEqual(authenticate(bytes,contentLength),Arrays.copyOfRange(bytes,contentLength,bytes.length)))throw new IOException("Anchor authentication failed");
        Map<String,Long> parsed=new TreeMap<>();AnchorCodec.Decoded decoded=AnchorCodec.readBody(bytes,contentLength,parsed);
        generation=decoded.generation();sealed=decoded.sealed();high.putAll(parsed);
    }
    @Override public synchronized void close()throws IOException {if(!closed){closed=true;wipe(key);wipe(macKey);wipe(pendingPlain);pendingPlain=null;try{lease.release();}finally{leaseChannel.close();}}}
}
