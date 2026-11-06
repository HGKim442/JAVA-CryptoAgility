import java.io.*;
import java.nio.*;
import java.nio.channels.*;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.util.*;
import java.util.concurrent.*;

/** Durable high-water reservations; unused values are burned on restart. No rollback protection. */
public final class NonceReservations {
    private static final class LockCell {int users;}
    private static final ConcurrentMap<Path,LockCell> JVM_LOCKS=new ConcurrentHashMap<>();
    private static final Set<PosixFilePermission> PRIVATE=PosixFilePermissions.fromString("rw-------");
    private static final int MAGIC=0x4e525633;
    private final Path directory,state,lock;private final int block;private long next,end;private long reservations;
    public NonceReservations(Path directory,String keyFingerprint,int block)throws IOException {
        if(keyFingerprint==null || !keyFingerprint.matches("[0-9a-f]{64}") || block<1 || block>4096)throw new IllegalArgumentException("Invalid reservation identity/block");
        if(Files.isSymbolicLink(directory) || !Files.isDirectory(directory,LinkOption.NOFOLLOW_LINKS))throw new IOException("Private existing directory required");
        Set<PosixFilePermission> permissions=Files.getPosixFilePermissions(directory,LinkOption.NOFOLLOW_LINKS);
        if(permissions.stream().anyMatch(p->p.name().startsWith("GROUP_") || p.name().startsWith("OTHERS_")))throw new IOException("Reservation directory must be owner-only");
        this.directory=directory.toRealPath();this.state=this.directory.resolve(keyFingerprint+".counter");this.lock=this.directory.resolve(keyFingerprint+".lock");this.block=block;
    }
    public synchronized long next()throws IOException {
        if(next==end)reserve();return next++;
    }
    public synchronized long reservationWrites(){return reservations;}
    private static byte[] hash(byte[] data)throws IOException {
        try{return java.security.MessageDigest.getInstance("SHA-256","SUN").digest(data);}catch(java.security.GeneralSecurityException e){throw new IOException(e);}
    }
    private void reserve()throws IOException {
        LockCell monitor=JVM_LOCKS.compute(lock,(p,cell)->{if(cell==null)cell=new LockCell();cell.users++;return cell;});
        try {synchronized(monitor){
            try(FileChannel channel=FileChannel.open(lock,Set.of(StandardOpenOption.CREATE,StandardOpenOption.READ,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS),PosixFilePermissions.asFileAttribute(PRIVATE));FileLock acquired=channel.lock()){
                if(!acquired.isValid() || Files.isSymbolicLink(state))throw new IOException("Unsafe counter path");
                long start=0;
                if(Files.exists(state,LinkOption.NOFOLLOW_LINKS)){
                    try(FileChannel input=FileChannel.open(state,Set.of(StandardOpenOption.READ,LinkOption.NOFOLLOW_LINKS))){
                        if(input.size()!=44)throw new IOException("Corrupt counter length");ByteBuffer raw=ByteBuffer.allocate(44);while(raw.hasRemaining())if(input.read(raw)<0)throw new EOFException();raw.flip();byte[] bytes=raw.array(),data=Arrays.copyOf(bytes,12),digest=Arrays.copyOfRange(bytes,12,44);
                        if(!java.security.MessageDigest.isEqual(digest,hash(data)))throw new IOException("Counter checksum mismatch");
                        if(raw.getInt()!=MAGIC || (start=raw.getLong())<0)throw new IOException("Corrupt counter");
                    }
                } else if(Files.size(lock)>0){throw new IOException("Counter missing for enrolled key; recovery required");}
                if(start>Long.MAX_VALUE-block)throw new IOException("Nonce reservation exhausted");long high=start+block;
                if(channel.size()==0){channel.write(ByteBuffer.wrap(new byte[]{1}),0);channel.force(true);try(FileChannel dir=FileChannel.open(directory,StandardOpenOption.READ)){dir.force(true);}}
                Path temp=Files.createTempFile(directory,".counter-",".tmp",PosixFilePermissions.asFileAttribute(PRIVATE));
                try{
                    try(FileChannel output=FileChannel.open(temp,StandardOpenOption.WRITE)){byte[] data=ByteBuffer.allocate(12).putInt(MAGIC).putLong(high).array();ByteBuffer raw=ByteBuffer.allocate(44).put(data).put(hash(data));raw.flip();while(raw.hasRemaining())output.write(raw);output.force(true);}
                    Files.move(temp,state,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);
                    try(FileChannel dir=FileChannel.open(directory,StandardOpenOption.READ)){dir.force(true);}
                    next=start;end=high;reservations++;
                }finally{Files.deleteIfExists(temp);}
            }
        }} finally {JVM_LOCKS.compute(lock,(p,cell)->{if(cell!=monitor)throw new IllegalStateException("Lock registry mismatch");return --cell.users==0?null:cell;});}
    }
}
