import java.io.*;
import java.nio.*;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.security.*;
import java.util.*;

/** Offline file interface. Keys stay in private files, never command-line key material. */
public final class CryptoCli {
    private static final Set<PosixFilePermission> PRIVATE=PosixFilePermissions.fromString("rw-------");
    private static final int MAX=16*1024*1024;
    static void help(){System.out.println("keygen KEY\ninit|status|upgrade5|repair KEY DATA ANCHOR CONTEXT\nseal KEY DATA ANCHOR CONTEXT INPUT OUTPUT\nseal-batch KEY DATA ANCHOR CONTEXT INPUT OUTPUT [INPUT OUTPUT ...] (max 64 files)\nseal-batch-parallel WORKERS KEY DATA ANCHOR CONTEXT INPUT OUTPUT [INPUT OUTPUT ...] (workers: 1,2,4; size/heap may reduce concurrency)\nopen KEY DATA ANCHOR CONTEXT POLICY_VERSION INPUT OUTPUT\nExisting output files are never overwritten. Read USAGE_KO.md.");}
    static Path target(String value)throws IOException {
        Path p=Path.of(value).toAbsolutePath().normalize();Path parent=p.getParent();if(parent==null || p.getFileName()==null)throw new IOException("Output path");
        TrustedStateStore.privateDirectory(parent);if(Files.exists(p,LinkOption.NOFOLLOW_LINKS))throw new FileAlreadyExistsException("Output exists");return p;
    }
    static long inputSize(Path path,int limit,boolean privateFile)throws IOException {
        var attributes=Files.readAttributes(path,PosixFileAttributes.class,LinkOption.NOFOLLOW_LINKS);
        if(!attributes.isRegularFile() || attributes.size()>limit)throw new IOException("Regular bounded input required");
        if(privateFile && attributes.permissions().stream().anyMatch(x->x.name().startsWith("GROUP_") || x.name().startsWith("OTHERS_")))throw new IOException("Private input required");
        return attributes.size();
    }
    static byte[] read(String value,int limit,boolean privateFile)throws IOException {
        Path p=Path.of(value);if(Files.isSymbolicLink(p) || !Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS))throw new IOException("Regular input required");
        if(privateFile && Files.getPosixFilePermissions(p,LinkOption.NOFOLLOW_LINKS).stream().anyMatch(x->x.name().startsWith("GROUP_") || x.name().startsWith("OTHERS_")))throw new IOException("Private input required");
        try(FileChannel ch=FileChannel.open(p,Set.of(StandardOpenOption.READ,LinkOption.NOFOLLOW_LINKS))){long size=ch.size();if(size>limit)throw new IOException("Input bounds");byte[] bytes=new byte[(int)size];
            try{ByteBuffer out=ByteBuffer.wrap(bytes);while(out.hasRemaining())if(ch.read(out)<0)throw new EOFException();if(ch.read(ByteBuffer.allocate(1))!=-1)throw new IOException("Input changed");return bytes;}catch(Exception e){Arrays.fill(bytes,(byte)0);throw e;}
        }
    }
    static void publish(Path target,byte[] bytes)throws IOException {
        publish(target,ch->{ByteBuffer in=ByteBuffer.wrap(bytes);while(in.hasRemaining())ch.write(in);});
    }
    static void publish(Path target,PqcExtension.Packet packet)throws IOException {publish(target,packet::writeTo);}
    @FunctionalInterface private interface FileWriter {void write(FileChannel channel)throws IOException;}
    private static void publish(Path target,FileWriter writer)throws IOException {
        Path parent=target.getParent(),tmp=Files.createTempFile(parent,".pqc-output-",".tmp",PosixFilePermissions.asFileAttribute(PRIVATE));
        try{try(FileChannel ch=FileChannel.open(tmp,StandardOpenOption.WRITE)){writer.write(ch);ch.force(true);}
            // POSIX hard-link publication is atomic and cannot replace an existing name.
            Files.createLink(target,tmp);try(FileChannel ch=FileChannel.open(parent,StandardOpenOption.READ)){ch.force(true);}
        }finally{Files.deleteIfExists(tmp);}
    }
    static void run(String[] args)throws Exception {
        int workers=1;boolean parallel=args.length>0 && args[0].equals("seal-batch-parallel");
        if(parallel){if(args.length<2)throw new IllegalArgumentException();workers=Integer.parseInt(args[1]);if(workers!=1 && workers!=2 && workers!=4)throw new IllegalArgumentException();String[] shifted=new String[args.length-1];shifted[0]="seal-batch";System.arraycopy(args,2,shifted,1,args.length-2);args=shifted;}
        if(args.length==0 || args[0].equals("help")){help();return;}String command=args[0];
        if(command.equals("keygen")){if(args.length!=2)throw new IllegalArgumentException();Path output=target(args[1]);byte[] key=new byte[32];try{new SecureRandom().nextBytes(key);publish(output,key);}finally{PqcExtension.wipe(key);}System.out.println("OK master key created");return;}
        Set<String> commands=Set.of("init","status","upgrade5","repair","seal","seal-batch","open");if(!commands.contains(command) || args.length<5)throw new IllegalArgumentException();
        int pairs=0;if(command.equals("seal") && args.length==7)pairs=1;else if(command.equals("seal-batch") && args.length>=7 && (args.length-5)%2==0 && args.length<=133)pairs=(args.length-5)/2;else if(command.equals("open") && args.length==8){}else if(Set.of("init","status","upgrade5","repair").contains(command) && args.length==5){}else throw new IllegalArgumentException();
        List<Path> outputs=new ArrayList<>();Set<Path> unique=new HashSet<>();for(int i=0;i<pairs;i++){Path output=target(args[6+2*i]);if(!unique.add(output))throw new IOException("Duplicate output");outputs.add(output);}
        Path openedOutput=command.equals("open")?target(args[7]):null;long version=command.equals("open")?Long.parseLong(args[5]):0;if(command.equals("open") && version<1)throw new IllegalArgumentException();
        byte[] master=read(args[1],32,true);try{if(master.length!=32)throw new IOException("Master key size");
            try(PqcExtension.Engine engine=command.equals("init")?PqcExtension.Engine.createPersistent(PqcExtension.P3,args[4],Path.of(args[2]),Path.of(args[3]),master):PqcExtension.Engine.reopen(args[4],Path.of(args[2]),Path.of(args[3]),master,command.equals("repair"))){
                if(command.equals("upgrade5")){var previous=engine.currentProfile();if(previous.category()!=3)throw new SecurityException("Already category 5");engine.activate(new PqcExtension.Profile(Math.addExact(previous.policyVersion(),1),Math.addExact(previous.keyVersion(),1),"ML-KEM-1024","ML-DSA-87",5,"BC",true));}
                if(command.equals("open")){byte[] encoded=read(args[6],MAX+10000,false),plaintext=null;try{plaintext=engine.open(engine.prepareHistorical(version),PqcExtension.Packet.decode(encoded));publish(openedOutput,plaintext);}finally{PqcExtension.wipe(encoded,plaintext);}System.out.println("OK opened");}
                else if(pairs>0){long writes=0;int effectiveWorkers=1;if(parallel){List<Path> inputs=new ArrayList<>();for(int i=0;i<pairs;i++)inputs.add(Path.of(args[5+2*i]));effectiveWorkers=engine.sealFiles(inputs,outputs,workers);writes=engine.reservationWrites(engine.prepare(engine.currentProfile(),args[4]));}else for(int i=0;i<pairs;i++){engine.sealFiles(List.of(Path.of(args[5+2*i])),List.of(outputs.get(i)),1);writes=engine.reservationWrites(engine.prepare(engine.currentProfile(),args[4]));}
                    System.out.println("OK sealed="+pairs+" policy_version="+engine.currentProfile().policyVersion()+" reservation_writes="+writes+(parallel?" requested_workers="+workers+" effective_workers="+effectiveWorkers:""));}
                else System.out.println("OK policy_version="+engine.currentProfile().policyVersion()+" category="+engine.currentProfile().category());
            }
        }finally{PqcExtension.wipe(master);}
    }
    public static void main(String[] args){try{run(args);}catch(IllegalArgumentException e){System.err.println("ERROR arguments; use help");System.exit(2);}catch(SecurityException|GeneralSecurityException e){System.err.println("ERROR policy/authentication check failed");System.exit(3);}catch(IOException e){System.err.println("ERROR storage/input check failed; check permissions, size, and output paths");System.exit(4);}catch(Exception e){System.err.println("ERROR operation failed");System.exit(5);}}
}
