import java.io.*;
import java.nio.*;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.util.*;

/** Deterministic test-only master key; not a production credential. */
public final class RecoveryTest {
    static int checks;
    static byte[] key(){byte[] k=new byte[32];Arrays.fill(k,(byte)73);return k;}
    static void check(boolean ok,String label){if(!ok)throw new AssertionError(label);checks++;}
    @FunctionalInterface interface Action{void run()throws Exception;}
    static void refused(Action action)throws Exception {try{action.run();}catch(IOException|java.security.GeneralSecurityException|SecurityException|IllegalStateException expected){checks++;return;}throw new AssertionError("Expected refusal");}
    static Path dir(Path parent,String name)throws Exception{return Files.createDirectory(parent.resolve(name),PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));}
    static long sequence(PqcExtension.Packet packet)throws Exception {ByteBuffer b=ByteBuffer.wrap(packet.encode());b.getInt();for(int i=0;i<3;i++){int len=b.getInt();b.position(b.position()+len);}check(b.getInt()==12,"nonce length");b.getInt();return b.getLong();}
    static void tests(Path out)throws Exception {
        Files.createDirectories(out);Path root=Files.createTempDirectory("recovery-v4-",PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));Path data=dir(root,"data"),anchor=dir(root,"trusted");byte[] master=key(),message={1,2,3};PqcExtension.Packet old,fresh;byte[] before,after;
        try(PqcExtension.Engine e=PqcExtension.Engine.createPersistent(PqcExtension.P3,PqcExtension.CONTEXT,data,anchor,master)){
            PqcExtension.Prepared request=e.prepare(PqcExtension.P3,PqcExtension.CONTEXT);old=e.seal(request,message);check(sequence(old)==0,"initial sequence");check(Arrays.equals(message,e.open(request,PqcExtension.Packet.decode(old.encode()))),"serialized roundtrip");
            refused(()->PqcExtension.Engine.reopen(PqcExtension.CONTEXT,data,anchor,master,false));before=Files.readAllBytes(data.resolve("engine.bin"));e.activate(PqcExtension.P5);fresh=e.seal(e.prepare(PqcExtension.P5,PqcExtension.CONTEXT),message);after=Files.readAllBytes(data.resolve("engine.bin"));check(!Arrays.equals(before,after),"checkpoint changed");check(Arrays.equals(message,e.open(e.prepareHistorical(1),old)),"history");refused(()->e.seal(e.prepareHistorical(1),message));
        }
        try(PqcExtension.Engine e=PqcExtension.Engine.reopen(PqcExtension.CONTEXT,data,anchor,master,false)){
            check(e.currentProfile().equals(PqcExtension.P5),"active restored");check(Arrays.equals(message,e.open(e.prepareHistorical(1),old)),"P3 keys restored");check(Arrays.equals(message,e.open(e.prepare(PqcExtension.P5,PqcExtension.CONTEXT),fresh)),"P5 keys restored");check(sequence(e.seal(e.prepare(PqcExtension.P5,PqcExtension.CONTEXT),message))==128,"nonce restart");refused(()->e.activate(new PqcExtension.Profile(3,3,"ML-KEM-768","ML-DSA-65",3,"BC",true)));refused(()->e.activate(PqcExtension.P5));
        }
        byte[] wrong=key();wrong[0]^=1;refused(()->PqcExtension.Engine.reopen(PqcExtension.CONTEXT,data,anchor,wrong,true));check(Arrays.equals(after,Files.readAllBytes(data.resolve("engine.bin"))),"wrong key no write");refused(()->PqcExtension.Engine.reopen("wrong-context",data,anchor,master,false));
        Files.write(data.resolve("engine.bin"),before);refused(()->PqcExtension.Engine.reopen(PqcExtension.CONTEXT,data,anchor,master,false));
        try(PqcExtension.Engine e=PqcExtension.Engine.reopen(PqcExtension.CONTEXT,data,anchor,master,true)){check(e.currentProfile().equals(PqcExtension.P5),"repair preserves P5");check(Arrays.equals(after,Files.readAllBytes(data.resolve("engine.bin"))),"repair authoritative");check(sequence(e.seal(e.prepare(PqcExtension.P5,PqcExtension.CONTEXT),message))==256,"repair no rewind");}
        byte[] corrupt=after.clone();corrupt[corrupt.length-1]^=1;Files.write(data.resolve("engine.bin"),corrupt);refused(()->PqcExtension.Engine.reopen(PqcExtension.CONTEXT,data,anchor,master,false));
        try(PqcExtension.Engine e=PqcExtension.Engine.reopen(PqcExtension.CONTEXT,data,anchor,master,true)){check(Arrays.equals(message,e.open(e.prepareHistorical(1),old)),"repair old data");}
        Files.delete(data.resolve("engine.bin"));refused(()->PqcExtension.Engine.reopen(PqcExtension.CONTEXT,data,anchor,master,false));
        try(PqcExtension.Engine e=PqcExtension.Engine.reopen(PqcExtension.CONTEXT,data,anchor,master,true)){PqcExtension.Prepared held=e.prepareHistorical(1);e.retire(1);refused(()->e.open(held,old));refused(()->e.prepareHistorical(1));refused(()->e.retire(2));check(Arrays.equals(message,e.open(e.prepare(PqcExtension.P5,PqcExtension.CONTEXT),fresh)),"current survives retire");}
        try(PqcExtension.Engine e=PqcExtension.Engine.reopen(PqcExtension.CONTEXT,data,anchor,master,false)){refused(()->e.prepareHistorical(1));check(e.currentProfile().equals(PqcExtension.P5),"retirement persists");}
        byte[] encoded=fresh.encode();refused(()->PqcExtension.Packet.decode(Arrays.copyOf(encoded,encoded.length-1)));refused(()->PqcExtension.Packet.decode(Arrays.copyOf(encoded,encoded.length+1)));byte[] oversized=encoded.clone();ByteBuffer.wrap(oversized).putInt(4,Integer.MAX_VALUE);refused(()->PqcExtension.Packet.decode(oversized));byte[] changed=encoded.clone();changed[0]^=1;refused(()->PqcExtension.Packet.decode(changed));
        for(int n=0;n<80;n++){int len=n;refused(()->PqcExtension.Packet.decode(Arrays.copyOf(encoded,len)));}
        refused(()->PqcExtension.Engine.createPersistent(PqcExtension.P3,PqcExtension.CONTEXT,data,anchor,master));byte[] trusted=Files.readAllBytes(anchor.resolve("anchor.bin"));byte[] damaged=trusted.clone();damaged[20]^=1;Files.write(anchor.resolve("anchor.bin"),damaged);refused(()->PqcExtension.Engine.reopen(PqcExtension.CONTEXT,data,anchor,master,false));Files.write(anchor.resolve("anchor.bin"),trusted);
        Files.setPosixFilePermissions(data.resolve("engine.bin"),PosixFilePermissions.fromString("rw-r--r--"));refused(()->PqcExtension.Engine.reopen(PqcExtension.CONTEXT,data,anchor,master,false));Files.setPosixFilePermissions(data.resolve("engine.bin"),PosixFilePermissions.fromString("rw-------"));
        Path mirror=data.resolve("engine.bin"),other=root.resolve("innocent");Files.write(other,new byte[]{42});Files.delete(mirror);Files.createSymbolicLink(mirror,other);refused(()->PqcExtension.Engine.reopen(PqcExtension.CONTEXT,data,anchor,master,true));check(Files.readAllBytes(other)[0]==42,"symlink target intact");Files.delete(mirror);Files.write(mirror,after,StandardOpenOption.CREATE_NEW);Files.setPosixFilePermissions(mirror,PosixFilePermissions.fromString("rw-------"));
        Files.delete(anchor.resolve("anchor.bin"));refused(()->PqcExtension.Engine.reopen(PqcExtension.CONTEXT,data,anchor,master,true));refused(()->PqcExtension.Engine.createPersistent(PqcExtension.P3,PqcExtension.CONTEXT,data,anchor,master));Files.write(anchor.resolve("anchor.bin"),trusted,StandardOpenOption.CREATE_NEW);Files.setPosixFilePermissions(anchor.resolve("anchor.bin"),PosixFilePermissions.fromString("rw-------"));
        Path d2=dir(root,"data2"),a2=dir(root,"trusted2");PqcExtension.Packet first;
        try(PqcExtension.Engine e=PqcExtension.Engine.createPersistent(PqcExtension.P3,PqcExtension.CONTEXT,d2,a2,master)){first=e.seal(e.prepare(PqcExtension.P3,PqcExtension.CONTEXT),message);}
        for(int i=1;i<=2;i++)try(PqcExtension.Engine e=PqcExtension.Engine.reopen(PqcExtension.CONTEXT,d2,a2,master,false)){check(Arrays.equals(message,e.open(e.prepare(PqcExtension.P3,PqcExtension.CONTEXT),first)),"same key restart");check(sequence(e.seal(e.prepare(PqcExtension.P3,PqcExtension.CONTEXT),message))==i*128,"P3 highwater");}
        // Real commit failure between trusted publication and untrusted mirror publication.
        Path d3=dir(root,"data3"),a3=dir(root,"trusted3");
        try(PqcExtension.Engine e=PqcExtension.Engine.createPersistent(PqcExtension.P3,PqcExtension.CONTEXT,d3,a3,master)){
            PqcExtension.Prepared token=e.prepare(PqcExtension.P3,PqcExtension.CONTEXT);PqcExtension.Packet packet=e.seal(token,message);Files.delete(d3.resolve("engine.bin"));Files.createSymbolicLink(d3.resolve("engine.bin"),other);
            refused(()->e.activate(PqcExtension.P5));refused(()->e.open(token,packet));check(Files.readAllBytes(other)[0]==42,"failed commit target intact");
        }
        Files.delete(d3.resolve("engine.bin"));refused(()->PqcExtension.Engine.reopen(PqcExtension.CONTEXT,d3,a3,master,false));
        try(PqcExtension.Engine e=PqcExtension.Engine.reopen(PqcExtension.CONTEXT,d3,a3,master,true)){check(e.currentProfile().equals(PqcExtension.P5),"anchor-first commit recoverable");}
        PqcExtension.wipe(master,wrong);Files.writeString(out.resolve("recovery-results.json"),"{\"checks\":"+checks+",\"passed\":true,\"threat_model\":\"trusted anchor and master key excluded from rollback\"}\n");System.out.println("PASS recovery checks="+checks);
    }
    static void worker(String mode,Path root)throws Exception {
        Path data=root.resolve("data"),anchor=root.resolve("trusted");byte[] k=key(),message={7,8,9};
        if(mode.equals("create")){
            try(PqcExtension.Engine e=PqcExtension.Engine.createPersistent(PqcExtension.P3,PqcExtension.CONTEXT,data,anchor,k)){PqcExtension.Packet p=e.seal(e.prepare(PqcExtension.P3,PqcExtension.CONTEXT),message);Files.write(root.resolve("old.packet"),p.encode());System.out.println("RESERVED="+sequence(p));System.out.flush();System.in.read();}
        }else if(mode.equals("upgrade")){
            try(PqcExtension.Engine e=PqcExtension.Engine.reopen(PqcExtension.CONTEXT,data,anchor,k,false)){check(Arrays.equals(message,e.open(e.prepareHistorical(1),PqcExtension.Packet.decode(Files.readAllBytes(root.resolve("old.packet"))))),"cross process P3");check(sequence(e.seal(e.prepare(PqcExtension.P3,PqcExtension.CONTEXT),message))==128,"SIGKILL highwater");e.activate(PqcExtension.P5);Files.write(root.resolve("new.packet"),e.seal(e.prepare(PqcExtension.P5,PqcExtension.CONTEXT),message).encode());System.out.println("PASS upgrade checks="+checks);}
        }else if(mode.equals("verify")){
            try(PqcExtension.Engine e=PqcExtension.Engine.reopen(PqcExtension.CONTEXT,data,anchor,k,false)){check(e.currentProfile().equals(PqcExtension.P5),"cross process active P5");check(Arrays.equals(message,e.open(e.prepareHistorical(1),PqcExtension.Packet.decode(Files.readAllBytes(root.resolve("old.packet"))))),"cross process history P3");check(Arrays.equals(message,e.open(e.prepare(e.currentProfile(),PqcExtension.CONTEXT),PqcExtension.Packet.decode(Files.readAllBytes(root.resolve("new.packet"))))),"cross process P5");check(sequence(e.seal(e.prepare(e.currentProfile(),PqcExtension.CONTEXT),message))==128,"P5 highwater");System.out.println("PASS verify checks="+checks);}
        }else throw new IllegalArgumentException("mode");PqcExtension.wipe(k);
    }
    public static void main(String[] args)throws Exception {if(args.length==1)tests(Path.of(args[0]));else worker(args[0],Path.of(args[1]));}
}
