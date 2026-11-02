import java.nio.file.*;
import java.nio.file.attribute.*;
import java.util.*;

/** Synthetic store-owned key/plaintext lifecycles, no secret logging. */
public final class ReuseCleanupTest {
    static int checks;
    static void check(boolean value){if(!value)throw new AssertionError("Reuse lifecycle");checks++;}
    static byte[] field(TrustedStateStore store,String name)throws Exception {var f=TrustedStateStore.class.getDeclaredField(name);f.setAccessible(true);return (byte[])f.get(store);}
    static boolean zero(byte[] a){for(byte b:a)if(b!=0)return false;return true;}
    public static void main(String[] args)throws Exception {
        Path root=Files.createTempDirectory("reuse-cleanup-",PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));byte[] master=new byte[32];Arrays.fill(master,(byte)73);
        try{
            Path data=RecoveryTest.dir(root,"data"),anchor=RecoveryTest.dir(root,"anchor");
            try(PqcExtension.Engine e=PqcExtension.Engine.createPersistent(PqcExtension.P3,"reuse-v15",data,anchor,master)){check(e.currentProfile().equals(PqcExtension.P3));}
            byte[] heldMac,heldMaster,heldPending;
            TrustedStateStore captured=TrustedStateStore.openForEngine(data,anchor,master,false);
            heldMac=field(captured,"macKey");heldMaster=field(captured,"key");heldPending=field(captured,"pendingPlain");check(heldPending!=null && heldPending.length>32);check(heldMac.length==32);
            byte[] loaded=captured.load();check(loaded==heldPending);check(field(captured,"pendingPlain")==null);byte[] again=captured.load();check(again!=loaded && Arrays.equals(loaded,again));PqcExtension.wipe(loaded,again);captured.close();check(zero(heldMac));check(zero(heldMaster));check(zero(heldPending));
            TrustedStateStore abandoned=TrustedStateStore.openForEngine(data,anchor,master,false);byte[] unused=field(abandoned,"pendingPlain"),mac=field(abandoned,"macKey");abandoned.close();check(zero(unused));check(zero(mac));check(field(abandoned,"pendingPlain")==null);
            try(TrustedStateStore publicStore=new TrustedStateStore(data,anchor,master,false,false)){check(field(publicStore,"pendingPlain")==null);byte[] owned=publicStore.load();check(owned.length>32);PqcExtension.wipe(owned);}
            TrustedStateStore replaced=TrustedStateStore.openForEngine(data,anchor,master,false);byte[] obsolete=field(replaced,"pendingPlain"),replacement=replaced.load();
            try{replaced.save(replacement);check(zero(obsolete)==false);/* load transferred ownership to this caller */}finally{PqcExtension.wipe(replacement);replaced.close();}check(zero(obsolete));
            // Pending plaintext is discarded on a save before consumption.
            TrustedStateStore beforeLoad=TrustedStateStore.openForEngine(data,anchor,master,false);byte[] pending=field(beforeLoad,"pendingPlain");byte[] independent=pending.clone();try{beforeLoad.save(independent);check(zero(pending));check(field(beforeLoad,"pendingPlain")==null);}finally{PqcExtension.wipe(independent);beforeLoad.close();}
            check(!zero(master));
        }finally{PqcExtension.wipe(master);try(var walk=Files.walk(root)){for(Path p:walk.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}}
        Path out=Path.of(args[0]);Files.createDirectories(out);Files.writeString(out.resolve("reuse-cleanup.json"),"{\"passed\":true,\"checks\":"+checks+",\"scope\":\"owned cached MAC key and one-use plaintext transfer, synthetic store data; not JVM-wide zeroization\"}\n");System.out.println("PASS reuse cleanup checks="+checks);
    }
}
