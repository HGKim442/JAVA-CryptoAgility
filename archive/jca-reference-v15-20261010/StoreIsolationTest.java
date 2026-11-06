import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/** Benign storage lifecycle checks with only the JDK on the runtime classpath. */
public final class StoreIsolationTest {
    static int checks;
    static void check(boolean value){if(!value)throw new AssertionError("Store isolation");checks++;}
    public static void main(String[] args)throws Exception {
        Path root=Files.createTempDirectory("store-isolation-",PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        byte[] master=new byte[32];Arrays.fill(master,(byte)11);
        Path data=Files.createDirectory(root.resolve("data"),PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        Path anchor=Files.createDirectory(root.resolve("anchor"),PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        byte[] plain={1,2,3};
        try {
            byte[] heldKey,heldMac;
            try(TrustedStateStore store=new TrustedStateStore(data,anchor,master,true,false)){
                var key=TrustedStateStore.class.getDeclaredField("key");key.setAccessible(true);heldKey=(byte[])key.get(store);
                var mac=TrustedStateStore.class.getDeclaredField("macKey");mac.setAccessible(true);heldMac=(byte[])mac.get(store);
                store.save(plain);check(Arrays.equals(store.load(),plain));
            }
            check(Arrays.equals(heldKey,new byte[32]));check(Arrays.equals(heldMac,new byte[32]));check(master[0]==11);
            try(TrustedStateStore store=new TrustedStateStore(data,anchor,master,false,false)){check(Arrays.equals(store.load(),plain));}
            try(TrustedStateStore ignored=new TrustedStateStore(data,anchor,new byte[32],false,false)){
                check(!ignored.usable());throw new AssertionError("Wrong key accepted");
            }catch(java.io.IOException expected){check(true);}
            // Failed constructor must release the lease so the legitimate caller can reopen.
            try(TrustedStateStore store=new TrustedStateStore(data,anchor,master,false,false)){check(store.usable());}
            Cipher wrong=Cipher.getInstance("AES/ECB/PKCS5Padding","SunJCE");wrong.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(master,"AES"));
            try{CheckpointCodec.seal(wrong,new byte[12],plain);throw new AssertionError("Wrong output shape accepted");}
            catch(java.security.GeneralSecurityException expected){check(true);}
        }finally{
            Arrays.fill(master,(byte)0);
            try(var paths=Files.walk(root)){for(Path path:paths.sorted(java.util.Comparator.reverseOrder()).toList())Files.delete(path);}
        }
        Path out=Path.of(args[0]);Files.createDirectories(out);
        Files.writeString(out.resolve("store-isolation.json"),"{\"passed\":true,\"checks\":"+checks+",\"scope\":\"JDK-only normal storage, failed constructor lease release, close wipes and codec rejection\"}\n");
        System.out.println("PASS JDK-only store checks="+checks);
    }
}
