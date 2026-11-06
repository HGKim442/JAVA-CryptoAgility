import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import javax.crypto.AEADBadTagException;

/** Checkpoint format/budget and authenticated per-document API checks. Synthetic keys only. */
public final class CompletionSecurityTest {
    static int checks;
    static void check(boolean v){if(!v)throw new AssertionError("Completion security check");checks++;}
    @FunctionalInterface interface Action {void run()throws Exception;}
    static void reject(Action a)throws Exception {try{a.run();}catch(java.io.IOException|java.security.GeneralSecurityException|IllegalArgumentException expected){checks++;return;}throw new AssertionError("Expected rejection");}
    static void clean(Path root)throws Exception {try(var paths=Files.walk(root)){for(Path p:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}}
    public static void main(String[] args)throws Exception {
        var perms=PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"));
        Path root=Files.createTempDirectory("completion-security-",perms),data=Files.createDirectory(root.resolve("data"),perms),anchor=Files.createDirectory(root.resolve("anchor"),perms);
        byte[] master=new byte[32];Arrays.fill(master,(byte)29);byte[] plain={1,2,3};
        try{
            var field=TrustedStateStore.class.getDeclaredField("generation");field.setAccessible(true);
            try(TrustedStateStore s=new TrustedStateStore(data,anchor,master,true,false)){
                s.save(plain);byte[] first=Files.readAllBytes(data.resolve("engine.bin"));s.save(plain);byte[] second=Files.readAllBytes(data.resolve("engine.bin"));
                check(first.length==plain.length+76);check(!Arrays.equals(Arrays.copyOfRange(first,16,48),Arrays.copyOfRange(second,16,48)));check(Arrays.equals(s.load(),plain));
                var decrypt=TrustedStateStore.class.getDeclaredMethod("decrypt",byte[].class);decrypt.setAccessible(true);
                for(int offset:new int[]{0,16,47,48,60,second.length-1}){
                    byte[] bad=second.clone();bad[offset]^=1;
                    try{decrypt.invoke(s,(Object)bad);throw new AssertionError("Checkpoint tampering accepted");}catch(java.lang.reflect.InvocationTargetException e){check(e.getCause() instanceof AEADBadTagException || e.getCause() instanceof java.io.IOException);}
                }
                byte[] maximum=new byte[1024*1024];s.save(maximum);check(Arrays.equals(s.load(),maximum));check(Files.size(data.resolve("engine.bin"))==maximum.length+76);
                field.setLong(s,TrustedStateStore.MAX_CHECKPOINTS-1);s.save(plain);byte[] atLimit=Files.readAllBytes(anchor.resolve("anchor.bin"));reject(()->s.save(plain));check(Arrays.equals(atLimit,Files.readAllBytes(anchor.resolve("anchor.bin"))));check(Arrays.equals(s.load(),plain));
            }
            try(TrustedStateStore s=new TrustedStateStore(data,anchor,master,false,false)){check(field.getLong(s)==TrustedStateStore.MAX_CHECKPOINTS);reject(()->s.save(plain));check(Arrays.equals(s.load(),plain));}
        }finally{Arrays.fill(master,(byte)0);clean(root);}
        for(PqcExtension.Profile profile:List.of(PqcExtension.P3,PqcExtension.P5)){
            Path dir=Files.createTempDirectory("document-security-",perms);
            try(PqcExtension.Engine engine=new PqcExtension.Engine(profile,PqcExtension.CONTEXT,dir)){
                var r=engine.prepare(profile,PqcExtension.CONTEXT);var packet=DocumentEnvelope.seal(engine,r,"tenant-A","문서-1",plain);
                check(Arrays.equals(DocumentEnvelope.open(engine,r,"tenant-A","문서-1",packet),plain));
                reject(()->engine.open(r,packet));
                reject(()->engine.sealWithAad(engine.prepare(profile,PqcExtension.CONTEXT),plain,new byte[2049]));
                reject(()->DocumentEnvelope.open(engine,r,"tenant-B","문서-1",packet));reject(()->DocumentEnvelope.open(engine,r,"tenant-A","문서-2",packet));
                reject(()->DocumentEnvelope.open(engine,r,"tenant-A","문서",packet));
                byte[] encoded=packet.encode();encoded[encoded.length-1]^=1;var altered=PqcExtension.Packet.decode(encoded);
                reject(()->DocumentEnvelope.open(engine,r,"tenant-A","문서-1",altered));
                reject(()->DocumentEnvelope.seal(engine,engine.prepare(profile,PqcExtension.CONTEXT),"","doc",plain));
                reject(()->DocumentEnvelope.seal(engine,engine.prepare(profile,PqcExtension.CONTEXT),"tenant","\ud800",plain));
                var rawRequest=engine.prepare(profile,PqcExtension.CONTEXT);var raw=engine.seal(rawRequest,new byte[64]);
                reject(()->DocumentEnvelope.open(engine,rawRequest,"tenant-A","문서-1",raw));
            }finally{clean(dir);}
        }
        Path out=Path.of(args[0]);Files.createDirectories(out);Files.writeString(out.resolve("completion-security.json"),"{\"passed\":true,\"checks\":"+checks+",\"profiles\":[3,5],\"budget_test\":\"synthetic generation marker; no billions of encryptions\",\"checkpoint_format\":5,\"scope\":\"new-format tampering, salt diversity, persistent budget and explicit PQC document identity API\"}\n");
        System.out.println("PASS completion security checks="+checks);
    }
}
