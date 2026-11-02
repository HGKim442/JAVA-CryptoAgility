import java.nio.file.*;
import java.nio.file.attribute.*;
import java.util.*;

/** New persistent-path cost, no causal speedup claim. */
public final class RecoveryBenchmark {
    static volatile int sink;
    public static void main(String[] args)throws Exception {
        Path out=Path.of(args[0]);Files.createDirectories(out);int offset=Integer.parseInt(args[1]);StringBuilder csv=new StringBuilder("profile,component,sample,ns\n");byte[] key=new byte[32];new java.security.SecureRandom().nextBytes(key);
        for(PqcExtension.Profile profile:offset%2==0?List.of(PqcExtension.P3,PqcExtension.P5):List.of(PqcExtension.P5,PqcExtension.P3)){
            Path root=Files.createTempDirectory("persistent-cost-",PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))),data=RecoveryTest.dir(root,"data"),anchor=RecoveryTest.dir(root,"trusted");byte[] msg=new byte[4096];PqcExtension.Packet old;
            try(PqcExtension.Engine e=PqcExtension.Engine.createPersistent(profile,PqcExtension.CONTEXT,data,anchor,key)){old=e.seal(e.prepare(profile,PqcExtension.CONTEXT),msg);}
            for(int i=-10;i<31;i++){
                long start=System.nanoTime();try(PqcExtension.Engine e=PqcExtension.Engine.reopen(PqcExtension.CONTEXT,data,anchor,key,false)){
                    long reopen=System.nanoTime()-start;start=System.nanoTime();PqcExtension.Packet next=e.seal(e.prepare(profile,PqcExtension.CONTEXT),msg);byte[] restored=e.open(e.prepare(profile,PqcExtension.CONTEXT),next);long request=System.nanoTime()-start;if(!Arrays.equals(msg,restored))throw new AssertionError();sink=restored.length;PqcExtension.wipe(restored);
                    if(!Arrays.equals(msg,e.open(e.prepareHistorical(profile.policyVersion()),old)))throw new AssertionError();
                    if(i>=0){csv.append(profile.category()).append(",reopen_key_import_pair_checks,").append(i).append(',').append(reopen).append('\n');csv.append(profile.category()).append(",first_seal_open_durable_reserve_4096,").append(i).append(',').append(request).append('\n');}
                }
            }
        }
        PqcExtension.wipe(key);Files.writeString(out.resolve("persistent-cost.csv"),csv);System.out.println("PASS persistent costs 124 samples");
    }
}
