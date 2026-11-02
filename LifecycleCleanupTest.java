import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;
public final class LifecycleCleanupTest {
    static int checks;
    static void check(boolean condition){if(!condition)throw new AssertionError();checks++;}
    public static void main(String[] args)throws Exception {
        byte[] secret=new byte[32];Arrays.fill(secret,(byte)7);boolean[] called=new boolean[2];
        IOException original=new IOException("original"),first=new IOException("release"),second=new IOException("channel");
        TrustedStateStore.cleanupAfterFailure(original,secret,()->{called[0]=true;throw first;},()->{called[1]=true;throw second;});
        check(called[0]);check(called[1]);check(Arrays.equals(secret,new byte[32]));check(original.getSuppressed().length==2);check(original.getSuppressed()[0]==first);check(original.getSuppressed()[1]==second);
        Arrays.fill(secret,(byte)8);TrustedStateStore.cleanupAfterFailure(original,secret,null,null);check(Arrays.equals(secret,new byte[32]));
        Path root=Files.createTempDirectory("lifecycle-",PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        Path data=Files.createDirectory(root.resolve("data"),PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))),anchor=Files.createDirectory(root.resolve("anchor"),PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        try {try{PqcExtension.Engine.reopen("",data,anchor,new byte[32],false);throw new AssertionError();}catch(IllegalArgumentException expected){checks++;}
            try(var entries=Files.list(anchor)){check(entries.count()==0);}try(var entries=Files.list(data)){check(entries.count()==0);}
        }finally{Files.delete(data);Files.delete(anchor);Files.delete(root);}
        Path out=Path.of(args[0]);Files.createDirectories(out);Files.writeString(out.resolve("lifecycle-cleanup-tests.json"),"{\"passed\":true,\"checks\":"+checks+",\"scope\":\"synthetic cleanup exceptions and invalid-context side effects\"}\n");
        System.out.println("PASS lifecycle cleanup checks="+checks);
    }
}
