import java.nio.file.Path;
import java.util.Arrays;
/** Fixture migration used by the compiled historical-reader regression only. */
public final class CheckpointMigrationTest {
    public static void main(String[] args)throws Exception {
        byte[] master=CryptoCli.read(args[0],32,true);
        try(TrustedStateStore store=new TrustedStateStore(Path.of(args[1]),Path.of(args[2]),master,false,false)){
            byte[] plain=store.load();try{store.save(plain);}finally{Arrays.fill(plain,(byte)0);}
        }finally{Arrays.fill(master,(byte)0);}
    }
}
