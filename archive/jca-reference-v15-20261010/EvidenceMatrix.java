import java.io.*;
import java.nio.*;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.util.*;

/** Requirement-to-evidence tests of the protected engine, no vulnerable implementations. */
public final class EvidenceMatrix {
    static int checks;static final StringBuilder csv=new StringBuilder("profile,requirement,case_name,evidence_kind,observed,passed\n");
    @FunctionalInterface interface Action{void run()throws Exception;}
    static void row(int category,String requirement,String name,String kind,boolean passed){checks++;if(!passed)throw new AssertionError(name);csv.append(category).append(',').append(requirement).append(',').append(name).append(',').append(kind).append(",expected_behavior,true\n");}
    static void reject(int category,String requirement,String name,String kind,Action action)throws Exception {try{action.run();}catch(IOException|java.security.GeneralSecurityException|SecurityException|IllegalStateException expected){row(category,requirement,name,kind,true);return;}throw new AssertionError("Not rejected: "+name);}
    static PqcExtension.Profile changed(PqcExtension.Profile p,int variant){
        return switch(variant){
            case 0->new PqcExtension.Profile(p.policyVersion(),p.keyVersion(),"UNAPPROVED_KEM",p.signature(),p.category(),p.provider(),true);
            case 1->new PqcExtension.Profile(p.policyVersion(),p.keyVersion(),p.kem(),"UNAPPROVED_SIGNATURE",p.category(),p.provider(),true);
            case 2->new PqcExtension.Profile(p.policyVersion(),p.keyVersion(),p.kem(),p.signature(),p.category(),"UNTRUSTED_LABEL",true);
            case 3->new PqcExtension.Profile(p.policyVersion(),p.keyVersion(),p.kem(),p.signature(),p.category(),p.provider(),false);
            case 4->new PqcExtension.Profile(p.policyVersion()+1,p.keyVersion(),p.kem(),p.signature(),p.category(),p.provider(),true);
            case 5->new PqcExtension.Profile(p.policyVersion(),p.keyVersion()+1,p.kem(),p.signature(),p.category(),p.provider(),true);
            case 6->new PqcExtension.Profile(p.policyVersion(),p.keyVersion(),p.kem(),p.signature(),1,p.provider(),true);
            default->throw new IllegalArgumentException();
        };
    }
    static int[] offsets(byte[] encoded){ByteBuffer b=ByteBuffer.wrap(encoded);b.getInt();int[] offsets=new int[6];for(int i=0;i<6;i++){int n=b.getInt();offsets[i]=b.position();b.position(b.position()+n);}return offsets;}
    public static void main(String[] args)throws Exception {
        Path out=Path.of(args[0]);Files.createDirectories(out);int fork=Integer.parseInt(args[1]);List<PqcExtension.Profile> profiles=fork%2==0?List.of(PqcExtension.P3,PqcExtension.P5):List.of(PqcExtension.P5,PqcExtension.P3);
        Path root=Files.createTempDirectory("evidence-v5-",PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        try{
            for(PqcExtension.Profile p:profiles){
                int cat=p.category();Path directory=RecoveryTest.dir(root,"p"+cat);byte[] message=new byte[4096];new java.security.SecureRandom().nextBytes(message);
                try(PqcExtension.Engine e=new PqcExtension.Engine(p,PqcExtension.CONTEXT,directory)){
                    String[] names={"unapproved_kem","unapproved_signature","provider_label","pqc_required_disabled","policy_version_mismatch","key_version_mismatch","category_mismatch"};
                    for(int i=0;i<names.length;i++){PqcExtension.Profile candidate=changed(p,i);String req=i==2?"P1_provider_selection":i==3?"E2_pqc_mandatory":i>=4?"P2_snapshot":"P1_algorithm_tuple";reject(cat,req,names[i],"actual_prepare_guard",()->e.prepare(candidate,PqcExtension.CONTEXT));}
                    reject(cat,"P3_metadata","different_context","actual_prepare_guard",()->e.prepare(p,"tenant-B/document-1"));
                    PqcExtension.Prepared token=e.prepare(p,PqcExtension.CONTEXT);PqcExtension.Packet packet=e.seal(token,message);row(cat,"E1_normal_transition","approved_roundtrip","actual_jca_crypto",Arrays.equals(message,e.open(token,packet)));
                    reject(cat,"P2_request_state","token_reuse","actual_engine_state",()->e.seal(token,message));
                    byte[] encoded=packet.encode();String[] fields={"binding","capsule","salt","nonce","ciphertext","signature"};int[] offsets=offsets(encoded);
                    for(int i=0;i<fields.length;i++){byte[] mutation=encoded.clone();mutation[offsets[i]]^=1;PqcExtension.Packet input=PqcExtension.Packet.decode(mutation);reject(cat,"P3_frame_authentication",fields[i]+"_changed","actual_crypto_or_binding_rejection",()->e.open(token,input));}
                    Set<String> nonces=new HashSet<>();
                    for(int n=0;n<16;n++){PqcExtension.Prepared next=e.prepare(p,PqcExtension.CONTEXT);PqcExtension.Packet value=e.seal(next,message);byte[] bytes=value.encode();int pos=offsets(bytes)[3];row(cat,"P2_nonce","fresh_nonce_"+n,"actual_engine_state",nonces.add(HexFormat.of().formatHex(Arrays.copyOfRange(bytes,pos,pos+12))));}
                    Random random=new Random(0x505143L+cat);int rejected=0;
                    for(int n=0;n<512;n++){byte[] mutation=encoded.clone();int field=n%6;int pos=offsets[field]-4;ByteBuffer.wrap(mutation).putInt(pos,random.nextBoolean()?Integer.MAX_VALUE:-1-random.nextInt(4096));try{PqcExtension.Packet.decode(mutation);throw new AssertionError("Malformed length accepted");}catch(IOException expected){rejected++;}}
                    row(cat,"P3_parser_bounds","512_invalid_lengths","defensive_parser_batch",rejected==512);
                }
                for(PqcExtension.Step failure:PqcExtension.Step.values()){
                    java.util.concurrent.atomic.AtomicBoolean enabled=new java.util.concurrent.atomic.AtomicBoolean();
                    try(PqcExtension.Engine e=new PqcExtension.Engine(p,PqcExtension.CONTEXT,RecoveryTest.dir(root,"fault"+cat+failure),step->{if(enabled.get() && step==failure)throw new java.security.GeneralSecurityException("Defensive adapter failure");})){
                        PqcExtension.Prepared token=e.prepare(p,PqcExtension.CONTEXT);PqcExtension.Packet packet=e.seal(token,message);enabled.set(true);
                        if(failure==PqcExtension.Step.BEFORE_VERIFICATION || failure==PqcExtension.Step.BEFORE_DECRYPTION)reject(cat,"P3_failure_closed",failure.name(),"actual_execution_adapter_exception",()->e.open(token,packet));
                        else reject(cat,"P3_failure_closed",failure.name(),"actual_execution_adapter_exception",()->e.seal(e.prepare(p,PqcExtension.CONTEXT),message));
                    }
                }
            }
            Files.writeString(out.resolve("evidence-matrix.csv"),csv);Files.writeString(out.resolve("evidence-summary.json"),"{\"passed\":true,\"checks\":"+checks+",\"parser_cases\":1024,\"scope\":\"protected engine defensive verification; no malicious Provider or attack blocking rate\"}\n");System.out.println("PASS evidence matrix checks="+checks+" parser_cases=1024");
        }finally{try(var walk=Files.walk(root)){for(Path p:walk.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}}
    }
}
