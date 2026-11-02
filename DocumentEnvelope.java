import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/** Canonical tenant/document identity bound as external AES-GCM AAD in the PQC packet. */
public final class DocumentEnvelope {
    private static final long MAGIC=0x4a4341444f433031L;
    private DocumentEnvelope() {}
    private static byte[] identity(String tenant,String document) {
        if(tenant==null || document==null)throw new IllegalArgumentException("Identity required");
        // Canonical UTF-8 encoding rejects ambiguous surrogate replacement and empty fields.
        for(String value:new String[]{tenant,document}) {
            if(value.isEmpty() || value.length()>256)throw new IllegalArgumentException("Identity bounds");
            for(int i=0;i<value.length();i++)if(Character.isSurrogate(value.charAt(i)))throw new IllegalArgumentException("Surrogate identity refused");
        }
        byte[] t=tenant.getBytes(StandardCharsets.UTF_8),d=document.getBytes(StandardCharsets.UTF_8);
        return ByteBuffer.allocate(16+t.length+d.length).putLong(MAGIC).putInt(t.length).put(t).putInt(d.length).put(d).array();
    }
    public static PqcExtension.Packet seal(PqcExtension.Engine engine,PqcExtension.Prepared request,String tenant,String document,byte[] plaintext)throws Exception {
        if(plaintext==null || plaintext.length>16*1024*1024)throw new IllegalArgumentException("Document size bounds");
        return engine.sealWithAad(request,plaintext,identity(tenant,document));
    }
    public static byte[] open(PqcExtension.Engine engine,PqcExtension.Prepared request,String expectedTenant,String expectedDocument,PqcExtension.Packet packet)throws Exception {
        return engine.openWithAad(request,packet,identity(expectedTenant,expectedDocument));
    }
}
