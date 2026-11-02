import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Map;

/** Exact TSA4 wire record with a reserved 32-byte MAC tail; caller authenticates only the prefix. */
final class AnchorCodec {
    record Decoded(long generation,byte[] sealed) {}
    static byte[] record(long generation,byte[] sealed,Map<String,Long> high)throws IOException {
        if(generation<=0 || sealed==null || sealed.length<28 || sealed.length>1024*1024+76 || high==null || high.size()>4096)throw new IOException("Anchor encoding bounds");
        for(var entry:high.entrySet()){
            String fp=entry.getKey();Long counter=entry.getValue();if(fp==null || fp.length()!=64 || counter==null || counter<0)throw new IOException("Anchor entry bounds");
            for(int i=0;i<64;i++){char c=fp.charAt(i);if(!(c>='0' && c<='9' || c>='a' && c<='f'))throw new IOException("Anchor fingerprint encoding");}
        }
        // 20-byte header + sealed + 2-byte UTF length/64 ASCII chars/8-byte counter per key + MAC.
        ByteBuffer out=ByteBuffer.allocate(20+sealed.length+74*high.size()+32);
        out.putInt(0x54534134).putLong(generation).putInt(sealed.length).put(sealed).putInt(high.size());
        for(var entry:high.entrySet()){
            out.putShort((short)64);String fp=entry.getKey();for(int i=0;i<64;i++)out.put((byte)fp.charAt(i));out.putLong(entry.getValue());
        }
        return out.array();
    }

    /** Parse only the authenticated prefix. Own the returned sealed array. */
    static Decoded readBody(byte[] record,int contentLength,Map<String,Long> high)throws IOException {
        if(record==null || contentLength<48 || contentLength>record.length || contentLength>2*1024*1024 || high==null || !high.isEmpty())throw new IOException("Anchor decoding bounds");
        ByteBuffer in=ByteBuffer.wrap(record,0,contentLength);if(in.getInt()!=0x54534134)throw new IOException("Anchor header");long generation=in.getLong();int len=in.getInt();
        if(generation<=0 || len<28 || len>1024*1024+76 || len>in.remaining()-4)throw new IOException("Anchor size");
        // Validate the complete entry layout before copying the checkpoint.
        int sealedOffset=in.position();in.position(sealedOffset+len);int n=in.getInt();
        if(n<0 || n>4096 || in.remaining()!=74*n)throw new IOException("Anchor key count/layout");
        for(int i=0;i<n;i++){
            if(Short.toUnsignedInt(in.getShort())!=64)throw new IOException("Anchor fingerprint length");
            char[] text=new char[64];for(int j=0;j<64;j++){int c=Byte.toUnsignedInt(in.get());if(!(c>='0' && c<='9' || c>='a' && c<='f'))throw new IOException("Anchor fingerprint");text[j]=(char)c;}
            String fp=new String(text);long counter=in.getLong();if(counter<0 || high.put(fp,counter)!=null)throw new IOException("Anchor counter");
        }
        byte[] sealed=java.util.Arrays.copyOfRange(record,sealedOffset,sealedOffset+len);return new Decoded(generation,sealed);
    }
}
