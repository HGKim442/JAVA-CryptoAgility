import java.security.GeneralSecurityException;
import javax.crypto.Cipher;

/** Nonce-prefixed AES-GCM ciphertext, with one owned output allocation. */
final class CheckpointCodec {
    static byte[] seal(Cipher cipher,byte[] nonce,byte[] plaintext)throws GeneralSecurityException {
        if(nonce==null || nonce.length!=12 || plaintext==null || plaintext.length>1024*1024)throw new GeneralSecurityException("Checkpoint bounds");
        byte[] output=new byte[12+cipher.getOutputSize(plaintext.length)];boolean transferred=false;
        try{
            System.arraycopy(nonce,0,output,0,12);int written=cipher.doFinal(plaintext,0,plaintext.length,output,12);
            if(written!=plaintext.length+16 || written+12!=output.length)throw new GeneralSecurityException("Checkpoint cipher length");
            transferred=true;return output;
        }finally{if(!transferred)java.util.Arrays.fill(output,(byte)0);}
    }
}
