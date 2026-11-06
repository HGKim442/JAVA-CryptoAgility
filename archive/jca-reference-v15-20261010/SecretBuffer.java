import java.io.OutputStream;
import java.util.Arrays;
import java.util.Objects;

/** Bounded owned buffer: wipes replaced backing arrays and the final array on close. */
final class SecretBuffer extends OutputStream {
    private byte[] buffer=new byte[256];private int count;private boolean closed;
    private void capacity(int extra){
        if(closed)throw new IllegalStateException("Secret buffer closed");
        if(extra<0 || extra>1024*1024-count)throw new IllegalArgumentException("Secret buffer size");
        int needed=count+extra;
        if(needed>buffer.length){byte[] prior=buffer;buffer=Arrays.copyOf(prior,Math.min(1024*1024,Math.max(needed,prior.length*2)));Arrays.fill(prior,(byte)0);}
    }
    @Override public synchronized void write(int value){capacity(1);buffer[count++]=(byte)value;}
    @Override public synchronized void write(byte[] input,int offset,int length){Objects.checkFromIndexSize(offset,length,input.length);capacity(length);System.arraycopy(input,offset,buffer,count,length);count+=length;}
    synchronized byte[] copy(){if(closed)throw new IllegalStateException("Secret buffer closed");return Arrays.copyOf(buffer,count);}
    @Override public synchronized void close(){if(!closed){Arrays.fill(buffer,(byte)0);count=0;closed=true;}}
}
