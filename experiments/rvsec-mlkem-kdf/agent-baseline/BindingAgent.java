import java.io.ByteArrayInputStream;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import javassist.*;
import javassist.expr.ExprEditor;
import javassist.expr.MethodCall;

/** Coverage-aware controlled app call-site / KDF method instrumenter; NOT provider attestation. */
public final class BindingAgent {
    public static void premain(String ignored, Instrumentation inst) {
        System.out.println("AGENT_PREMAIN=true");
        System.out.println("AGENT_MODE=" + AgentProbe.MODE);
        inst.addTransformer(new ClassFileTransformer() {
            public byte[] transform(ClassLoader loader, String name,
                    Class<?> redefined, ProtectionDomain pd, byte[] original) {
                if (!"RegistrationTrustExperiment".equals(name)
                        && !"KdfBindingExperiment".equals(name)) return null;
                CtClass cc = null;
                try {
                    ClassPool pool = new ClassPool(true);
                    if (loader != null) pool.insertClassPath(new LoaderClassPath(loader));
                    cc = pool.makeClass(new ByteArrayInputStream(original));
                    if ("RegistrationTrustExperiment".equals(name)) {
                        final int[] hooks = {0};
                        cc.getDeclaredMethod("main").instrument(new ExprEditor() {
                            public void edit(MethodCall call) throws CannotCompileException {
                                if ("org.bouncycastle.jcajce.SecretKeyWithEncapsulation"
                                        .equals(call.getClassName())
                                        && "getEncoded".equals(call.getMethodName())) {
                                    call.replace("{ $_ = $proceed($$); AgentProbe.captureKem($_); }");
                                    hooks[0]++;
                                }
                            }
                        });
                        if (hooks[0] != 2) throw new IllegalStateException(
                            "Expected 2 KEM result getEncoded call sites, got " + hooks[0]);
                        System.out.println("AGENT_CALLSITE_HOOKS=" + hooks[0]);
                    } else {
                        cc.getDeclaredMethod("derive")
                            .insertBefore("{ AgentProbe.beforeKdf($2); }");
                        cc.getDeclaredMethod("record")
                            .insertBefore("{ AgentProbe.beforeRecord(); }");
                    }
                    byte[] modified = cc.toBytecode();
                    AgentProbe.transformed(name);
                    System.out.println("AGENT_TRANSFORMED=" + name);
                    return modified;
                } catch (Throwable e) {
                    System.err.println("AGENT_TRANSFORM_ERROR=" + name + ":" + e);
                    e.printStackTrace(System.err);
                    return null;  // Experiment audit treats missing hooks as failure.
                } finally {
                    if (cc != null) cc.detach();
                }
            }
        });
    }
}
