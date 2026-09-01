import java.security.Provider;
import java.security.Security;
import java.security.KeyStore;
import java.security.Signature;
import java.security.PrivateKey;
import java.io.ByteArrayInputStream;

public class TestJavaPKCS11 {
    public static void main(String[] args) throws Exception {
        System.out.println("[*] Initializing SunPKCS11 provider inside JVM...");
        
        String config = "--name=SoftHSM\n" +
                        "library=/home/cab21/softhsm2_install/lib/softhsm/libsofthsm2.so\n" +
                        "slotListIndex=0\n";
                        
        Provider p = Security.getProvider("SunPKCS11");
        p = p.configure(new ByteArrayInputStream(config.getBytes()));
        Security.addProvider(p);

        System.out.println("[*] Authenticating to SoftHSM Token...");
        KeyStore ks = KeyStore.getInstance("PKCS11", p);
        ks.load(null, "5678".toCharArray());

        System.out.println("[*] Retrieving key and signing data via JNI...");
        PrivateKey privateKey = (PrivateKey) ks.getKey("ISO8583SwitchKey", null);

        Signature sig = Signature.getInstance("SHA256withRSA", p);
        sig.initSign(privateKey);
        sig.update("ISO8583_PAYMENT_PAYLOAD".getBytes());
        byte[] signatureBytes = sig.sign();

        System.out.println("[+] JVM Signature Successful: " + signatureBytes.length + " bytes generated.");
    }
}
