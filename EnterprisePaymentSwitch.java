import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.util.Arrays;
import java.util.Enumeration;

public class EnterprisePaymentSwitch {
    private static final int PORT = 9999;
    private static final String PIN = "5678";
    private static final String CONFIG_PATH = "softhsm_jpos.cfg";

    public static void main(String[] args) {
        System.out.println("==========================================================");
        System.out.println("  PRODUCTION FINANCIAL SWITCH GATEWAY (jPOS Architecture) ");
        System.out.println("==========================================================");

        try {
            // 1. Initialize SunPKCS11 JNI Bridge
            System.out.println("[*] Initializing SunPKCS11 JNI Bridge to SoftHSMv2...");
            Provider pkcs11Provider = Security.getProvider("SunPKCS11");
            pkcs11Provider = pkcs11Provider.configure(CONFIG_PATH);
            Security.addProvider(pkcs11Provider);
            System.out.println("[+] SunPKCS11 Native Bridge Loaded: " + pkcs11Provider.getName());

            // 2. Open Session and Authenticate to Hardware Token
            System.out.println("[*] Loading Hardware Keystore from Token Slot 0...");
            KeyStore keyStore = KeyStore.getInstance("PKCS11", pkcs11Provider);
            keyStore.load(null, PIN.toCharArray());

            // 3. Dynamic Alias Resolution
            Enumeration<String> aliases = keyStore.aliases();
            String resolvedAlias = null;
            PrivateKey switchPrivateKey = null;

            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                System.out.println("    [+] Discovered Hardware Token Entry: " + alias);
                if (keyStore.isKeyEntry(alias)) {
                    resolvedAlias = alias;
                    switchPrivateKey = (PrivateKey) keyStore.getKey(alias, null);
                    break;
                }
            }

            if (switchPrivateKey == null) {
                // Fallback direct alias check
                switchPrivateKey = (PrivateKey) keyStore.getKey("ISO8583SwitchKey", null);
                if (switchPrivateKey != null) {
                    resolvedAlias = "ISO8583SwitchKey";
                }
            }

            if (switchPrivateKey == null) {
                System.err.println("[-] FATAL: No usable Private Key found on SoftHSM Token.");
                System.exit(1);
            }

            System.out.println("[+] Successfully Bound Hardware Key Handle: '" + resolvedAlias + "' (" + switchPrivateKey.getAlgorithm() + ")");

            // 4. Start ISO 8583 Financial Network Listener
            ServerSocket serverSocket = new ServerSocket(PORT);
            System.out.println("[+] Gateway Server listening for ISO 8583 transactions on TCP port " + PORT + "...\n");

            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("[*] Connection established from: " + clientSocket.getRemoteSocketAddress());

                InputStream in = clientSocket.getInputStream();
                OutputStream out = clientSocket.getOutputStream();

                byte[] buffer = new byte[4096];
                int bytesRead = in.read(buffer);

                if (bytesRead > 0) {
                    byte[] rawIsoMessage = Arrays.copyOfRange(buffer, 0, bytesRead);
                    String isoText = new String(rawIsoMessage);
                    System.out.println("    [>] Received ISO 8583 Payload (" + bytesRead + " bytes): " + isoText.trim());

                    // 5. Offload Cryptographic Signature to SoftHSMv2 via JNI
                    System.out.println("    [*] Offloading Cryptographic Signature to SoftHSMv2 via JNI...");
                    Signature signatureEngine = Signature.getInstance("SHA256withRSA", pkcs11Provider);
                    signatureEngine.initSign(switchPrivateKey);
                    signatureEngine.update(rawIsoMessage);
                    byte[] hardwareSignature = signatureEngine.sign();

                    System.out.println("    [+] Hardware Module Signature Computed: " + hardwareSignature.length + " bytes (RSA-2048)");

                    // 6. Send ISO 8583 0210 Authorization Response
                    String responsePayload = "0210_AUTH_OK_SIGLEN_" + hardwareSignature.length + "\n";
                    out.write(responsePayload.getBytes());
                    out.flush();
                    System.out.println("    [<] 0210 Authorization Response dispatched to terminal.\n");
                }
                clientSocket.close();
            }

        } catch (Exception e) {
            System.err.println("[-] Gateway Execution Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
