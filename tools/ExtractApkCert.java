import com.android.apksig.ApkVerifier;
import java.io.File;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;

///<file summary>: Prints the signing certificate (hex DER) Android would use for an APK at a given SDK level. Tries v3/v3.1 (signer whose SDK range covers the target), then v2, then v1. Called by OpenPortal.ps1 to read Messenger and host package signing certs. Usage: java -cp "<apksig.jar>;<dir>" ExtractApkCert <apk> [sdk]
public class ExtractApkCert {
    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
    static void emit(X509Certificate c) throws Exception {
        byte[] der = c.getEncoded();
        String sha = hex(MessageDigest.getInstance("SHA-256").digest(der));
        System.out.println("SHA256=" + sha + " DERLEN=" + der.length);
        System.out.println("DER=" + hex(der));
    }
    public static void main(String[] args) throws Exception {
        File apk = new File(args[0]);
        int sdk = args.length > 1 ? Integer.parseInt(args[1]) : 28;
        ApkVerifier.Result r = new ApkVerifier.Builder(apk).build().verify();

        for (ApkVerifier.Result.V3SchemeSignerInfo s : r.getV3SchemeSigners()) {
            if (s.getMinSdkVersion() <= sdk && sdk <= s.getMaxSdkVersion()) { emit(s.getCertificate()); return; }
        }
        for (ApkVerifier.Result.V3SchemeSignerInfo s : r.getV31SchemeSigners()) {
            if (s.getMinSdkVersion() <= sdk && sdk <= s.getMaxSdkVersion()) { emit(s.getCertificate()); return; }
        }
        for (ApkVerifier.Result.V2SchemeSignerInfo s : r.getV2SchemeSigners()) { emit(s.getCertificate()); return; }
        for (ApkVerifier.Result.V1SchemeSignerInfo s : r.getV1SchemeSigners()) { emit(s.getCertificate()); return; }
        System.err.println("NO_SIGNER_FOUND for " + args[0]);
        System.exit(2);
    }
}
