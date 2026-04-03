import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Scanner;

class Vulnerable {
    
    // Hardcoded Secret Rule (CWE-798)
    private static final String API_KEY = "super_secret_api_key_12345";
    
    public static void main(String[] args) {
        System.out.println("Starting VAIS test");
        
        if (args.length > 0) {
            runCommand(args[0]);
        }
        hashData("test_data");
    }

    private static void runCommand(String cmd) {
        try {
            // Command Injection via Runtime.exec (CWE-78)
            Runtime.getRuntime().exec("ping -c 4 " + cmd);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void hashData(String data) {
        try {
            // Weak Crypto (CWE-327)
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(data.getBytes());
            System.out.println(new String(hash));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
