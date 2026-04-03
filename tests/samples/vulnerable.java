import java.sql.*;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ObjectInputStream;
import java.io.File;
import java.io.IOException;

public class VulnerableApp {

    public void vulnerableMethod1(String userInput) throws Exception {
        // SQL Injection via string concat
        Connection conn = DriverManager.getConnection("url", "user", "pass");
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + userInput + "'");
        PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE name = '" + userInput + "'");
    }

    public void vulnerableMethod2() throws Exception {
        // XXE via DocumentBuilderFactory
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.newDocumentBuilder();
    }

    public void vulnerableMethod3(java.io.InputStream in) throws Exception {
        // Unsafe Deserialization
        ObjectInputStream ois = new ObjectInputStream(in);
        ois.readObject();
    }

    public void vulnerableMethod4(String pathExt) {
        // Path Traversal
        File f = new File("/var/www/uploads/" + pathExt);
    }

    public void vulnerableMethod5(String cmd) throws IOException {
        // Command Injection
        Runtime.getRuntime().exec("ping " + cmd);
    }

    public void vulnerableMethod6() {
        // Hardcoded Credential
        String password = "SuperSecretPassword";
        String API_KEY = "1234567890abcdef1234567890abcdef";
        String privateKey = "BEGIN RSA PRIVATE KEY...";
    }

    public void vulnerableMethod7() {
        // Null Return Not Checked
        System.getProperty("missingProp").length();
    }

    public void vulnerableMethod8() throws Exception {
        // Hardcoded Crypto Key
        javax.crypto.spec.SecretKeySpec keySpec = new javax.crypto.spec.SecretKeySpec("mysecretkey12345".getBytes(), "AES");
    }

    public static void main(String[] args) throws Exception {
        VulnerableApp app = new VulnerableApp();
        if (args.length > 0) {
            app.vulnerableMethod1(args[0]);
            app.vulnerableMethod4(args[0]);
            app.vulnerableMethod5(args[0]);
        }
        app.vulnerableMethod2();
        app.vulnerableMethod6();
        app.vulnerableMethod7();
        app.vulnerableMethod8();
    }
}
