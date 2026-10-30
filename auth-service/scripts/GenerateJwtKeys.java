import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.util.Base64;

/** Run with JDK 21: java scripts/GenerateJwtKeys.java secrets */
class GenerateJwtKeys {
    public static void main(String[] args) throws Exception {
        Path directory = Path.of(args.length == 0 ? "secrets" : args[0]);
        Path privateFile = directory.resolve("private.pem");
        Path publicFile = directory.resolve("public.pem");
        if (Files.exists(privateFile) || Files.exists(publicFile)) {
            throw new IllegalStateException("Key files already exist; refusing to overwrite");
        }
        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        var pair = generator.generateKeyPair();
        Files.createDirectories(directory);
        Files.writeString(privateFile, pem("PRIVATE KEY", pair.getPrivate().getEncoded()),
                StandardCharsets.US_ASCII, java.nio.file.StandardOpenOption.CREATE_NEW);
        Files.writeString(publicFile, pem("PUBLIC KEY", pair.getPublic().getEncoded()),
                StandardCharsets.US_ASCII, java.nio.file.StandardOpenOption.CREATE_NEW);
        System.out.println("Created RSA key pair in " + directory.toAbsolutePath());
    }

    private static String pem(String label, byte[] bytes) {
        return "-----BEGIN " + label + "-----\n"
                + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(bytes)
                + "\n-----END " + label + "-----\n";
    }
}
