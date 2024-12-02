import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.sql.*;
import java.util.Base64;
import java.util.Random;

public class practica1 {
    public static void main(String[] args) throws Exception {
//        ex1();
//        ex2();
//        ex3();
//        ex4();
//        ex5();
//        ex6();
//        ex7();
//        ex8();
//        KeyPair claus = generateAsymmetricKeyPair(512);
//        String text = "a";
//        ex9(text, claus);
//        ex10(text, claus);
//        ex11();
//        ex13();
        ex14();



    }

    public static void ex1 (){
        //Generar Clau
        SecretKey sKey = generateKey("DES", 56);
        //Canvi a base64 i passar-la a String
        String encodedKey = Base64.getEncoder().encodeToString(sKey.getEncoded());

        System.out.println("La clau " + sKey.getAlgorithm() + " és: " + encodedKey);
    }

    public static void ex2 (){//ex.2
    String fullName = "DavidAlcarazEstrague";
    byte[] hash = hashGenerator(fullName, "SHA-512");
    String hashedName =  hashToHexadecimal(hash);
    System.out.println("El hash del nom "+fullName+" és: "+hashedName);
    }

    public static void ex3 (){
        String text = "Hello World";
        byte[] hash = hashGenerator(text, "SHA-256");
        SecretKey aesKey = new SecretKeySpec(hash,"AES");
        System.out.println(hashToHexadecimal(aesKey.getEncoded()));


    }

    public static void ex4 (){
        String fullName = "DavidAlcarazEstrague";
        byte[] salt = generateSalt(16);
        byte[] hash = hashGenerator(fullName, "SHA-512", salt);
        String hashedName =  hashToHexadecimal(hash);

        System.out.println("El hash del nom " + fullName + " amb salt és: " + hashedName);
        System.out.println("El salt utilitzat (en hexadecimal) és: " + hashToHexadecimal(salt));
    }

    public static void ex5 (){
        String user = "laura";
        String password = "1a3e";
        Connection con = getConnection();
        createUserAndPassword(con, user, password);
        closeConnection(con);
    }

    public static void ex6 (){
        String user = "laura";
        String password = "1a3e";
        Connection con = getConnection();
        checkUserAndPassword(con, user, password);
        closeConnection(con);
    }

    public static void ex7 (){
        KeyPair claus = generateAsymmetricKeyPair(512);
        PrivateKey privateKey = claus.getPrivate();
        PublicKey publicKey = claus.getPublic();
        System.out.println("La clau privada és: " + Base64.getEncoder().encodeToString(privateKey.getEncoded()));
        System.out.println("La clau pública és: " + Base64.getEncoder().encodeToString(publicKey.getEncoded()));

    }

    public static void ex8 (){
        generateAsymmetricKeyPair(512);
    }

    public static void ex9 (String text, KeyPair claus){
        encrypt(text,claus );
    }

    public static void ex10 (String text, KeyPair claus){
        encryptHash(text,claus );
    }

    public static void ex11 (){
        decrypt();

    }

    public static void ex13 () throws UnrecoverableEntryException, CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
        showSecretKey();
    }
    public static void ex14 () throws Exception {
        String keystoreFile = "mykeystore.jks";
        String keystorePassword = "mypassword";
        String alias = "myaeskey2";
        // Crear una clau simètrica i emmagatzemar-la al keystore
        createAndStoreSymmetricKey(keystoreFile, keystorePassword, alias);

        // Mostrar la clau simètrica des del keystore
        showSecretKey(keystoreFile, keystorePassword, alias);

    }

    //METODE PER GENERAR CLAU
    public static SecretKey generateKey(String algorithm, int keysize) {
        SecretKey sKey = null;
        try{
            KeyGenerator kgen = KeyGenerator.getInstance(algorithm);
            kgen.init(keysize);
            sKey = kgen.generateKey();
        }catch (NoSuchAlgorithmException e){
            System.out.println("No se ha podido generar el SecretKey"+e.getMessage());
        }
        return sKey;
    }

    //METODE PER GENERAR HASH
    public static byte[] hashGenerator (String word, String algorithm){
        try{
            byte[] data = word.getBytes();
            MessageDigest md = MessageDigest.getInstance(algorithm);
            byte[] hash = md.digest(data);
            return hash;

        } catch (Exception e){
            System.out.println("No s'ha pogut hashar "+e.getMessage());
        }
        return new byte[0];
    }

    //METODE PER CONVERTIR HASH A HEXADECIMAL
    public static String hashToHexadecimal (byte[] hash){
        StringBuilder hex = new StringBuilder();
        for (byte b : hash) {
            String a = Integer.toHexString(b & 0xFF); //%02X
            if (a.length() == 1) hex.append('0');
            hex.append(a);
        }
        return hex.toString();
    }

    //METODE PER GENERAR HASH AMB SAL
    public static byte[] hashGenerator (String word, String algorithm, byte[] sal){
        try{
            MessageDigest md = MessageDigest.getInstance(algorithm);
            md.update(sal);

            byte[] hash = md.digest(word.getBytes());
            return hash;

        } catch (Exception e){
            System.out.println("No s'ha pogut hashar "+e.getMessage());
        }
        return new byte[0];
    }

    //METODE PER GENERAR SAL UTILITZANT SecureRandom
    public static byte[] generateSalt(int length) {
        byte[] salt = new byte[length];
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(salt);
        return salt;
    }

    //METODE PER OBTENIR CONNEXIÓ A LA BASE DE DADES
    public static Connection getConnection(){
        Connection con = null;
        String url = "jdbc:mysql://localhost:3306/uf1criptodavidalcaraz";
        String user = "root";
        String password = "1234";
        try {
            con = DriverManager.getConnection(url, user, password);
            if (!con.isClosed()) System.out.println("Connexió establerta");
        }catch (SQLException e){
            System.out.println("No s'ha pogut connectar a la base de dades "+e.getMessage());
        }
        return con;
    }

    //METODE PER TANCAR CONNEXIÓ A LA BASE DE DADES
    public static void closeConnection(Connection con){
        try {
            con.close();
            if (!con.isClosed()) System.out.println("Connexió tancada");
        } catch (SQLException e) {
            System.out.println("No s'ha pogut tancar la connexió "+e.getMessage());
        }
    }

    //METODE PER CREAR USUARI A LA BASE DE DADES
    public static void createUserAndPassword(Connection con, String user, String password){
        //Crear Sal
        Random random = new Random();
        int randomInt = random.nextInt(100);
        String salHexa = Integer.toHexString(randomInt);
        //Crear password amb sal
        String salPassword = salHexa + password;
        //Crear usuari a la bbdd
        try {
            PreparedStatement ps = con.prepareStatement("INSERT INTO usuaris (user, password, sal, pass_hash) VALUES (?, ?, ?, ?)");
            ps.setString(1, user);
            ps.setString(2, password);
            ps.setString(3, salHexa);
            ps.setString(4, hashToHexadecimal(hashGenerator(salPassword, "SHA-512")));
            ps.executeUpdate();
            ps.close();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    //METODE PER VERIFICAR USUARI A LA BASE DE DADES
    public static void checkUserAndPassword(Connection con, String user, String password) {

        try {

            PreparedStatement ps = con.prepareStatement("SELECT * FROM usuaris WHERE user = ? AND password = ?");
            ps.setString(1, user);
            ps.setString(2, password);
            ResultSet rs = ps.executeQuery();
            rs.next();

            String salBBDD = rs.getString(3);
            String passHashBBDD = rs.getString(4);

            String salPassword = salBBDD + password;
            if (hashToHexadecimal(hashGenerator(salPassword, "SHA-512")).equals(passHashBBDD)) {
                System.out.println("Usuari: " + user + " amb password: " + password + " ha estat identificat");
            } else {
                System.out.println("Usuari: " + user + " amb password: " + password + " no ha estat identificat");
            }
            ps.close();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    //METODE PER CREAR CLAUS ASIMETRIQUES
    public static KeyPair generateAsymmetricKeyPair(int len){
        KeyPair keys = null;
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(len);
            keys = keyGen.genKeyPair();

        } catch (NoSuchAlgorithmException e) {
            System.out.println("No s'ha pogut generar la clau asimetrica "+e.getMessage());
        }
        return keys;
    }

    //METODE PER ENCRIPTAR TEXT
    public static void encrypt(String text, KeyPair claus){
        try{


            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, claus.getPrivate());
            byte[] encrypted = cipher.doFinal(text.getBytes());

            String encryptedString = Base64.getEncoder().encodeToString(encrypted);
            String encryptedHex = hashToHexadecimal(encrypted);

            System.out.println("El text encriptat és: "+new String(encrypted));
            System.out.println("encryptedString: "+encryptedString);
            System.out.println("encryptedHex: "+encryptedHex);


        }catch (Exception e){
            System.out.println("No s'ha pogut encriptar "+e.getMessage());
        }

    }

    //METODE PER ENCRIPTAR HASH
    public static byte[] encryptHash(String text, KeyPair claus){
        try{
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(text.getBytes());

            String hex = hashToHexadecimal(hash);
            System.out.println("El hash del text és: "+hex);

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, claus.getPrivate());
            byte[] encrypted = cipher.doFinal(hex.getBytes());

            String encryptedString = Base64.getEncoder().encodeToString(encrypted);
            String encryptedHex = hashToHexadecimal(encrypted);

            System.out.println("El text encriptat és: "+new String(encrypted));
            System.out.println("encryptedString: "+encryptedString);
            System.out.println("encryptedHex: "+encryptedHex);
            return encrypted;


        }catch (Exception e){
            System.out.println("No s'ha pogut encriptar "+e.getMessage());
            return null;
        }

    }

    //METODE PER DESENCRIPTAR
    public static void decrypt() {
        KeyPair keys = generateAsymmetricKeyPair(512);
        byte[] infoEncrypt = encryptHash("ah", keys);
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, keys.getPublic());
            byte[] decrypted = cipher.doFinal(infoEncrypt);

            System.out.println("Dades desenctiptades: " + new String(decrypted));
        } catch(Exception e) {
            System.out.println("No s'ha pogut desencriptar "+e.getMessage());
        }
    }

    //METODE PER MOSTRAR CLAU SIMÈTRICA
    public static void showSecretKey() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableEntryException {
        FileInputStream fis = new FileInputStream("mykeystore.jks");
        KeyStore keystore = KeyStore.getInstance("JCEKS");
        keystore.load(fis, "mypassword".toCharArray());

        KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keystore.getEntry("myaeskey",
                new KeyStore.PasswordProtection("mypassword".toCharArray()));
        SecretKey secretKey = secretKeyEntry.getSecretKey();

        System.out.println("Clau simètrica (en hexadecimal): " + hashToHexadecimal(secretKey.getEncoded()));
    }

    //METODE PER CREAR UNA CLAU SIMÈTRICA I EMMAGATZEMAR-LA AL KEYSTORE
    public static void createAndStoreSymmetricKey(String keystoreFile, String keystorePassword, String alias) throws Exception {
        SecretKey secretKey = generateKey("AES", 256);

        KeyStore keystore = KeyStore.getInstance("JCEKS");
        try (FileInputStream fis = new FileInputStream(keystoreFile)) {
            keystore.load(fis, keystorePassword.toCharArray());
        } catch (Exception e) {
            keystore.load(null, keystorePassword.toCharArray());
        }
        KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);
        KeyStore.PasswordProtection keyPassword = new KeyStore.PasswordProtection(keystorePassword.toCharArray());
        keystore.setEntry(alias, secretKeyEntry, keyPassword);

        try (FileOutputStream fos = new FileOutputStream(keystoreFile)) {
            keystore.store(fos, keystorePassword.toCharArray());
        }
        System.out.println("Clau simètrica generada i emmagatzemada en el keystore.");
    }

    //METODE PER MOSTRAR CLAU SIMÈTRICA AMB PARAMETRES
    public static void showSecretKey(String keystoreFile, String keystorePassword, String alias) throws Exception {
        KeyStore keystore = KeyStore.getInstance("JCEKS");
        try (FileInputStream fis = new FileInputStream(keystoreFile)) {
            keystore.load(fis, keystorePassword.toCharArray());
        }
        KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keystore.getEntry(alias,
                new KeyStore.PasswordProtection(keystorePassword.toCharArray()));
        SecretKey secretKey = secretKeyEntry.getSecretKey();

        String hexKey = hashToHexadecimal(secretKey.getEncoded());
        System.out.println("Clau simètrica (en hexadecimal): " + hexKey);

    }





}
