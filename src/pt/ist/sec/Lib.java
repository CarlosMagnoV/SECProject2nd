package pt.ist.sec;
import sun.text.normalizer.UTF16;

import javax.crypto.*;
import java.io.*;
import java.math.BigInteger;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.Timestamp;
import java.security.cert.X509Certificate;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.nio.charset.StandardCharsets;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.X509EncodedKeySpec;
import java.sql.*;
import java.util.ArrayList;
import java.util.Arrays;

import static java.lang.System.exit;
import static java.util.Arrays.copyOfRange;
import static javax.xml.bind.DatatypeConverter.printBase64Binary;
import static javax.xml.bind.DatatypeConverter.printHexBinary;

public class Lib implements ClientInterface{
    public PublicKey ClientPublicKey;
    public Key ClientPrivateKey;
    private SecretKey aesKey;
    private PublicKey ServerPublicKey;
    private SecretKey SessionKey;
    public ArrayList<byte[]> usedNonces;
    private ArrayList<byte[]> serverSentNonces = new ArrayList<>();
    private java.sql.Timestamp nonceValue;

    private static ClientInterface client;
    private static ServerInterface stub;

    private static String certFile = System.getProperty("user.dir") + "\\clientData\\Server.cer";
    private static String aesFile = System.getProperty("user.dir") + "\\clientData\\aesFile";
    private static String pastNonce = System.getProperty("user.dir") + "\\data\\nonce.txt";
    public Lib lib = this;
    public int myId;

    public Lib(int port) throws Exception{
        client = (ClientInterface)this;

        try {
            System.out.println("connecting . . .");

            Registry registry = null;
             //String ip = InetAddress.getLocalHost().getHostAddress();
                registry = LocateRegistry.getRegistry(port);

                //registry = LocateRegistry.getRegistry(1000);


            UnicastRemoteObject.exportObject(client, 0);
            stub = (ServerInterface) registry.lookup(""+port);

            File file = new File(pastNonce);

            if (!file.exists()) {
                file.createNewFile();
                return;
            }

            FileReader fileReader = new FileReader(file);
            BufferedReader br = new BufferedReader(fileReader);

            String line = "";


            if(stub.checkConnection()==1){
                System.err.println("Connected to the server");
            }
            else{
                System.err.println("Client connection error");
            }
        }
        catch(Exception e){
            System.err.println("Client connection error: " + e.toString());
            exit(0);
        }
    }

    //Função para correr para verificar replay attack
    //Falta adicionar o nonce nas mensagens do server, e por consequencia, falta isto tambem
    private boolean checkNonce(java.sql.Timestamp nonce){

        try {

            if(!(new java.sql.Timestamp(System.currentTimeMillis())).before(nonceValue)){
                setNonce(nonce);
                return true;
            }


        }
        catch(Exception e){
            e.printStackTrace();
        }
        return false;

    }

    private void setNonce(java.sql.Timestamp nonce){
        this.nonceValue = nonce;
    }

    public byte[] getNonce(){
        try {
            return EncryptCommunication(("" + new java.sql.Timestamp(System.currentTimeMillis())).getBytes());
        }
        catch(Exception e){}
        return null;
    }

    public java.sql.Timestamp createNonce(){

        nonceValue = new java.sql.Timestamp(System.currentTimeMillis());

        return nonceValue;
    }


    public void init(KeyStore ks, String keyPass, String alias) throws Exception
    {

        usedNonces = new ArrayList<>();
        Certificate cert = ks.getCertificate(alias);
        ClientPublicKey = cert.getPublicKey();
        ClientPrivateKey = ks.getKey(alias,keyPass.toCharArray());

        FileInputStream fin = new FileInputStream(certFile);
        CertificateFactory f = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate)f.generateCertificate(fin);
        ServerPublicKey = certificate.getPublicKey();



        File file = new File(aesFile);

        if(!file.exists()){
            file.createNewFile();
            FileOutputStream output = new FileOutputStream(file, true);
            output.write(EncryptionAssymmetric(symmetricKeyGen().getEncoded(), ClientPublicKey));
            output.close();
        }
        else{
            Path path = Paths.get(aesFile);

            byte[] keyBytes = DecryptionAssymmetric(Files.readAllBytes(path));
            aesKey = new SecretKeySpec(keyBytes, "AES");
        }

        registerUser();
    }

    public void setSessionKey(byte[] SessKey, byte[] keySignature, byte[] id, byte[] idSignature)throws Exception{

        byte[] SessBytes = DecryptionAssymmetric(SessKey);
        byte[] clearId = DecryptionAssymmetric(id);
        //String strID = new String(clearId);

        if(verifyDigitalSignature(keySignature, SessBytes, ServerPublicKey) && verifyDigitalSignature(idSignature, clearId, ServerPublicKey)) {
            this.SessionKey = new SecretKeySpec(SessBytes, "AES");
            this.myId = Integer.parseInt(new String(clearId));
        }

    }


    public void close()
    {
        Runtime.getRuntime().exit(1);
    }

    public void registerUser() throws Exception
    {
        stub.register(ClientPublicKey.getEncoded(),(ClientInterface)this);
        System.out.println("I am ID: "+ myId);


    }


    public void save_password(byte[] message) throws Exception {

        byte[] cipher = EncryptCommunication(message);
        byte[] signature = makeDigitalSignature(cipher, (PrivateKey)ClientPrivateKey);
        nonceValue = new java.sql.Timestamp(System.currentTimeMillis());
        byte[] nonce = ("" + nonceValue).getBytes();


        byte[] signatureNonce = makeDigitalSignature(nonce, (PrivateKey)ClientPrivateKey);


        stub.put(cipher, signature, EncryptCommunication(nonce), signatureNonce, myId);
    }


    public byte[] retrieve_password(byte[] message) throws Exception {



        byte[] cipher = EncryptCommunication(message);
        byte[] signature = makeDigitalSignature(cipher, (PrivateKey)ClientPrivateKey);

        nonceValue = new java.sql.Timestamp(System.currentTimeMillis());
        byte[] nonce = ("" + nonceValue).getBytes();

        byte[] signatureNonce = makeDigitalSignature(nonce, (PrivateKey)ClientPrivateKey);


        byte[] helper = null;

        helper = stub.get(cipher, signature, EncryptCommunication(nonce), signatureNonce, myId);

        if(helper == null){
            nonceValue = new java.sql.Timestamp(System.currentTimeMillis());
        }

        //return DecryptionSymmetric(DecryptCommunication(helper));
        byte[] answer = DecryptCommunication(helper);       //password + nonce

        if(!checkNonce(java.sql.Timestamp.valueOf("" + new String(copyOfRange(answer, (16), answer.length), "ASCII")))){
            return null;
        }

        byte[] digitalSignature = DecryptCommunication(stub.getDigitalSignature(EncryptCommunication(ClientPublicKey.getEncoded())));

        if(!verifyDigitalSignature(digitalSignature, answer, ServerPublicKey)){
            return null;
        }

        return DecryptionSymmetric(copyOfRange(answer, 0 , (answer.length - (answer.length - 16))));


    }

    private SecretKey symmetricKeyGen() throws Exception{

        // Generate AES key
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(128); // initialize the key size
        aesKey = keygen.generateKey();
        return aesKey;

    }

    public byte[] EncryptionSymmetric(String plaintext) throws Exception{

        // Initialize cipher object
        Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] cleartext = plaintext.getBytes();

        // Encrypt the cleartext
        byte[] ciphertext = aesCipher.doFinal(cleartext);

        return ciphertext;

    }

    public byte[] DecryptionSymmetric(byte[] ciphertext) throws Exception{


        // Initialize cipher object
        Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey);

        byte[] cleartext = aesCipher.doFinal(ciphertext);
        return cleartext;

    }


    public byte[] EncryptCommunication(byte[] plaintext) throws Exception{
        try
        {
            // Initialize cipher object
            Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            aesCipher.init(Cipher.ENCRYPT_MODE, SessionKey);

            // Encrypt the cleartext
            byte[] ciphertext = aesCipher.doFinal(plaintext);
            return ciphertext;
        }
        catch(Exception e)
        {
            System.out.println(e + " - error in ciphering communication");
        }
        byte[] error = null;
        return error;

    }

    public byte[] DecryptCommunication(byte[] ciphertext) throws Exception{

        // Initialize cipher object
        Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        aesCipher.init(Cipher.DECRYPT_MODE, SessionKey);

        // Encrypt the cleartext
        byte[] plaintext = aesCipher.doFinal(ciphertext);

        return plaintext;

    }

    public byte[] EncryptionAssymmetric(byte[] plaintext, PublicKey key) throws Exception{

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherData = cipher.doFinal(plaintext);

        return cipherData;
    }

    public byte[] DecryptionAssymmetric(byte[] ciphertext) throws Exception {

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, ClientPrivateKey);
        byte[] cipherData = cipher.doFinal(ciphertext);

        return cipherData;
    }


    public static byte[] makeDigitalSignature(byte[] bytes, PrivateKey privateKey) throws Exception {

        // get a signature object using the SHA-1 and RSA combo
        // and sign the plaintext with the private key
        Signature sig = Signature.getInstance("SHA256WithRSA");
        sig.initSign(privateKey);
        sig.update(bytes);
        byte[] signature = sig.sign();

        return signature;
    }



    //Verifies that the data received is from the expected entity with the that entity's public key
    public static boolean verifyDigitalSignature(byte[] signature, byte[] message, PublicKey publicKeyServer) throws Exception {

        // verify the signature with the public key
        Signature sig = Signature.getInstance("SHA256WithRSA");

        sig.initVerify(publicKeyServer);

        sig.update(message);
        try {
            return sig.verify(signature);
        } catch (SignatureException se) {
            System.out.println("Caught exception while verifying " + se);
            return false;
        }
    }


    public void applyPaddSend (PublicKey publicKey, String domain, String username, String password, int maxSize) throws Exception
    {
        int tamD = maxSize - domain.length();
        int tamU = maxSize - username.length();
        int tamP = maxSize - password.length();

        for (int i = 0; i < tamD; i++ )
        {
            domain += "-";
        }
        if(new Integer(tamD).toString().length() == 1)
        {
            domain += "0" + tamD;
        }
        else
        {
            domain += tamD;
        }
        for (int i = 0; i < tamU; i++ )
        {
            username += "-";
        }
        if(new Integer(tamU).toString().length() == 1)
        {
            username += "0" + tamU;
        }
        else
        {
            username += tamU;
        }

       ArrayList<byte[]> list = new ArrayList<byte[]>();
        list.add(publicKey.getEncoded());
        list.add(domain.getBytes());
        list.add(username.getBytes());
        list.add(EncryptionSymmetric(password));
        //list.add(password.getBytes());


        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (byte[] element : list) {
            //out.write(element);
            baos.write(element);
        }
        byte[] bytes = baos.toByteArray();
        save_password(bytes);

    }

    public byte[] applyPaddRet (PublicKey publicKey, String domain, String username, int maxSize) throws Exception
    {
        int tamD = maxSize - domain.length();
        int tamU = maxSize - username.length();

        for (int i = 0; i < tamD; i++ )
        {
            domain += "-";
        }
        if(new Integer(tamD).toString().length() == 1)
        {
            domain += "0" + tamD;
        }
        else
        {
            domain += tamD;
        }
        for (int i = 0; i < tamU; i++ )
        {
            username += "-";
        }
        if(new Integer(tamU).toString().length() == 1)
        {
            username += "0" + tamU;
        }
        else
        {
            username += tamU;
        }

        ArrayList<byte[]> list = new ArrayList<byte[]>();
        list.add(publicKey.getEncoded());
        list.add(domain.getBytes());
        list.add(username.getBytes());

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (byte[] element : list) {
            //out.write(element);
            baos.write(element);
        }
        byte[] bytes = baos.toByteArray();
        return retrieve_password(bytes);

    }



}