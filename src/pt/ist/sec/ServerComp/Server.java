package pt.ist.sec;


import javax.crypto.*;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.beans.Expression;
import java.io.*;

import java.math.BigInteger;
import java.net.InetAddress;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.rmi.Remote;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.rmi.RemoteException;

import java.security.*;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Arrays;

import static java.util.Arrays.copyOfRange;
import static javax.xml.bind.DatatypeConverter.*;

public class Server implements ServerInterface{

    private static String DataFileLoc = System.getProperty("user.dir") + "/data/storage.txt";
    private static String LogFile = System.getProperty("user.dir") + "/log/log.txt";
    private static String RegFile = System.getProperty("user.dir") + "/data/register.txt";
    private static String byteFile = System.getProperty("user.dir") + "/data/byteFile";

    private static String certFile = System.getProperty("user.dir") + "/clientData/Server.cer";
    private static String KeyStoreFile = System.getProperty("user.dir") + "/clientData/KeyStore.jks";

    private static PublicKey ServerPublicKey;
    private static Key ServerPrivateKey;

    private KeyAgreement bobKeyAgree;

    private static ArrayList<ClientClass> clientList = new ArrayList<>();
    private static ArrayList<ClientInterface> clientNonces;
    private static ArrayList<byte[]> usedNonces = new ArrayList<>();;

    public Server(){

    }

    public static void main(String[] args) {

        clientNonces = new ArrayList<>();
        try {

            System.out.println("connecting . . .");
            Server obj = new Server();
            ServerInterface stub = (ServerInterface) UnicastRemoteObject.exportObject(obj, 0);

            String ip = InetAddress.getLocalHost().getHostAddress();

            System.setProperty("java.rmi.server.hostname", ip);
            Registry registry = LocateRegistry.createRegistry(Integer.parseInt(args[0]));
            registry.bind("Server", stub);

            //FileInputStream fin = new FileInputStream(certFile);
            //CertificateFactory f = CertificateFactory.getInstance("X.509");
            //X509Certificate certificate = (X509Certificate)f.generateCertificate(fin);
            //ServerPublicKey = certificate.getPublicKey();

            FileInputStream fis = new FileInputStream(KeyStoreFile);
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(fis, "changeit".toCharArray()); // esta password é a pass do keystore

            java.security.cert.Certificate cert = keystore.getCertificate("client-alias");
            ServerPublicKey = cert.getPublicKey();
            ServerPrivateKey = keystore.getKey("client-alias","changeit".toCharArray());


            System.err.println("Server ready. Connected in: " + ip);
        } catch (Exception e) {
            System.err.println("Server connection error: " + e.toString());
            e.printStackTrace();
        }

        fileCreation(DataFileLoc);
        fileCreation(LogFile);
        fileCreation(RegFile);
        fileCreation(byteFile);


        while(true);
    }


    public static void fileCreation(String path) {
        File file = new File(path);

        try {
            if (!file.exists()) {
                file.createNewFile();
            }
        }
        catch(IOException e) {
            System.out.println("File problem: " + e);
            e.printStackTrace();
        }
    }

    private static void writeByteCode(byte[] code, int index){

        try {
            if(index >= 0) {
                //FileOutputStream output = new FileOutputStream(byteFile);
                File output = new File(byteFile);
                RandomAccessFile raf = new RandomAccessFile(output, "rw");
                raf.seek(index*16);
                raf.write(code);
                raf.close();
            }
            else{
                FileOutputStream output = new FileOutputStream(byteFile, true);
                output.write(code);
                output.close();
            }
        }
        catch(IOException e){
            System.out.println("Error writing password in file: " + e);
            e.printStackTrace();
        }
    }

    private byte[] readByteCode(int index){

        try {

            Path path = Paths.get(byteFile);

            byte[] byteArray = copyOfRange(Files.readAllBytes(path),index*16,(index*16)+16);

            return byteArray;
        }
        catch(IOException e){
            System.out.println("Error reading password from file: " + e);
            e.printStackTrace();
            return null;
        }
    }



    public void storeData(PublicKey pubKey, byte[] domain, byte[] username, byte[] password){

        try {
            String concateneted = "";
            File file = new File(DataFileLoc);

            FileWriter fileWriter = new FileWriter(file.getAbsoluteFile(), true);
            BufferedWriter bw = new BufferedWriter(fileWriter);

            concateneted += printBase64Binary(domain) + " " +
            printBase64Binary(username) + " " +
            printBase64Binary(password);

            bw.write(concateneted);
            bw.close();
        }
        catch(IOException e){
            System.out.println("File Writing Problem: " + e );
        }
    }

    public byte[] getData(PublicKey pubKey, byte[] domain, byte[] username) //falta chave publica
    {
        try (BufferedReader br = new BufferedReader(new FileReader(DataFileLoc)))
        {
            String concateneted = "";
            concateneted += printBase64Binary(domain) + " " +
                    printBase64Binary(username) + " ";
            String line;
            while ((line = br.readLine()) != null)
            {
               if(line.equals(concateneted))
               {
                   String[] parts = line.split(" ");
                   return parseBase64Binary(parts[3]);
               }
            }
        }
        catch(Exception e)
        {
            System.out.println("Error retrieving data" + e);

        }
        byte[] missing = parseBase64Binary("");
        return missing;
    }


    public byte[] EncryptCommunication(byte[] plaintext, SecretKey SessKey) throws Exception{

        // Initialize cipher object

        Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        aesCipher.init(Cipher.ENCRYPT_MODE, SessKey);

        // Encrypt the cleartext
        byte[] ciphertext = aesCipher.doFinal(plaintext);

        return ciphertext;

    }

    public byte[] DecryptCommunication(byte[] ciphertext, SecretKey SessKey) throws Exception{

        // Initialize cipher object
        Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        aesCipher.init(Cipher.DECRYPT_MODE, SessKey);

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

    private byte[] DecryptionAssymmetric(byte[] ciphertext, PublicKey key) throws Exception {

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] cipherData = cipher.doFinal(ciphertext);

        return cipherData;
    }
    public int checkConnection(){
        return 1;
    }

    public void put(byte[] message, byte[] signature, byte[] nonce, byte[] signatureNonce) throws Exception{


        byte[] pKeyBytes = null;
        byte[] restMsg = null;
        byte[] decryptNonce = null;
            ClientClass client = clientList.get(0);
            for(ClientClass element: clientList) {

                try {
                    byte[] Bmsg = DecryptCommunication(message, element.getSessionKey());
                    pKeyBytes = copyOfRange(Bmsg,0,294); // parte da chave publica
                    restMsg = copyOfRange(Bmsg, 294, Bmsg.length); // resto dos argumentos
                    decryptNonce = DecryptCommunication(nonce, element.getSessionKey());
                    client = element;

                }
                catch(Throwable e){

                }
            }
            //if(pKeyBytes == null){}

        PublicKey ClientPublicKey = null;

            ClientPublicKey =
                    KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pKeyBytes));

            if(!verifyDigitalSignature(signature, message, ClientPublicKey)&&!verifyDigitalSignature(signatureNonce, decryptNonce, ClientPublicKey)){ //If true, signature checks
                return;
            }


            if (!client.checkNonce(decryptNonce)) {
                return;
            }
            String dom = new String(copyOfRange(restMsg, 0, 30), "ASCII");
            String usr = new String(copyOfRange(restMsg, 30, 60), "ASCII");
            //String pass = new String(copyOfRange(restMsg, 60, restMsg.length), "ASCII");
            byte[] pass = copyOfRange(restMsg, 60, restMsg.length);
            String domFinal = rmPadd(dom.toCharArray());
            String usrFinal = rmPadd(usr.toCharArray());


            String pKeyString = printBase64Binary(pKeyBytes);
            String domainString = domFinal;
            String usernameString = usrFinal;
            //String passwordString = pass;

            String elements = domainString + " " + usernameString;


            File file = new File(DataFileLoc);
            FileReader fileReader = new FileReader(file);
            BufferedReader br = new BufferedReader(fileReader);
            String line;
            Path path = Paths.get(DataFileLoc);

            Charset charset = Charset.forName("ISO-8859-1");

            List<String> lines = Files.readAllLines(path, charset);

            int i = 0;
            Boolean newData = true;
            while ((line = br.readLine()) != null) {
                if (line.contains(pKeyString)) {
                    line = br.readLine();
                    if (line.contains(domainString)) {
                        line = br.readLine();
                        if (line.contains(usernameString)) {
                            writeByteCode(pass, Integer.parseInt(br.readLine()));
                            newData = false;
                            break;
                        } else {
                            br.readLine();
                        }
                    } else {
                        br.readLine();
                        br.readLine();
                    }
                } else {
                    br.readLine();
                    br.readLine();
                    br.readLine();
                }
                i += 4;
            }
            if (newData) {
                //Files.write(Paths.get(DataFileLoc), ("\n"+pKeyString+" "+elements + " " + passwordString).getBytes(), StandardOpenOption.APPEND);
                Files.write(Paths.get(DataFileLoc),
                        (pKeyString + "\n" + domainString + "\n" + usernameString + "\n" + (getLastNumber()+1) + "\n").getBytes(),
                        StandardOpenOption.APPEND);
                writeByteCode(pass, -1);
            } else {
                Files.write(path, lines, charset);
            }

            br.close();
    }

    private int getLastNumber(){

        int number = -1;
        String line = "";

        try {
            File file = new File(DataFileLoc);
            FileReader fileReader = new FileReader(file);
            BufferedReader br = new BufferedReader(fileReader);

            while((line =br.readLine())!= null){
                for(int i = 0; i < 2; i++){
                    line = br.readLine();
                }
                number = Integer.parseInt(br.readLine());
            }

            return number;
        }
        catch(Exception e){
            e.printStackTrace();
            return number;      //No caso de não ter nenhum valor
        }



    }


    public static String rmPadd(char[] s)throws Exception
    {
        if(s[28] == '0')
        {
            char c = s[29];
            int x = Character.getNumericValue(c);
            char[] fin = copyOfRange(s,0, 28-x);
            return concatenate(fin);
        }
        else
        {
            char[] c = copyOfRange(s,28,30);
            int x = Integer.parseInt(new String(c));
            char[] fin = copyOfRange(s,0,28-x);
            return concatenate(fin);
        }

    }

    private static String concatenate (char[] c){
        String str = "";
        for(char a: c){
            str += a;
        }
        return str;
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
    public static boolean verifyDigitalSignature(byte[] signature, byte[] message, PublicKey publicKeyClient) throws Exception {

        // verify the signature with the public key
        Signature sig = Signature.getInstance("SHA256WithRSA");

        sig.initVerify(publicKeyClient);

        sig.update(message);
        try {
            return sig.verify(signature);
        } catch (SignatureException se) {
            System.out.println("Caught exception while verifying " + se);
            return false;
        }
    }

    public byte[] get( byte[] message, byte[] signature, byte[] nonce, byte[] signatureNonce){
        byte[] password = get2(message, signature, nonce, signatureNonce);
        ClientClass client = null;

        for(ClientClass element: clientList){

            try {
                DecryptCommunication(message, element.getSessionKey());
                client = element;
            }
            catch(Exception e){
            }

        }

        byte[] bytes = null;

        try {

            ArrayList<byte[]> list = new ArrayList<>();
            list.add(password);
            list.add(client.getNextNonce());




            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            for (byte[] element : list) {
                //out.write(element);
                baos.write(element);
            }
            bytes = baos.toByteArray();

            client.setSignature(makeDigitalSignature(bytes, (PrivateKey)ServerPrivateKey)); //Assina o plaintext

            return EncryptCommunication(bytes, client.getSessionKey());
        }
        catch(Exception e){
            e.printStackTrace();
        }

        return null;


    }

    public byte[] getDigitalSignature(byte[] PublicKey){

        ClientClass client = null;

        for(ClientClass element: clientList){

            try {
                DecryptCommunication(PublicKey, element.getSessionKey());
                client = element;
            }
            catch(Exception e){

            }

        }

        try {
            return EncryptCommunication(client.getLastSignature(), client.getSessionKey());
        }
        catch(Exception e){
            System.out.println("Error retrieving digital signature: " + e);
            return null;
        }
    }

    public byte[] createNonce(){
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[16];
        random.nextBytes(bytes);
        byte seed[] = random.generateSeed(16);

        while(usedNonces.contains(seed)){
            random.nextBytes(bytes);
            seed = random.generateSeed(16);
        }

        usedNonces.add(seed);

        return seed;
    }

    public byte[] get2( byte[] message, byte[] signature, byte[] nonce, byte[] signatureNonce){

        byte[] pKeyBytes = null;
        ClientClass client = clientList.get(0);
        byte[] restMsg = null;
        byte[] decryptNonce = null;
        for(ClientClass element: clientList) {



            try {
                byte[] Bmsg = DecryptCommunication(message, element.getSessionKey());
                pKeyBytes = copyOfRange(Bmsg,0,294); // parte da chave publica
                restMsg = copyOfRange(Bmsg, 294, Bmsg.length); // resto dos argumentos
                decryptNonce = DecryptCommunication(nonce, element.getSessionKey());
                client = element;

            }
            catch(Throwable e){

            }
        }
        if(pKeyBytes == null){return null;}

        PublicKey ClientPublicKey = null;
        try {
            ClientPublicKey =
                    KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pKeyBytes));

        if(!verifyDigitalSignature(signature, message, ClientPublicKey)&&!verifyDigitalSignature(signatureNonce, decryptNonce, ClientPublicKey)){ //If true, signature checks
            return null;
        }

        if(!client.checkNonce(decryptNonce)){
            return null;
        }

        }
        catch(Exception e){
            System.err.println("(Retrieve)Signature error: " + e.toString());
            e.printStackTrace();
        }

        try {
            String dom = new String(copyOfRange(restMsg, 0, 30), "ASCII");
            String usr = new String(copyOfRange(restMsg, 30, restMsg.length), "ASCII");
            String domFinal = rmPadd(dom.toCharArray());
            String usrFinal = rmPadd(usr.toCharArray());


            String pKeyString = printBase64Binary(pKeyBytes);
            String domainString = domFinal;
            String usernameString = usrFinal;

            //String elements = domainString+" "+usernameString;


            File file = new File(DataFileLoc);
            FileReader fileReader = new FileReader(file);
            BufferedReader br = new BufferedReader(fileReader);
            String line;
            Path path = Paths.get(DataFileLoc);

            Charset charset = Charset.forName("ISO-8859-1");

            List<String> lines = Files.readAllLines(path,charset);

            int i=0;
            Boolean newData = true;
            while((line = br.readLine()) != null){
                if(line.contains(pKeyString)){
                    line = br.readLine();
                    if (line.contains(domainString)) {
                        line = br.readLine();
                        if (line.contains(usernameString)){
                            line = br.readLine();
                            //System.out.println(line);
                            //System.out.println(parseBase64Binary(line));
                            return readByteCode(Integer.parseInt(line));
                        }
                        else{
                            br.readLine();
                        }
                    }
                    else{
                        br.readLine();
                        br.readLine();
                    }
                }
                else{
                    br.readLine();
                    br.readLine();
                    br.readLine();
                }
                i+=4;
            }

        }
        catch (Exception e){
            System.out.println("Error: Couldn't locate the file.");
            e.printStackTrace();
            return "noFile".getBytes();
        }





        //Area de teste, deu ok

        /*
        try {
            byte[] Msg = copyOfRange(restMsg, 0, 30);
            System.out.println("Domain: " + new String(Msg, "ASCII"));
            return EncryptCommunication(copyOfRange(Msg, 0, 30), client.getSessionKey());    //so para nao dar erro
        }
        catch(Exception e){}

        */
        return null;
    }


    public void register(byte[] pubKey, ClientInterface c) throws Exception{

        //Decifrar chave publica
        
        //decipheredPubK = DecryptionAssymmetric(pubKey,ServerPublicKey);
        byte[] decipheredPubK = pubKey;

        SecretKey SessKey = generateSession();
        //if(!alreadyRegistered(decipheredPubK, SessKey)){ // se o cliente já existir, alreadyRegistered faz update da sua chave de sessão
            addClient(decipheredPubK,SessKey);
        //}

        //pass the session key to client
        c.setSessionKey(EncryptionAssymmetric(SessKey.getEncoded(),
                KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decipheredPubK)))
                );

        PublicKey decipheredKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decipheredPubK));
        for(ClientClass client: clientList){
            if(client.getPublicKey().equals(decipheredKey) && client.getSessionKey().equals(SessKey)){
                int newNonce = Integer.parseInt(new String(DecryptCommunication(c.getNonce(), SessKey), "ASCII"));
                client.setNonce(newNonce);
            }
        }

        System.out.print("\nNew client: " + printBase64Binary(decipheredPubK));



    }

    private SecretKey generateSession()throws Exception {
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(128);
        return keygen.generateKey();

    }

    private void addClient(byte[] clientPublicKey, SecretKey sessionKey){
        try {
            clientList.add(new ClientClass(sessionKey, KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(clientPublicKey))));
        }catch(Exception e){
            System.out.println("Error adding client: "+ e);
        }
    }



    //Deste metodo, devemos fazer uma verificação sobre o valor retornado. se for null,
    // nao encontrou o client(a sua chave)na lista
    private SecretKey getSessionKey(PublicKey clientPublicKey){
        for(ClientClass element: clientList){
            if(element.getPublicKey().equals(clientPublicKey)){
                return element.getSessionKey();
            }
        }
        return null;
    }

    private boolean alreadyRegistered(byte[] publicKey, SecretKey newSessionKey){

        try {
            PublicKey pk = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKey));

            for (ClientClass element : clientList) {
                if (element.getPublicKey().equals(pk)) {
                    element.updateSessionKey(newSessionKey);
                    return true;
                }
            }
        }
        catch (Exception e){
            return false;
        }
        return false;
    }



   /* private byte[] addNonce(ClientInterface lib){
        clientNonces.add(lib);
        return lib.createNonce();
    }*/



    //49 - nova lista de elementos do tipo ClientClass
    //427, 428. adicionar um client à lista
    //426, PubKey cifrada (mudou de PublicKey para byte[]
    //433, chave já vem em bytes
    //305 - 321
    //396 - 412
    //291, not global
    //49, adeus var global





}
