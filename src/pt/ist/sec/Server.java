package pt.ist.sec;


import com.sun.deploy.util.SessionState;

import javax.crypto.*;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.beans.Expression;
import java.io.*;

import java.math.BigInteger;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.channels.MulticastChannel;
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
import java.sql.Time;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Arrays;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;

import static java.util.Arrays.copyOfRange;
import static javax.xml.bind.DatatypeConverter.*;

public class Server implements ServerInterface{


    private static String DataFileLoc = System.getProperty("user.dir") + "/data/storage.txt";
    private static String LogFile = System.getProperty("user.dir") + "/log/log.txt";
    private static String SignFile = System.getProperty("user.dir") + "/log/signatures.txt";
    private static String RegFile = System.getProperty("user.dir") + "/data/register.txt";
    private static String byteFile = System.getProperty("user.dir") + "/data/byteFile";
    private static String certFile = System.getProperty("user.dir") + "/serverData/server.cer";

    public static String myPort;
    public static int myRank;
    public static Boolean amWriter = true;
    private static String KeyStoreFile = System.getProperty("user.dir") + "/serverData/KeyStore.jks";

    private static Key ServerPrivateKey;
    private static PublicKey ServerPublicKey;

    private static ArrayList<ClientClass> clientList = new ArrayList<>();
    public static ArrayList<Integer> portList = new ArrayList<>();
    public static SharedMemoryRegister reg;
    private static ServerInterface server;
    public static int totalId = 0;
    public static int myByzantine; //0, functional. 1, constant high timestamp.

    public Server(){

    }

    public static void main(String[] args) {


        try {
            myByzantine = Integer.parseInt(args[0]);
            if(myByzantine > 0) {
                System.out.println("I'm byzantine type " + myByzantine);
                if(myByzantine == 3){
                    System.out.println("After calling a write or read operation, i will crash!");
                }
            }
            reg = new SharedMemoryRegister();
            getMyPublic();
            System.out.println("connecting . . .");
            server = new Server();
            ServerInterface stub = (ServerInterface) UnicastRemoteObject.exportObject(server, 0);

           // String ip = InetAddress.getLocalHost().getHostAddress();

            myPort = args[1];
            myRank = Integer.parseInt(args[1]);
           //System.setProperty("java.rmi.server.hostname");
            Registry registry = LocateRegistry.createRegistry(Integer.parseInt(args[1]));
            registry.bind(args[1], stub);

            connectReplicas(args);

            FileInputStream fis = new FileInputStream(KeyStoreFile);
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(fis, "changeit".toCharArray()); // esta password é a pass do keystore

            java.security.cert.Certificate cert = keystore.getCertificate("server-alias");
            ServerPrivateKey = keystore.getKey("server-alias","changeit".toCharArray());




           System.err.println("Server ready. Connected in: " + args[1]);
        } catch (Exception e) {
            //e.printStackTrace();
            System.err.println("Couldn't connect to server. Please, restart.");
            System.out.println("Sugestion: try another server.");
        }

        fileCreation(DataFileLoc);
        fileCreation(LogFile);
        fileCreation(RegFile);
        fileCreation(byteFile);
        fileCreation(SignFile);

        try {
            while (true) Thread.sleep(Long.MAX_VALUE); //Sleep forever
        }
        catch(Exception e){
            e.printStackTrace();
        }
    }

    public static void getMyPublic()throws Exception{
        FileInputStream fin = new FileInputStream(certFile);
        CertificateFactory f = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate)f.generateCertificate(fin);
        ServerPublicKey = certificate.getPublicKey();
    }

    //Adds the propagated client to this replica
    public void registerDeliver(byte[] sessKey, PublicKey pKey, byte[] id, int port)throws Exception{
        byte[] clientSession = DecryptionAssymmetric(sessKey);
        SecretKey originalKey = new SecretKeySpec(clientSession,"AES");
        byte[] clearId = DecryptionAssymmetric(id);
        addClient(pKey.getEncoded(),originalKey, Integer.parseInt(new String(clearId)));
        System.out.println("Client added. ID: " + Integer.parseInt(new String(clearId)));
        reg.regDeliver(port);
    }

    public void deliverRegister(){
        Lock lock = new ReentrantLock();
        lock.lock();
        reg.finishRegister();
        lock.unlock();
    }

    public void writeReturn(byte[] message, byte[] signature, byte[] nonce, byte[] signatureNonce, Timestamp wts, int port, int id, byte[] writerSignature, int rid, int rank)throws Exception{
        amWriter = false;
        for(ClientClass c : clientList) {
            if(c.id == id) {
                c.myReg.bebDeliverWrite(message, signature, nonce, signatureNonce, wts, port, id, writerSignature,rid, rank);
            }
        }
    }

    public void ackReturn(byte[] message, byte[] signature, byte[] nonce, byte[] signatureNonce, Timestamp ts, int port, int id, int rid) throws Exception{
        for(ClientClass c : clientList) {
            if(c.id == id) {
                c.myReg.plDeliverWrite(message, signature, nonce, signatureNonce, ts, port, id,rid);
            }
        }
    }

    public void readReturn( byte[] message, byte[] signature, byte[] nonce, byte[] signatureNonce, int rid, int port, int id)throws Exception{
        for(ClientClass c : clientList) {
            if(c.id == id) {
                byte[] password = getPass(message,signature,nonce,signatureNonce, id, port);
                Timestamp ts = getTimetamp(message,signature,nonce,signatureNonce);
                byte[] serverSignature = getServerSignature(message);
                int wr = getRank(message, id);
                c.myReg.bebDeliverRead(password,ts,rid,port,id, serverSignature,message,signature,nonce,signatureNonce, wr);

            }
        }
    }

    public void sendValue(int rid, int id, byte[] password, Timestamp ts,byte[] serverSignature,byte[] message, byte[] signature, byte[] nonce, byte[] signatureNonce, int wr)throws Exception{
        for(ClientClass c : clientList) {
            if(c.id == id) {
                Lock lock = new ReentrantLock();
                lock.lock();
                c.myReg.plDeliverRead(rid, password, ts, serverSignature,message,signature,nonce,signatureNonce,id, wr);
                lock.unlock();
            }
        }
    }

    public byte[] DecryptionAssymmetric(byte[] ciphertext) throws Exception {

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, ServerPrivateKey);
        byte[] cipherData = cipher.doFinal(ciphertext);

        return cipherData;
    }
    //Updates the port list
    public static void connectReplicas(String[] ports) throws Exception{

        for(int i = 2; i < ports.length; i++){
            try {
                Registry registry = null;

                String ip = InetAddress.getLocalHost().getHostAddress();
                registry = LocateRegistry.getRegistry(ip, Integer.parseInt(ports[i]));

                server = new Server();
                UnicastRemoteObject.exportObject(server, 0);
                ServerInterface stub = (ServerInterface) registry.lookup(ports[i]);
                portList.add(Integer.parseInt(ports[i]));

                stub.registerServer(myPort);
            } catch(Exception e){
                System.out.println("Couldn't connect to replica " + ports[i]);
            }
        }
    }

    public void registerServer(String port) throws Exception{

        Lock lock = new ReentrantLock();
        lock.lock();
        portList.add(Integer.parseInt(port));
        lock.unlock();

    }
    //Stores the digital signatures in a log file for non-repudiation purposes
    private void storageSignture(ClientClass client, byte[] signature){
        Lock lock = new ReentrantLock();
        lock.lock();
        String pubKey = printBase64Binary(client.getPublicKey().getEncoded());
        String signString = printBase64Binary(signature);

        try {
            File file = new File(SignFile);
            FileReader fileReader = new FileReader(file);
            BufferedReader br = new BufferedReader(fileReader);
            String line;
            Path path = Paths.get(SignFile);

            Charset charset = Charset.forName("ISO-8859-1");

            List<String> lines = Files.readAllLines(path, charset);

            int i = 0;
            boolean newData = true;
            boolean isEmpty = true;
            while ((line = br.readLine()) != null) {
                isEmpty = false;
                if(line.equals(pubKey)){
                    line = br.readLine();
                    newData = false;
                    break;
                }
                else{
                    br.readLine();
                    br.readLine();
                    i+= 3;
                }
            }

            if(newData){
                if(!isEmpty){
                    lines.add("");
                    lines.add("");
                    lines.add("");
                }
                lines.add(i, pubKey);
                lines.add(i + 1, signString);
            }
            else{
                lines.remove(i + 1);
                lines.add(i + 1, line  + " || " + signString);
            }

            Files.write(path, lines, charset);
            br.close();
            fileReader.close();
        }
        catch(Exception e){
            e.printStackTrace();
        }
        lock.unlock();
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
        }
    }
    //Stores the password in a file with byte type
    private static void writeByteCode(byte[] code, int index){
        Lock lock = new ReentrantLock();
        lock.lock();
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
        lock.unlock();
    }

    //Gets the password from the byte file
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


    public void storeData(byte[] pass, String pKeyString, String domainString, String usernameString, Timestamp ts, byte[] writerSignature, int rank)throws Exception{
        Lock lock = new ReentrantLock();
        lock.lock();
        String elements = domainString + " " + usernameString;
        String signature = printBase64Binary(writerSignature);


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
            if (line.equals(pKeyString)) {
                line = br.readLine();
                if (line.equals(domainString)) {
                    line = br.readLine();
                    if (line.equals(usernameString)) {
                        writeByteCode(pass, Integer.parseInt(br.readLine()));
                        newData = false;
                        lines.remove(i+6);
                        lines.remove(i+5);
                        lines.remove(i+4);
                        lines.add(i+4, ts.toString());
                        lines.add(i+5, signature);
                        lines.add(i+6, ""+rank);
                        break;
                    } else {
                        br.readLine();
                        br.readLine();
                        br.readLine();
                        br.readLine();
                    }
                } else {
                    br.readLine();
                    br.readLine();
                    br.readLine();
                    br.readLine();
                    br.readLine();
                }
            } else {
                br.readLine();
                br.readLine();
                br.readLine();
                br.readLine();
                br.readLine();
                br.readLine();
            }
            i += 7;
        }
        if (newData) {
            Files.write(Paths.get(DataFileLoc),
                    (pKeyString + "\n" + domainString + "\n" + usernameString + "\n" + (getLastNumber()+1) + "\n" + ts + "\n" + signature + "\n" + rank + "\n").getBytes(),
                    StandardOpenOption.APPEND);
            writeByteCode(pass, -1);
        } else {
            Files.write(path, lines, charset);
        }

        br.close();
        lock.unlock();
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

    public int checkConnection(){
        return 1;
    }

    //Stores the information of the client in a file
    public void savePassword(byte[] message, byte[] signature, byte[] nonce, byte[] signatureNonce, Timestamp ts, int id, byte[] writerSignature, int port, int rank)throws Exception{

        byte[] pKeyBytes = null;
        byte[] restMsg = null;
        byte[] decryptNonce = null;
        ClientClass client = clientList.get(0);

        for(ClientClass element: clientList) {

            if(element.id == id) {

                byte[] Bmsg = DecryptCommunication(message, element.getSessionKey());
                pKeyBytes = copyOfRange(Bmsg, 0, 294); // parte da chave publica
                restMsg = copyOfRange(Bmsg, 294, Bmsg.length); // resto dos argumentos
                decryptNonce = DecryptCommunication(nonce, element.getSessionKey());
                client = element;
            }
        }

        //if(pKeyBytes == null){}

        PublicKey ClientPublicKey = null;

        ClientPublicKey =
                KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pKeyBytes));

        if(!verifyDigitalSignature(signature, message, ClientPublicKey)&&!verifyDigitalSignature(signatureNonce, decryptNonce, ClientPublicKey)){ //If true, signature checks
            return;
        }

        storageSignture(client, signature);


        if(!reg.getReplica(port).getReadingBool(id)) {
            if (!client.checkNonce(Timestamp.valueOf(new String(decryptNonce, "ASCII")))) {
                return;
            }
        }
        String dom = new String(copyOfRange(restMsg, 0, 30), "ASCII");
        String usr = new String(copyOfRange(restMsg, 30, 60), "ASCII");



        byte[] pass = copyOfRange(restMsg, 60, restMsg.length);
        String domFinal = rmPadd(dom.toCharArray());
        String usrFinal = rmPadd(usr.toCharArray());


        String pKeyString = printBase64Binary(pKeyBytes);
        String domainString = domFinal;
        String usernameString = usrFinal;

        storeData(pass,pKeyString,domainString,usernameString, ts, writerSignature, rank);


    }

    public void put(byte[] message, byte[] signature, byte[] nonce, byte[] signatureNonce , int id) throws Exception{

            for(ClientClass c : clientList) {
                if(c.id == id) {
                    if(portList.size() == 0){ //in case we only have one server we do not need to call the register
                        savePassword(message,signature,nonce,signatureNonce, new Timestamp(System.currentTimeMillis()), id, makeServerDigitalSignature(message), Integer.parseInt(myPort), myRank);
                        return;
                    }
                    c.myReg.write(message, signature, nonce, signatureNonce, id);
                }
            }

    }

    public boolean getReadingBool(int id){
        for(ClientClass c : clientList) {
            if(c.id == id) {
                return c.myReg.reading;
            }
        }
        return true;
    }

    //Gets the timestamp from file
    public Timestamp getTimetamp(byte[] message,byte[]signature,byte[] nonce,byte[] signatureNonce){

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
                if(line.equals(pKeyString)){
                    line = br.readLine();
                    if (line.equals(domainString)) {
                        line = br.readLine();
                        if (line.equals(usernameString)){
                            line = br.readLine();
                            line = br.readLine();

                            //Byzantine test 1, high timestamp, from 2020
                            if(myByzantine != 1) {
                                return Timestamp.valueOf(line);
                            }
                            else{
                                return Timestamp.valueOf("2020-05-05 03:33:12.738");
                            }
                        }
                        else{
                            br.readLine();
                            br.readLine();
                            br.readLine();
                            br.readLine();
                        }
                    }
                    else{
                        br.readLine();
                        br.readLine();
                        br.readLine();
                        br.readLine();
                        br.readLine();
                    }
                }
                else{
                    br.readLine();
                    br.readLine();
                    br.readLine();
                    br.readLine();
                    br.readLine();
                    br.readLine();
                }
                i+=7;
            }

        }
        catch (Exception e){
            System.out.println("Error: Couldn't locate the file.");
            e.printStackTrace();
            return null;
        }

        return null;
    }

    //Gets the rank from the file (to break ties)
    public int getRank(byte[]message, int id){


        byte[] pKeyBytes = null;
        ClientClass client = clientList.get(0);
        byte[] restMsg = null;
        for(ClientClass element: clientList) {



            try {
                byte[] Bmsg = DecryptCommunication(message, element.getSessionKey());
                pKeyBytes = copyOfRange(Bmsg,0,294); // parte da chave publica
                restMsg = copyOfRange(Bmsg, 294, Bmsg.length); // resto dos argumentos
                client = element;

            }
            catch(Throwable e){

            }
        }
        if(pKeyBytes == null){return 0;}

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
                if(line.equals(pKeyString)){
                    line = br.readLine();
                    if (line.equals(domainString)) {
                        line = br.readLine();
                        if (line.equals(usernameString)){
                            line = br.readLine();
                            line = br.readLine();
                            line = br.readLine();
                            line = br.readLine();
                            if(myByzantine!=2) {
                                return Integer.parseInt(line);
                            }
                            else if(myByzantine == 2 && getReadingBool(id)){
                                return 1;
                            }
                        }
                        else{
                            br.readLine();
                            br.readLine();
                            br.readLine();
                            br.readLine();
                        }
                    }
                    else{
                        br.readLine();
                        br.readLine();
                        br.readLine();
                        br.readLine();
                        br.readLine();
                    }
                }
                else{
                    br.readLine();
                    br.readLine();
                    br.readLine();
                    br.readLine();
                    br.readLine();
                    br.readLine();
                }
                i+=7;
            }

        }
        catch (Exception e){
            System.out.println("Error: Couldn't locate the file.");
            e.printStackTrace();
            return 0;
        }

        return 0;
    }

    public byte[] getServerSignature(byte[] message){


        byte[] pKeyBytes = null;
        ClientClass client = clientList.get(0);
        byte[] restMsg = null;
        for(ClientClass element: clientList) {



            try {
                byte[] Bmsg = DecryptCommunication(message, element.getSessionKey());
                pKeyBytes = copyOfRange(Bmsg,0,294); // parte da chave publica
                restMsg = copyOfRange(Bmsg, 294, Bmsg.length); // resto dos argumentos
                client = element;

            }
            catch(Throwable e){

            }
        }
        if(pKeyBytes == null){return null;}

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
                if(line.equals(pKeyString)){
                    line = br.readLine();
                    if (line.equals(domainString)) {
                        line = br.readLine();
                        if (line.equals(usernameString)){
                            line = br.readLine();
                            line = br.readLine();
                            line = br.readLine();
                            return parseBase64Binary(line);
                        }
                        else{
                            br.readLine();
                            br.readLine();
                            br.readLine();
                            br.readLine();
                        }
                    }
                    else{
                        br.readLine();
                        br.readLine();
                        br.readLine();
                        br.readLine();
                        br.readLine();
                    }
                }
                else{
                    br.readLine();
                    br.readLine();
                    br.readLine();
                    br.readLine();
                    br.readLine();
                    br.readLine();
                }
                i+=7;
            }

        }
        catch (Exception e){
            System.out.println("Error: Couldn't locate the file.");
            e.printStackTrace();
            return null;
        }

        return null;
    }

    //Gets the index corresponding to the last saved new data
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
                br.readLine();
                br.readLine();
                br.readLine();
            }

            return number;
        }
        catch(Exception e){
            e.printStackTrace();
            return number;              }

    }

    //Remove padding resulting from the communication
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

    public byte[] concatenateBytes(byte[] password, byte[] ts, byte[] rank) throws Exception{
        byte[] bytes = null;

        ArrayList<byte[]> list = new ArrayList<>();
        list.add(password);
        list.add(ts);
        list.add(rank);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (byte[] element : list) {
            baos.write(element);
        }
        bytes = baos.toByteArray();

        return bytes;
    }

    //Signs with server's private key
    public static byte[] makeServerDigitalSignature(byte[] bytes) throws Exception {


        // get a signature object using the SHA-1 and RSA combo
        // and sign the plaintext with the private key
        Signature sig = Signature.getInstance("SHA256WithRSA");
        sig.initSign((PrivateKey)ServerPrivateKey);
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

    public static boolean verifyServerDigitalSignature(byte[] signature, byte[] message) throws Exception {

        // verify the signature with the public key
        Signature sig = Signature.getInstance("SHA256WithRSA");

        sig.initVerify(ServerPublicKey);

        sig.update(message);
        try {
            return sig.verify(signature);
        } catch (SignatureException se) {
            System.out.println("Caught exception while verifying " + se);
            return false;
        }
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

    //Gets the password corresponding to a username and domain combination
    public byte[] retrievePassword(byte[] message, byte[] password){
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
           // e.printStackTrace();
        }

        return null;

    }

    public byte[] get( byte[] message, byte[] signature, byte[] nonce, byte[] signatureNonce, int id){

        SharedMemoryRegister obj = new SharedMemoryRegister();

        byte[] password = null;
        if(portList.size() == 0) { // Se não houver replicas, lemos do ficheiro
            password = getPass(message, signature, nonce, signatureNonce, id, Integer.parseInt(myPort));
        }else{
            for(ClientClass c : clientList) {
                if(c.id == id) {
                    c.myReg.read(message, signature, nonce, signatureNonce, Integer.parseInt(myPort), id);
                    obj = c.myReg;
                }
            }
            password = obj.value.password;
        }


        return retrievePassword(message, password);
    }

    //Divides the message and returns the password
    public byte[] divideMessage(byte[] message) {

        byte[] pKeyBytes = null;
        ClientClass client = clientList.get(0);
        byte[] restMsg = null;
        for (ClientClass element : clientList) {


            try {
                byte[] Bmsg = DecryptCommunication(message, element.getSessionKey());
                pKeyBytes = copyOfRange(Bmsg, 0, 294); // parte da chave publica
                restMsg = copyOfRange(Bmsg, 294, Bmsg.length); // resto dos argumentos
                client = element;

            } catch (Throwable e) {

            }
        }

        return copyOfRange(restMsg, 60, restMsg.length);
    }

    //Gets the password from the byte file
    public byte[] getPass( byte[] message, byte[] signature, byte[] nonce, byte[] signatureNonce, int id, int port){

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

            storageSignture(client, signature);

        if(reg.getReplica(port).getReadingBool(id))
            if(!client.checkNonce(Timestamp.valueOf(new String(decryptNonce, "ASCII")))){
                return null;
            }

        }
        catch(Exception e){
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
                if(line.equals(pKeyString)){
                    line = br.readLine();
                    if (line.equals(domainString)) {
                        line = br.readLine();
                        if (line.equals(usernameString)){
                            line = br.readLine();
                            if(myByzantine != 4 || !getReadingBool(id)) {
                                return readByteCode(Integer.parseInt(line));
                            }
                            else if(myByzantine == 4 && getReadingBool(id)){
                                SecureRandom rd = new SecureRandom();
                                byte[] rand = new byte[16];
                                rd.nextBytes(rand);
                                return rand;
                            }
                        }
                        else{
                            br.readLine();
                            br.readLine();
                            br.readLine();
                            br.readLine();
                        }
                    }
                    else{
                        br.readLine();
                        br.readLine();
                        br.readLine();
                        br.readLine();
                        br.readLine();
                    }
                }
                else{
                    br.readLine();
                    br.readLine();
                    br.readLine();
                    br.readLine();
                    br.readLine();
                    br.readLine();
                }
                i+=7;
            }

        }
        catch (Exception e){
            System.out.println("Error: Couldn't locate the file.");
            e.printStackTrace();
            return "noFile".getBytes();
        }

        return null;
    }


    public void register(byte[] pubKey, ClientInterface c) throws Exception{

        SecretKey SessKey = generateSession();

        Lock lock = new ReentrantLock();
        lock.lock();

        totalId = clientList.size()+1;
        int id = totalId; // we copy global totalID to a local id to pass to the client
        addClient(pubKey,SessKey, totalId);
        lock.unlock();

        PublicKey realClientPubKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pubKey));


        //pass the session key to client
        c.setSessionKey(EncryptionAssymmetric(SessKey.getEncoded(),realClientPubKey),
                makeServerDigitalSignature(SessKey.getEncoded()),
                EncryptionAssymmetric(Integer.toString(id).getBytes(),realClientPubKey),
                makeServerDigitalSignature((""+id).getBytes())
                );

        System.out.println("Client added. ID: " + id);

        Lock lock2 = new ReentrantLock();
        lock2.lock();
        if(portList.size()>0)reg.broadcastRegister(EncryptionAssymmetric(SessKey.getEncoded(), ServerPublicKey), realClientPubKey, EncryptionAssymmetric(Integer.toString(id).getBytes(),ServerPublicKey), Integer.parseInt(myPort));
        lock2.unlock();

    }





    private SecretKey generateSession()throws Exception {
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(128);
        return keygen.generateKey();

    }

    private void addClient(byte[] clientPublicKey, SecretKey sessionKey, int id){

        SharedMemoryRegister reg = new SharedMemoryRegister();
        try {
            clientList.add(new ClientClass(sessionKey, KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(clientPublicKey)),id, reg));
        }catch(Exception e){
            System.out.println("Error adding client: "+ e);
        }
    }



}
