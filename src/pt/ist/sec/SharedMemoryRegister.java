package pt.ist.sec;


import javax.crypto.SecretKey;
import java.net.InetAddress;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.security.PublicKey;
import java.sql.Time;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import static javax.xml.bind.DatatypeConverter.printBase64Binary;

public class SharedMemoryRegister extends Server {

    ReadListReplicas value;
    List<ReadListReplicas> readList = new ArrayList<>();
    //List<Integer> timestamps;

    public int rid;
    public Timestamp wts;
    public int acks;
    private byte[] writerSignature;
    public boolean reading;
    public int regACK;
    public boolean regLock;
    public boolean readLock;
    public Semaphore readingSemaphore = new Semaphore(0,true);
    public Semaphore registerSemaphore = new Semaphore(0,true);
    private int cId;
    private boolean registerFlag = false;
    private int count=0;
    private ReadListReplicas writeValue;

    public SharedMemoryRegister() {

        rid = 0;
        wts = null;
        acks = 1;
        value = null;
        writerSignature = null;
        reading = false;
        regACK = 0;
        regLock = false;
        readLock = false;


    }
    //This method is called when a client invokes a send password operation (writes register)
    public void write(byte[] message, byte[] signature, byte[] nonce, byte[] signatureNonce, int id) throws Exception {
        //Byzantine test 1, high timestamp, from 2020
        if(myByzantine !=1) {
            wts = new Timestamp(System.currentTimeMillis());
        }
        else{
            wts = Timestamp.valueOf("2020-05-05 03:33:12.738");

        }
        acks = 1;
        rid++;
        byte[] pass = divideMessage(message); //gets the password from the message
        byte[] signedPassTsRank = concatenateBytes(pass, ("" + wts).getBytes(), ("" + myRank).getBytes());    //Join pass, timestamp and rank for signing
        writerSignature = makeServerDigitalSignature(signedPassTsRank);//signs the password, ts and rank to prevent byzantine modifications
        readList = new ArrayList<>();

        writeValue = new ReadListReplicas(pass, wts, writerSignature, message, signature, nonce, signatureNonce, id, myRank);

        //Adds own file information to the list, acting as a broadcast received message
        byte[] filePass = getPass(message, signature, nonce, signatureNonce, id, Integer.parseInt(myPort));
        Timestamp ts = getTimetamp(message, signature, nonce, signatureNonce);
        byte[] fileSign = getServerSignature(message);

        boolean sign = false;
        boolean equalSign = false;
        try {
            byte[] fileSignedPassTsRank = concatenateBytes(filePass, ("" + ts).getBytes(), ("" + myRank).getBytes());
            sign = verifyServerDigitalSignature(fileSign, fileSignedPassTsRank);
            equalSign = printBase64Binary(fileSign).equals(printBase64Binary(readList.get(0).serverSignature));
        }
        catch(Exception e){
            if(filePass != null && ts != null && fileSign != null){
                sign = true; equalSign = true;
            }
        }
        if(sign && equalSign) {
            readList.add(new ReadListReplicas(filePass, ts, fileSign, message, signature, nonce, signatureNonce, id, myRank));//puts itself in the readlist, to simulate broadcast to itself
        }

        bebBroadcastRead(message, signature, nonce, signatureNonce,rid, Integer.parseInt(myPort), id); //broadcast read operation to all other replicas
    }
    //This method broadcasts write asynchronously to all other replicas
    public void bebBroadcastWrite(byte[] message, byte[] signature, byte[] nonce, byte[] signatureNonce, Timestamp wts, int id, byte[] writerSignature, int rank){
        try{
            for (int p : portList) {
                Runnable task = () -> {
                    try {
                        getReplica(p).writeReturn(message, signature, nonce, signatureNonce, wts, Integer.parseInt(super.myPort), id, writerSignature, rid, rank);
                    }
                    catch(Exception e){}
            };

            Thread thread = new Thread(task);
            thread.start();

            }
        }catch (Exception e){
            //e.printStackTrace();
        }
    }
    //This method writes in the replicas file and sends ack to the writer/reader
    public void bebDeliverWrite(byte[] message, byte[] signature, byte[] nonce, byte[] signatureNonce, Timestamp ts, int port, int id, byte[] writerSignature, int rid, int rank)throws Exception{
        Lock lock = new ReentrantLock();
        lock.lock();
        if(getTimetamp(message,signature,nonce,signatureNonce) != null) {
            if (ts.after(getTimetamp(message, signature, nonce, signatureNonce)) || (ts.equals(getTimetamp(message, signature, nonce, signatureNonce)) && getRank(message) > rank) || getTimetamp(message, signature, nonce, signatureNonce).after(new Timestamp(System.currentTimeMillis()))) {
                savePassword(message, signature, nonce, signatureNonce, ts, id, writerSignature, port, rank);
            }
            sendAck(message, signature, nonce, signatureNonce, ts, port, id,rid);
        }
        else{
            savePassword(message, signature, nonce, signatureNonce, ts, id, writerSignature, port, rank);
            sendAck(message, signature, nonce, signatureNonce, ts, port, id,rid);
        }
        lock.unlock();
    }

    public void sendAck(byte[] message, byte[] signature, byte[] nonce, byte[] signatureNonce, Timestamp ts, int port, int id, int rid) {
        try {
            getReplica(port).ackReturn(message, signature, nonce, signatureNonce, ts, port, id,rid);

        } catch (Exception e) {
            //e.printStackTrace();
        }
    }
    //This method delivers the write operation
    public void plDeliverWrite(byte[] message, byte[] signature, byte[] nonce, byte[] signatureNonce, Timestamp ts, int port, int id,int rid) throws Exception
    {
        if(this.rid==rid) {

            acks++;
            if (acks > Math.ceil((int) (portList.size() + 1) / 2)) {
                acks = 0;
                if (reading) {
                    reading = false;
                } else {
                    //savePassword(message, signature, nonce, signatureNonce, ts, id, writerSignature, port, myRank);
                    writerSignature = null;
                }
            }

        }

    }
    //This method is invoked when a client tries to retrieve a password (reads register)
    public void read( byte[] message, byte[] signature, byte[] nonce, byte[] signatureNonce, int port, int id){
        rid++;
        acks=1;
        reading=true;
        readList = new ArrayList<>();
        value = null;

        //gets all information from own file
        byte[]readerPassword = getPass(message,signature,nonce,signatureNonce, id, port);
        Timestamp ts = getTimetamp(message,signature,nonce,signatureNonce);
        writerSignature = getServerSignature(message);
        byte[] serverSignature = getServerSignature(message);
        ReadListReplicas value = new ReadListReplicas(readerPassword, ts, serverSignature,message,signature,nonce,signatureNonce,id, getRank(message));
        readList.add(value);//puts itself in the readlist, to simulate broadcast to itself

        bebBroadcastRead(message, signature, nonce, signatureNonce,rid, port, id); //broadcasts to all other replicas
    }

    //This method broadcasts read asynchronously to all other replicas
    public void bebBroadcastRead( byte[] message, byte[] signature, byte[] nonce, byte[] signatureNonce, int rid, int port, int id){
        try{
            for (int p : portList) {
                Runnable task = () -> {
                    try {
                        getReplica(p).readReturn(message, signature, nonce, signatureNonce, rid, port, id);
                    } catch (Exception e) {
                    }
                    count++;
                };

                Thread thread = new Thread(task);
                thread.start();
            }

                readingSemaphore.acquire();




        }catch (Exception e){
           // e.printStackTrace();
        }
    }
    //Sends each replicas value (in the file) to the reader
    public void bebDeliverRead( byte[] password, Timestamp ts, int rid, int port, int id, byte[] serverSignature,byte[] message, byte[] signature, byte[] nonce, byte[] signatureNonce, int wr)throws Exception{

        try {
            if(myByzantine == 1) {
                System.out.println("I'm getting 2020-05-05 03:33:12.738 as timestamp from the file.");
            }
            getReplica(port).sendValue(rid, id, password, ts, serverSignature, message, signature, nonce, signatureNonce, wr);
        } catch (Exception e){}
    }


    public void plDeliverRead(int rid, byte[] password, Timestamp ts, byte[] serverSignature,byte[] message, byte[] signature, byte[] nonce, byte[] signatureNonce, int id, int wr)throws Exception{
        if(this.rid == rid) {
            boolean sign = false;
            boolean equalSign = false;
            try {


                //Prevents errors while writing & checks signatures
                if(reading){
                    byte[] signedPassTsRank = concatenateBytes(password, (""+ts).getBytes(), (""+wr).getBytes());
                    sign = verifyServerDigitalSignature(serverSignature, signedPassTsRank);
                    equalSign = printBase64Binary(serverSignature).equals(printBase64Binary(readList.get(0).serverSignature));
                }
                else{
                    if(password != null && ts != null && serverSignature != null && wr != 0){
                        byte[] signedPassTsRank = concatenateBytes(password, (""+ts).getBytes(), (""+wr).getBytes());
                        sign = verifyServerDigitalSignature(serverSignature, signedPassTsRank);
                        equalSign = printBase64Binary(serverSignature).equals(printBase64Binary(readList.get(0).serverSignature));
                    }
                    else{
                        sign = true;
                        equalSign = true;
                    }

                }
            }
            catch (Exception e){
                reading = false;
                return;
            }
            if (sign){
                if (equalSign || !reading) {
                    Lock lock = new ReentrantLock();
                    lock.lock();
                    ReadListReplicas newValue = new ReadListReplicas(password, ts, serverSignature,message,signature,nonce,signatureNonce,id,wr);
                    readList.add(newValue);

                    //Sufficient number of replicas
                    if (readList.size() > Math.ceil((int) (portList.size() + 1) / 2)) {

                        //Attributes the first value to the max value, ts and rank
                        Timestamp currentTs = readList.get(0).ts;
                        int rank = readList.get(0).rank;
                        int index = 0;
                        int indexMax = 0;

                        //Check what is the max ts & rank, saving the value
                        for (ReadListReplicas auxVal : readList) {
                            try {
                                if (currentTs.equals(auxVal.ts) && rank >= auxVal.rank) {
                                    currentTs = auxVal.ts;
                                    rank = auxVal.rank;
                                    indexMax = index;
                                } else if (currentTs.before(auxVal.ts)) {
                                    currentTs = auxVal.ts;
                                    rank = auxVal.rank;
                                    indexMax = index;
                                }

                            }
                            catch(Exception e){}
                            index++;
                        }

                        try {
                            if ((currentTs.equals(writeValue.ts) && rank >= writeValue.rank) || currentTs.before(writeValue.ts)) {
                                this.value = writeValue;
                            } else {
                                this.value = readList.get(indexMax);
                            }

                        }
                        catch(Exception e){this.value = writeValue;}


                        readList = new ArrayList<>();
                        lock.unlock();
                        try {
                            //Saves the highest values while reading, according to the atomic algorithm
                            if (reading) {
                                if (getTimetamp(message, signature, nonce, signatureNonce) != null) {
                                    savePassword(this.value.message, this.value.signature, this.value.nonce, this.value.signatureNonce, this.value.ts, this.value.id, this.value.serverSignature, Integer.parseInt(myPort), this.value.rank);
                                }
                                bebBroadcastWrite(this.value.message, this.value.signature, this.value.nonce, this.value.signatureNonce, this.value.ts, this.value.id, this.value.serverSignature, this.value.rank);
                            }

                            //Simply writes the values in every replica
                            else {

                                savePassword(this.value.message, this.value.signature, this.value.nonce, this.value.signatureNonce, this.value.ts, this.value.id, this.value.serverSignature, Integer.parseInt(myPort), myRank);
                                bebBroadcastWrite(this.value.message, this.value.signature, this.value.nonce, this.value.signatureNonce, this.value.ts, this.value.id, this.value.serverSignature, myRank);

                            }
                            readingSemaphore.release();   //Unlocks the main thread, since values are already avaliable to be retrieved
                        }
                        catch (Exception e){
                            readingSemaphore.release();
                        }

                    }
                }
            }
        }
    }
    //This method created a remote object in a server specified by port
    public ServerInterface getReplica(int port) throws Exception {
        Registry registry = null;
        String ip = InetAddress.getLocalHost().getHostAddress();
        registry = LocateRegistry.getRegistry(ip, port);
        ServerInterface stub = (ServerInterface) registry.lookup("" + port);
        return stub;
    }



    //This method propagates the client register operation to all other replicas
    public void broadcastRegister(byte[] sess, PublicKey pubK, byte[] id, int port) throws Exception {
        cId = Integer.parseInt(new String(DecryptionAssymmetric(id),"ASCII"));
        regACK++;
        //unlockServer(Integer.parseInt(new String(DecryptionAssymmetric(id),"ASCII")));
        for (int p : portList) {

            Runnable task = () -> {
                try {

                    getReplica(p).registerDeliver(sess, pubK, id, port);
                }
                catch(Exception e){}
            };

            Thread thread = new Thread(task);
            thread.start();
        }
        registerSemaphore.acquire(); //locks main thread and waits for a sufficient replica's return
        cId = 0;
        if(registerFlag){
            registerFlag = false;
            throw new Exception();
        }

    }
/*
    public void unlockServer(int id){
        Runnable task = () -> {
            try {
                Thread.sleep(500);
                if(cId == id){
                    registerFlag = true;
                    registerSemaphore.release(); //locks main thread and waits for a sufficient replica's return
                    regACK = 1;
                }
            }
            catch(Exception e){}
        };

    }
    */


    public void regDeliver(int port) throws Exception{
        try {
            getReplica(port).deliverRegister();
        }
        catch(Exception e){}
    }
    //collects client registration acks
    public void finishRegister(){
        regACK++;
        if (regACK > Math.ceil((int) (portList.size() + 1) / 2)) {
            regACK = 0;
            registerSemaphore.release();// we have a sufficient number of acks so we release the main thread
        }
    }
}