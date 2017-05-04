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

    public SharedMemoryRegister() {

        rid = 0;
        wts = null;
        acks = 1;
        value = null;
        writerSignature = null;
        reading = false;

    }

    public void write(byte[] message, byte[] signature, byte[] nonce, byte[] signatureNonce, int id) throws Exception {
        wts = new Timestamp(System.currentTimeMillis());
        acks = 1;
        rid++;
        byte[] pass = divideMessage(message);
        writerSignature = makeServerDigitalSignature(pass);
        readList.add(new ReadListReplicas(pass, wts, writerSignature, message, signature, nonce, signatureNonce, id, myRank));
        bebBroadcastRead(message, signature, nonce, signatureNonce,rid, Integer.parseInt(myPort), id);
    }

    public void bebBroadcastWrite(byte[] message, byte[] signature, byte[] nonce, byte[] signatureNonce, Timestamp wts, int id, byte[] writerSignature, int rank){
        try{
            for (int p : portList) {
                getReplica(p).writeReturn(message, signature, nonce, signatureNonce, wts, Integer.parseInt(super.myPort), id, writerSignature, rid, rank);
            }
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public void bebDeliverWrite(byte[] message, byte[] signature, byte[] nonce, byte[] signatureNonce, Timestamp ts, int port, int id, byte[] writerSignature, int rid, int rank)throws Exception{
        Lock lock = new ReentrantLock();
        lock.lock();
        if(getTimetamp(message,signature,nonce,signatureNonce) != null) {
            if (ts.after(getTimetamp(message, signature, nonce, signatureNonce)) || (ts.equals(getTimetamp(message, signature, nonce, signatureNonce)) && getRank(message) > rank)) {
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
            e.printStackTrace();
        }
    }
    public void plDeliverWrite(byte[] message, byte[] signature, byte[] nonce, byte[] signatureNonce, Timestamp ts, int port, int id,int rid) throws Exception
    {
        if(this.rid==rid) {

            acks++;
            if (acks > Math.ceil((int) (portList.size() + 1) / 2)) {
                acks = 1;
                if (reading) {
                    reading = false;
                } else {
                    //savePassword(message, signature, nonce, signatureNonce, ts, id, writerSignature, port, myRank);
                    writerSignature = null;
                }
            }

        }

    }

    public void read( byte[] message, byte[] signature, byte[] nonce, byte[] signatureNonce, int port, int id){
        rid++;
        acks=1;
        reading=true;
        readList = new ArrayList<>();
        value = null;
        byte[]readerPassword = getPass(message,signature,nonce,signatureNonce, id, port); //Para adicionar o seu valor da password na readlist para efeitos de posterior comparação
        Timestamp ts = getTimetamp(message,signature,nonce,signatureNonce);
        writerSignature = getServerSignature(message);

        byte[] serverSignature = getServerSignature(message);
        ReadListReplicas value = new ReadListReplicas(readerPassword, ts, serverSignature,message,signature,nonce,signatureNonce,id, getRank(message));
        readList.add(value);
        bebBroadcastRead(message, signature, nonce, signatureNonce,rid, port, id);
    }

    public void bebBroadcastRead( byte[] message, byte[] signature, byte[] nonce, byte[] signatureNonce, int rid, int port, int id){
        try{
            for (int p : portList) {
                getReplica(p).readReturn(message,signature,nonce,signatureNonce,rid, port, id);
            }
        }catch (Exception e){
           // e.printStackTrace();
        }
    }

    public void bebDeliverRead( byte[] password, Timestamp ts, int rid, int port, int id, byte[] serverSignature,byte[] message, byte[] signature, byte[] nonce, byte[] signatureNonce, int wr)throws Exception{

        getReplica(port).sendValue(rid, id, password, ts, serverSignature,message,signature,nonce,signatureNonce,wr);
    }

    public void plDeliverRead(int rid, byte[] password, Timestamp ts, byte[] serverSignature,byte[] message, byte[] signature, byte[] nonce, byte[] signatureNonce, int id, int wr)throws Exception{
        if(this.rid == rid) {
            boolean sign = false;
            boolean equalSign = false;
            try {
                if(reading){
                    sign = verifyServerDigitalSignature(serverSignature, password);
                    equalSign = printBase64Binary(serverSignature).equals(printBase64Binary(readList.get(0).serverSignature));
                }
                else{sign = true; equalSign = true;}
            }
            catch (Exception e){
                reading = false;
                return;  //Caso seja escrita, não existe ainda assinatura
            }
            if (sign){
                if (equalSign || !reading) {
                    Lock lock = new ReentrantLock();
                    lock.lock();
                    ReadListReplicas newValue = new ReadListReplicas(password, ts, serverSignature,message,signature,nonce,signatureNonce,id,wr);
                    readList.add(newValue);
                    lock.unlock();
                    if (readList.size() > Math.ceil((int) (portList.size() + 1) / 2)) {

                        Timestamp currentTs = readList.get(0).ts;
                        int rank = readList.get(0).rank;
                        int index = 0;
                        int indexMax = 0;
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
                        this.value = readList.get(indexMax);
                        readList = new ArrayList<>();

                        if(reading) {
                            if (getTimetamp(message, signature, nonce, signatureNonce) != null) {
                                if (value.ts.after(getTimetamp(message, signature, nonce, signatureNonce))) {
                                    savePassword(this.value.message, this.value.signature, this.value.nonce, this.value.signatureNonce, this.value.ts, this.value.id, this.value.serverSignature, Integer.parseInt(myPort), this.value.rank);
                                }
                                else if(value.ts.equals(getTimetamp(message, signature, nonce, signatureNonce)) && value.rank < myRank){
                                    savePassword(this.value.message, this.value.signature, this.value.nonce, this.value.signatureNonce, this.value.ts, this.value.id, this.value.serverSignature, Integer.parseInt(myPort), this.value.rank);
                                }
                            }
                            bebBroadcastWrite(this.value.message, this.value.signature, this.value.nonce, this.value.signatureNonce, this.value.ts, this.value.id, this.value.serverSignature, this.value.rank);
                        }
                        else{
                            Timestamp newTs = new Timestamp(System.currentTimeMillis());
                            if (getTimetamp(message, signature, nonce, signatureNonce) != null) {
                                if (value.ts.after(getTimetamp(message, signature, nonce, signatureNonce))) {
                                    savePassword(this.value.message, this.value.signature, this.value.nonce, this.value.signatureNonce, newTs, this.value.id, this.value.serverSignature, Integer.parseInt(myPort), myRank);
                                }
                            }
                            else{savePassword(this.value.message, this.value.signature, this.value.nonce, this.value.signatureNonce, newTs, this.value.id, this.value.serverSignature, Integer.parseInt(myPort), myRank);}
                            bebBroadcastWrite(this.value.message, this.value.signature, this.value.nonce, this.value.signatureNonce, newTs , this.value.id, this.value.serverSignature, myRank);

                        }

                    }
                }
            }
        }
    }

    public ServerInterface getReplica(int port) throws Exception {
        Registry registry = null;
        String ip = InetAddress.getLocalHost().getHostAddress();
        registry = LocateRegistry.getRegistry(ip, port);
        ServerInterface stub = (ServerInterface) registry.lookup("" + port);
        return stub;
    }




    public void broadcastRegister(byte[] sess, PublicKey pubK, byte[] id) throws Exception {
        for (int p : portList) {

            getReplica(p).registerDeliver(sess, pubK, id);
        }
    }
}