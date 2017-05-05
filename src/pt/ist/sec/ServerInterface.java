package pt.ist.sec;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.sql.Timestamp;

public interface ServerInterface extends Remote{


    int checkConnection() throws RemoteException;
    void put(byte[] message, byte[] signature, byte[] nonce, byte[] signatureNonce, int id) throws Exception;
    byte[] get( byte[] message, byte[] signature, byte[] nonce, byte[] signatureNonce, int id) throws RemoteException;
    byte[] getDigitalSignature(byte[] PublicKey) throws Exception;
    void register(byte[] pubKey, ClientInterface c) throws Exception;
    void registerDeliver(byte[] sessKey, PublicKey pKey, byte[] id, int port)throws Exception;
    void registerServer(String port) throws Exception;
    void writeReturn(byte[] message, byte[] signature, byte[] nonce, byte[] signatureNonce, java.sql.Timestamp wts, int port, int id, byte[] writerSignature, int rid, int rank) throws Exception;
    void readReturn(byte[] message, byte[] signature, byte[] nonce, byte[] signatureNonce, int rid, int port, int id) throws Exception;
    void ackReturn(byte[] message, byte[] signature, byte[] nonce, byte[] signatureNonce, Timestamp ts, int port, int id, int rid) throws Exception;
    void sendValue(int rid, int id, byte[] password, Timestamp ts, byte[] serverSignature,byte[] message, byte[] signature, byte[] nonce, byte[] signatureNonce, int wr)throws Exception;
    boolean getReadingBool(int id) throws Exception;
    void deliverRegister() throws Exception;
}
