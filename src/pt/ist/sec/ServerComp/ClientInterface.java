package pt.ist.sec;

import javax.crypto.SecretKey;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

public interface ClientInterface extends Remote {
    void save_password(byte[] message) throws Exception;
    byte[] retrieve_password(byte[] message) throws Exception;
    void setSessionKey(byte[] SessKey)throws Exception;
    byte[] getNonce() throws Exception;
}
