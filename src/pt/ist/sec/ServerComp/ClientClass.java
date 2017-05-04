package pt.ist.sec;

import javax.crypto.SecretKey;
import java.io.*;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;

import static javax.xml.bind.DatatypeConverter.printBase64Binary;

/**
 * Created by Romeu Viana on 14/03/2017.
 */
public class ClientClass extends Server {
    private PublicKey publicKey;
    private SecretKey sessionKey;
    public ArrayList<byte[]> usedNonces = new ArrayList<>();
    private byte[] signature;
    private int nonce;

    private String noncePath = System.getProperty("user.dir") + "\\data\\nonces.txt";;

    public ClientClass (SecretKey sessionKey, PublicKey pk){
        this.sessionKey = sessionKey;
        this.publicKey = pk;
    }

    protected void setPublicKey(PublicKey pubKey){

        this.publicKey = pubKey;
        //noncePath = System.getProperty("user.dir") + "\\data\\" + Arrays.copyOf(publicKey.getEncoded(),10) + ".txt";
    }

    protected PublicKey getPublicKey(){

        return publicKey;
    }

    protected SecretKey getSessionKey(){

        return sessionKey;
    }

    protected void updateSessionKey(SecretKey sessionKey){

        this.sessionKey = sessionKey;
    }

    protected void setNonce(int nonce){
        this.nonce = nonce;
    }

    protected byte[] getNextNonce(){
        this.nonce = this.nonce + 10;
        return ("" + this.nonce).getBytes();
    }

    protected boolean checkNonce(byte[] nonceBytes){
        try {
            int newNonce = Integer.parseInt(new String(nonceBytes, "ASCII"));

            if(newNonce == (this.nonce + 10)){
                setNonce(newNonce);
                return true;
            }
        }
        catch(Exception e){
            e.printStackTrace();
        }

        return false;
    }

    protected byte[] getLastSignature(){
        return signature;
    }

    protected void setSignature(byte[] signature){
        this.signature=signature;
    }
}
