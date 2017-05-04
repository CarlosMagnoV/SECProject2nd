package pt.ist.sec;

import javax.crypto.SecretKey;
import java.io.*;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.PublicKey;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;

import static javax.xml.bind.DatatypeConverter.printBase64Binary;


public class ClientClass extends Server {
    private PublicKey publicKey;
    private SecretKey sessionKey;
    public ArrayList<byte[]> usedNonces = new ArrayList<>();
    private byte[] signature;
    private Timestamp nonce;
    public int id;
    public SharedMemoryRegister myReg;

    public ClientClass (SecretKey sessionKey, PublicKey pk, int id, SharedMemoryRegister myReg){
        this.sessionKey = sessionKey;
        this.publicKey = pk;
        this.id = id;
        this.myReg = myReg;
    }

    protected void setPublicKey(PublicKey pubKey){

        this.publicKey = pubKey;

    }

    protected PublicKey getPublicKey(){

        return publicKey;
    }

    protected SecretKey getSessionKey(){

        return sessionKey;
    }


    protected void setNonce(Timestamp nonce){
        this.nonce = nonce;
    }

    protected byte[] getNextNonce(){
        return (""+this.nonce).getBytes();
    }


    protected boolean checkNonce(Timestamp nonce){

        if(this.nonce == null){
            this.nonce = nonce;
            return true;
        }

        try {
            //int newNonce = Integer.parseInt(new String(nonceBytes, "ASCII"));

            if(nonce.after(this.nonce)){
                setNonce(nonce);
                return true;
            }
            else{System.out.println("Wrong nonce. Our Nonce=" + this.nonce + " ; Checking=" + nonce);}
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
