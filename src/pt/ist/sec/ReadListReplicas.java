package pt.ist.sec;

import com.sun.org.apache.regexp.internal.RE;

import java.sql.Timestamp;

public class ReadListReplicas {

   public byte[] password;
   public Timestamp ts;
   public byte[] serverSignature;
   public byte[] message;
   public byte[] signature;
   public byte[] nonce;
   public byte[] signatureNonce;
   public int id;
   public int rank;


   public ReadListReplicas(byte[] password, Timestamp ts, byte[] serverSignature, byte[] message, byte[] signature,byte[] nonce, byte[] signatureNonce, int id, int rank){
      this.password = password;
      this.ts = ts;
      this.serverSignature = serverSignature;
      this.message = message;
      this.signature = signature;
      this.nonce = nonce;
      this.signatureNonce = signatureNonce;
      this.id = id;
      this.rank = rank;
   }
}
