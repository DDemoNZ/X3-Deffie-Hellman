package com.example.thriplerutchet.entities;

import java.util.Arrays;

public class RemoteAttestationResponse {

  private byte[] serverEphemeralPublic;

  private byte[] serverStaticPublic;

  private byte[] quote;

  private byte[] iv;

  private byte[] ciphertext;

  private byte[] tag;

  private String signature;

  private String certificates;

  private String signatureBody;

  public RemoteAttestationResponse(byte[] serverEphemeralPublic, byte[] serverStaticPublic,
                                   byte[] iv, byte[] ciphertext, byte[] tag,
                                   byte[] quote, String signature, String certificates, String signatureBody)
  {
    this.serverEphemeralPublic = serverEphemeralPublic;
    this.serverStaticPublic    = serverStaticPublic;
    this.iv                    = iv;
    this.ciphertext            = ciphertext;
    this.tag                   = tag;
    this.quote                 = quote;
    this.signature             = signature;
    this.certificates          = certificates;
    this.signatureBody         = signatureBody;
  }

  public RemoteAttestationResponse() {}

  public void setServerEphemeralPublic(byte[] serverEphemeralPublic) {
    this.serverEphemeralPublic = serverEphemeralPublic;
  }

  public void setServerStaticPublic(byte[] serverStaticPublic) {
    this.serverStaticPublic = serverStaticPublic;
  }

  public void setQuote(byte[] quote) {
    this.quote = quote;
  }

  public void setIv(byte[] iv) {
    this.iv = iv;
  }

  public void setCiphertext(byte[] ciphertext) {
    this.ciphertext = ciphertext;
  }

  public void setTag(byte[] tag) {
    this.tag = tag;
  }

  public void setSignature(String signature) {
    this.signature = signature;
  }

  public void setCertificates(String certificates) {
    this.certificates = certificates;
  }

  public void setSignatureBody(String signatureBody) {
    this.signatureBody = signatureBody;
  }

  public byte[] getServerEphemeralPublic() {
    return serverEphemeralPublic;
  }

  public byte[] getServerStaticPublic() {
    return serverStaticPublic;
  }

  public byte[] getQuote() {
    return quote;
  }

  public byte[] getIv() {
    return iv;
  }

  public byte[] getCiphertext() {
    return ciphertext;
  }

  public byte[] getTag() {
    return tag;
  }

  public String getSignature() {
    return signature;
  }

  public String getCertificates() {
    return certificates;
  }

  public String getSignatureBody() {
    return signatureBody;
  }

  @Override
  public String toString() {
    return "RemoteAttestationResponse{" +
            "serverEphemeralPublic=" + Arrays.toString(serverEphemeralPublic) +
            ", serverStaticPublic=" + Arrays.toString(serverStaticPublic) +
            ", quote=" + Arrays.toString(quote) +
            ", iv=" + Arrays.toString(iv) +
            ", ciphertext=" + Arrays.toString(ciphertext) +
            ", tag=" + Arrays.toString(tag) +
            ", signature='" + signature + '\'' +
            ", certificates='" + certificates + '\'' +
            ", signatureBody='" + signatureBody + '\'' +
            '}';
  }
}
