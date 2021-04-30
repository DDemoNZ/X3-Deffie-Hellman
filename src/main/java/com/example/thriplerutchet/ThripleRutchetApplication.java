package com.example.thriplerutchet;

import com.example.thriplerutchet.entities.RemoteAttestationResponse;
import com.example.thriplerutchet.util.AESCipher;
import com.example.thriplerutchet.util.ByteUtil;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPrivateKey;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.kdf.HKDFv3;
import org.whispersystems.libsignal.ecc.Curve;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

//@SpringBootApplication
public class ThripleRutchetApplication {
    private final static int REQUEST_ID_LENGTH = 16;
    private static ECKeyPair serverStatic;
    private static ECKeyPair serverEphemeral;
    public static AESCipher aesCipher = new AESCipher();

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, java.security.InvalidKeyException {

        ECKeyPair clientKeyPair = Curve.generateKeyPair();

        sendRequestToServer(clientKeyPair);
    }

    private static void sendRequestToServer(ECKeyPair clientGeneratedKeyPair) throws NoSuchAlgorithmException, InvalidKeyException, java.security.InvalidKeyException {
        doServerHandshake(clientGeneratedKeyPair);

        generateRequestId();
    }

    private static void doServerHandshake(ECKeyPair clientGeneratedKeyPair) throws InvalidKeyException, NoSuchAlgorithmException, java.security.InvalidKeyException {
        serverEphemeral = Curve.generateKeyPair();
        serverStatic = Curve.generateKeyPair();

        KeyPair serverKeyPair = keyExchangeServer(clientGeneratedKeyPair.getPublicKey());

        String testString = "test";

        AESCipher.AESEncryptedResult encryptedResult = aesCipher.encrypt(serverKeyPair.getServerKey(), null, testString.getBytes());

        RemoteAttestationResponse attestationResponse = new RemoteAttestationResponse(
                serverEphemeral.getPublicKey().getPublicKeyBytes(), serverStatic.getPublicKey().getPublicKeyBytes(),
                encryptedResult.getIv(), encryptedResult.getData(), encryptedResult.getMac(),
                null, null, null, null);

        KeyPair clientKeyPair = keyExchangeClient(clientGeneratedKeyPair, attestationResponse);

//        String s = new String(aesCipher.decrypt(clientKeyPair.getServerKey(), attestationResponse.getIv(), attestationResponse.getCiphertext(), attestationResponse.getTag(), null));
//        System.out.println(s);

        System.out.println("**********************************");
        System.out.println("Server key pair: " + serverKeyPair);
        System.out.println("Client key pair: " + clientKeyPair);
        System.out.println("**********************************");
    }

    private static KeyPair keyExchangeClient(ECKeyPair clientGeneratedKeyPair, RemoteAttestationResponse attestationResponse) throws InvalidKeyException {
        return keyPairClient(clientGeneratedKeyPair, attestationResponse.getServerEphemeralPublic(), attestationResponse.getServerStaticPublic());
    }

    private static KeyPair keyPairClient(ECKeyPair keyPair, byte[] serverPublicEphemeral, byte[] serverPublicStatic) throws InvalidKeyException {
        byte[] ephemeralToEphemeral = Curve.calculateAgreement(ECPublicKey.fromPublicKeyBytes(serverPublicEphemeral), keyPair.getPrivateKey());
        byte[] ephemeralToStatic    = Curve.calculateAgreement(ECPublicKey.fromPublicKeyBytes(serverPublicStatic), keyPair.getPrivateKey());

        byte[] masterSecret = org.whispersystems.libsignal.util.ByteUtil.combine(ephemeralToEphemeral, ephemeralToStatic                          );
        byte[] publicKeys   = org.whispersystems.libsignal.util.ByteUtil.combine(keyPair.getPublicKey().getPublicKeyBytes(), serverPublicEphemeral, serverPublicStatic);

        HKDFv3 generator = new HKDFv3();

        byte[] clientKey = new byte[32];
        byte[] serverKey = new byte[32];

        byte[] keys      = generator.deriveSecrets(masterSecret, publicKeys, null, clientKey.length + serverKey.length);

        System.arraycopy(keys, 0, clientKey, 0, clientKey.length);
        System.arraycopy(keys, clientKey.length, serverKey, 0, serverKey.length);

        return new KeyPair(clientKey, serverKey);
    }

    private static KeyPair keyExchangeServer(ECPublicKey clientPublicKey) throws InvalidKeyException, NoSuchAlgorithmException {
        byte[] ephemeral_dh_key_x = curve25519_donna(serverEphemeral.getPrivateKey(), clientPublicKey);
        byte[] static_dh_key_x = curve25519_donna(serverStatic.getPrivateKey(), clientPublicKey);
        byte[] hkdf_salt = sgxsd_enclave_sha256(clientPublicKey.getPublicKeyBytes(), serverEphemeral.getPublicKey().getPublicKeyBytes(), serverStatic.getPublicKey().getPublicKeyBytes());
        byte[] pending_request_hkdf_prk = sgxsd_enclave_hmac_sha256(hkdf_salt, ephemeral_dh_key_x, static_dh_key_x);

        byte[] clientKey = new byte[32];
        byte[] serverKey = new byte[32];

        System.arraycopy(pending_request_hkdf_prk, 0, clientKey, 0, clientKey.length);
        System.arraycopy(pending_request_hkdf_prk, clientKey.length, serverKey, 0, serverKey.length);

        return new KeyPair(clientKey, serverKey);
    }


    public static byte[] generateRequestId() {
        byte[] requestId = new byte[REQUEST_ID_LENGTH];
        new SecureRandom().nextBytes(requestId);

        return requestId;
    }

    private static byte[] curve25519_donna(ECPrivateKey serverPrivateKey, ECPublicKey clientPublicKey) throws InvalidKeyException {
        return Curve.calculateAgreement(clientPublicKey, serverPrivateKey);
    }

    private static byte[] sgxsd_enclave_sha256(byte[] clPubKey, byte[] serEphemeralPublicKey, byte[] serStaticPublicKey) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        digest.update(clPubKey);
        digest.update(serEphemeralPublicKey);
        digest.update(serStaticPublicKey);

        return digest.digest();
    }

    private static byte[] sgxsd_enclave_hmac_sha256(byte[] salt, byte[] ephemeral_dh_key_x, byte[] static_dh_key_x) {
        byte[] combKeys = ByteUtil.combine(ephemeral_dh_key_x, static_dh_key_x);
        HKDFv3 generator = new HKDFv3();

        return generator.deriveSecrets(combKeys, salt, null, 64);
    }

    public static class KeyPair {
        private final byte[] clientKey;
        private final byte[] serverKey;

        public KeyPair(byte[] clientKey, byte[] serverKey) {
            this.clientKey = clientKey;
            this.serverKey = serverKey;
        }

        public byte[] getClientKey() {
            return clientKey;
        }

        public byte[] getServerKey() {
            return serverKey;
        }

        @Override
        public String toString() {
            return "KeyPair {" +
                    "   \nclientKey=" + Arrays.toString(clientKey) +
                    ",  \nserverKey=" + Arrays.toString(serverKey) +
                    "\n}";
        }
    }

}
