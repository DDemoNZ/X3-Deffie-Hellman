package com.example.thriplerutchet.util;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class AESCipher {

    public static final int    TAG_LENGTH_BYTES     = 16;
    public static final int    TAG_LENGTH_BITS      = TAG_LENGTH_BYTES * 8;
    public static final String AES_CIPHER_ALGORITHM = "AES/GCM/NoPadding";
    public static final String KEY_ALGORITHM        = "AES";
    public static final int    IV_LENGTH            = 12;
    private             Cipher cipher;

    public AESCipher() {
        getCipherInstance();
    }

    private void getCipherInstance() {
        try {
            cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new AssertionError(e);
        }
    }

    public byte[] decrypt(byte[] key, byte[] iv, byte[] ciphertext, byte[] tag, byte[] aad) throws InvalidKeyException {
        try {
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, KEY_ALGORITHM), new GCMParameterSpec(TAG_LENGTH_BITS, iv));

            if (aad != null) {
                cipher.updateAAD(aad);
            }

            return cipher.doFinal(ByteUtil.combine(ciphertext, tag));
        } catch (InvalidAlgorithmParameterException | IllegalBlockSizeException e) {
            throw new AssertionError(e);
        } catch (InvalidKeyException | BadPaddingException e) {
            throw new InvalidKeyException(e);
        }
    }

    public AESEncryptedResult encrypt(byte[] key, byte[] aad, byte[] requestData) {
        try {
            byte[] iv = Util.getSecretBytes(IV_LENGTH);

            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, KEY_ALGORITHM), gcmParameterSpec);

            if (aad != null) {
                cipher.updateAAD(aad);
            }

            byte[]   cipherText = cipher.doFinal(requestData);
            byte[][] parts      = ByteUtil.split(cipherText, cipherText.length - TAG_LENGTH_BYTES, TAG_LENGTH_BYTES);

            byte[] mac  = parts[1];
            byte[] data = parts[0];

            return new AESEncryptedResult(iv, data, mac, aad);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            throw new AssertionError(e);
        }
    }

    public static class AESEncryptedResult {
        final byte[] iv;
        final byte[] data;
        final byte[] mac;
        final byte[] aad;

        private AESEncryptedResult(byte[] iv, byte[] data, byte[] mac, byte[] aad) {
            this.iv   = iv;
            this.data = data;
            this.mac  = mac;
            this.aad  = aad;
        }

        public byte[] getIv() {
            return iv;
        }

        public byte[] getData() {
            return data;
        }

        public byte[] getMac() {
            return mac;
        }

        public byte[] getAad() {
            return aad;
        }
    }
}
