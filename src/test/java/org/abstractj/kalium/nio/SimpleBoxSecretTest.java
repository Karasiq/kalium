package org.abstractj.kalium.nio;

import org.abstractj.kalium.NaCl;
import org.junit.Test;

import java.nio.ByteBuffer;

import static java.nio.ByteBuffer.allocate;
import static java.nio.ByteBuffer.wrap;
import static org.abstractj.kalium.NaCl.Sodium.CRYPTO_SECRETBOX_KEYBYTES;
import static org.abstractj.kalium.NaCl.Sodium.CRYPTO_SECRETBOX_MACBYTES;
import static org.abstractj.kalium.encoders.Encoder.HEX;
import static org.abstractj.kalium.fixture.TestVectors.*;
import static org.abstractj.kalium.nio.SimpleBox.newSecretBox;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class SimpleBoxSecretTest {

    byte[] keyArray = HEX.decode(SECRET_KEY);
    byte[] msgArray = HEX.decode(BOX_MESSAGE);
    byte[] ciphertextArray = HEX.decode(BOX_CIPHERTEXT);
    byte[] nonceArray = HEX.decode(BOX_NONCE);


    @Test
    public void testSecretKeyRequired() throws Exception {
        try {
            newSecretBox(null);
        } catch (NullPointerException npe) {
            assertEquals("secretKey cannot be null", npe.getMessage());
        }
    }

    @Test
    public void testSecretKeyLength() throws Exception {
        try {
            newSecretBox(allocate(CRYPTO_SECRETBOX_KEYBYTES - 1));
        } catch (IllegalArgumentException iae) {
            assertEquals("secretKey expected length = " + CRYPTO_SECRETBOX_KEYBYTES +
                            ", actual length = " + (CRYPTO_SECRETBOX_KEYBYTES - 1),
                    iae.getMessage());
        }

        try {
            newSecretBox(allocate(CRYPTO_SECRETBOX_KEYBYTES + 1));
        } catch (IllegalArgumentException iae) {
            assertEquals("secretKey expected length = " + CRYPTO_SECRETBOX_KEYBYTES +
                            ", actual length = " + (CRYPTO_SECRETBOX_KEYBYTES + 1),
                    iae.getMessage());
        }

        newSecretBox(allocate(CRYPTO_SECRETBOX_KEYBYTES));
    }

    @Test
    public void testEncryptDecrypt() throws Exception {
        SimpleBox box = newSecretBox(wrap(keyArray));
        BoxedData encryptedData = box.encrypt(wrap(msgArray));
        ByteBuffer decryptedMessage = box.decrypt(encryptedData);
        byte[] decryptedArray = new byte[decryptedMessage.limit()];
        decryptedMessage.get(decryptedArray);
        assertArrayEquals(msgArray, decryptedArray);
    }

    @Test
    public void testEncrypt() throws Exception {
        SimpleBox box = newSecretBox(wrap(keyArray));
        BoxedData encryptedData = box.encrypt(wrap(msgArray));

        byte[] ciphertext = encryptedData.copyCiphertextToArray();
        byte[] mac = encryptedData.copyMacToArray();
        byte[] nonce = encryptedData.copyNonceToArray();

        byte[] decryptedArray = new byte[ciphertext.length];
        int r = NaCl.sodium().crypto_secretbox_open_detached(
                decryptedArray, ciphertext, mac, ciphertext.length, nonce, keyArray);
        assertEquals(0, r);
        assertArrayEquals(msgArray, decryptedArray);
    }

    @Test
    public void testDecryptCombined() throws Exception {
        SimpleBox box = newSecretBox(wrap(keyArray));
        BoxedData encryptedData = BoxedData.fromArrays(nonceArray, ciphertextArray, null);

        ByteBuffer decryptedMessage = box.decrypt(encryptedData);
        byte[] decryptedArray = new byte[decryptedMessage.limit()];
        decryptedMessage.get(decryptedArray);
        assertArrayEquals(msgArray, decryptedArray);

        byte[] ciphertextArray1 = new byte[msgArray.length + CRYPTO_SECRETBOX_MACBYTES];
        int r = NaCl.sodium().crypto_secretbox_easy(ciphertextArray1, msgArray, msgArray.length, nonceArray, keyArray);
        assertEquals(0, r);
        encryptedData = BoxedData.fromArrays(nonceArray, ciphertextArray1, null);

        decryptedMessage = box.decrypt(encryptedData);
        decryptedArray = new byte[decryptedMessage.limit()];
        decryptedMessage.get(decryptedArray);
        assertArrayEquals(msgArray, decryptedArray);
    }

    @Test
    public void testTestDecryptDetatched() throws Exception {
        SimpleBox box = newSecretBox(wrap(keyArray));

        byte[] ctNoMacArray = new byte[ciphertextArray.length - CRYPTO_SECRETBOX_MACBYTES];
        byte[] macArray = new byte[CRYPTO_SECRETBOX_MACBYTES];
        System.arraycopy(ciphertextArray, 0, macArray, 0, CRYPTO_SECRETBOX_MACBYTES);
        System.arraycopy(ciphertextArray, CRYPTO_SECRETBOX_MACBYTES, ctNoMacArray, 0, ctNoMacArray.length);

        BoxedData encryptedData = BoxedData.fromArrays(nonceArray, ctNoMacArray, macArray);
        ByteBuffer decryptedMessage = box.decrypt(encryptedData);
        byte[] decryptedArray = new byte[decryptedMessage.limit()];
        decryptedMessage.get(decryptedArray);
        assertArrayEquals(msgArray, decryptedArray);
    }
}