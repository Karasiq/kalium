package org.abstractj.kalium.nio;

import java.nio.ByteBuffer;

import static org.abstractj.kalium.NaCl.Sodium.*;
import static org.abstractj.kalium.NaCl.sodium;
import static org.abstractj.kalium.crypto.Util.*;

public class SimpleSecretBox extends SimpleBox {
    private final ByteBuffer secretKey;

    public SimpleSecretBox(final ByteBuffer secretKey) {
        checkLength(secretKey, keyBytes(), "secretKey");
        this.secretKey = secretKey;
    }

    protected int keyBytes() {
        return CRYPTO_SECRETBOX_KEYBYTES;
    }

    @Override
    protected int macBytes() {
        return CRYPTO_SECRETBOX_MACBYTES;
    }

    @Override
    protected int nonceBytes() {
        return CRYPTO_SECRETBOX_NONCEBYTES;
    }

    @Override
    public void _encrypt(final BoxedData boxed, final ByteBuffer message) {
        final int r;

        if (boxed.macLength() > 0) {
            r = sodium().crypto_secretbox_detached(
                            boxed.getCiphertext(), boxed.getMac(), message, message.limit(), boxed.getNonce(), secretKey);
        } else {
            r = sodium().crypto_secretbox_easy(
                    boxed.getCiphertext(), message, message.limit(), boxed.getNonce(), secretKey);
        }

        isValid(r, "failed encryption");
    }

    @Override
    protected void _decrypt(final ByteBuffer msg, final BoxedData boxed) {
        final int r;

        if (boxed.macLength() > 0) {
//            byte[] msgArray = new byte[msg.limit()];
//            byte[] ctArray = boxed.copyCiphertextToArray();
//            byte[] nArray = boxed.copyNonceToArray();
//            byte[] macArray = boxed.copyMacToArray();
//            byte[] keyArray = new byte[secretKey.limit()];
//            secretKey.get(keyArray);
//            secretKey.rewind();

//            r = sodium().crypto_secretbox_open_detached(msgArray, ctArray, macArray, ctArray.length, nArray, keyArray);
            ByteBuffer sk2 = ByteBuffer.allocateDirect(boxed.getNonce().capacity());
            sk2.put(boxed.getNonce());
            r = sodium().crypto_secretbox_open_detached(
                    msg, boxed.getCiphertext(), boxed.getMac(), boxed.ciphertextLength(), sk2, secretKey);
        } else {
            r = sodium().crypto_secretbox_open_easy(
                    msg, boxed.getCiphertext(), boxed.ciphertextLength(), boxed.getNonce(), secretKey);
        }

        isValid(r, "failed decryption");
    }

    @Override
    public void destroy() {
        zeroBuffer(secretKey);
    }

    protected ByteBuffer getSecretKey() {
        return secretKey;
    }
}
