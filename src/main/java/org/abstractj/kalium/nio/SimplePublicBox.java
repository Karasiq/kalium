package org.abstractj.kalium.nio;

import java.nio.ByteBuffer;

import static java.nio.ByteBuffer.allocateDirect;
import static org.abstractj.kalium.NaCl.Sodium.*;
import static org.abstractj.kalium.NaCl.sodium;
import static org.abstractj.kalium.crypto.Util.*;

public class SimplePublicBox extends SimpleBox {

    private final ByteBuffer sharedKey;

    public SimplePublicBox(final ByteBuffer thierPublicKey, final ByteBuffer ourPrivateKey) {
        checkLength(thierPublicKey, publicKeyBytes(), "publicKey");
        checkLength(ourPrivateKey, privateKeyBytes(), "privateKey");

        sharedKey = allocateDirect(sharedKeyBytes());
        sodium().crypto_box_beforenm(sharedKey, thierPublicKey, ourPrivateKey);
    }

    protected int publicKeyBytes() {
        return CRYPTO_BOX_PUBLICKEYBYTES;
    }

    protected int privateKeyBytes() {
        return CRYPTO_BOX_SECRETKEYBYTES;
    }

    protected int sharedKeyBytes() {
        return CRYPTO_BOX_BEFORENMBYTES;
    }

    @Override
    protected int macBytes() {
        return CRYPTO_BOX_MACBYTES;
    }

    @Override
    protected int nonceBytes() {
        return CRYPTO_BOX_NONCEBYTES;
    }

    @Override
    protected void _encrypt(BoxedData boxed, ByteBuffer message) {
        final int r;

        if (boxed.macLength() > 0) {
            r = sodium().crypto_box_detached_afternm(
                    boxed.getCiphertext(), boxed.getMac(), message, message.limit(), boxed.getNonce(), sharedKey);
        } else {
            r = sodium().crypto_box_easy_afternm(
                    boxed.getCiphertext(), message, message.limit(), boxed.getNonce(), sharedKey);
        }

        isValid(r, "failed encryption");
    }

    @Override
    protected void _decrypt(final ByteBuffer msg, final BoxedData boxed) {
        final int r;

        if (boxed.macLength() > 0) {
            r = sodium().crypto_box_open_detached_afternm(
                    msg, boxed.getCiphertext(), boxed.getMac(), boxed.ciphertextLength(), boxed.getNonce(), sharedKey);
        } else {
            r = sodium().crypto_box_open_easy_afternm(
                    msg, boxed.getCiphertext(), boxed.ciphertextLength(), boxed.getNonce(), sharedKey);
        }

        isValid(r, "failed decryption");
    }

    @Override
    public void destroy() {
        zeroBuffer(sharedKey);
    }

    protected ByteBuffer getSharedKey() {
        return sharedKey;
    }
}
