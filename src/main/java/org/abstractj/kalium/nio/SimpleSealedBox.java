package org.abstractj.kalium.nio;

import java.nio.ByteBuffer;

import static java.nio.ByteBuffer.allocateDirect;
import static org.abstractj.kalium.NaCl.Sodium.*;
import static org.abstractj.kalium.NaCl.sodium;
import static org.abstractj.kalium.crypto.Util.*;

public class SimpleSealedBox extends SimpleBox {
    private final ByteBuffer recipientPublicKey;
    private final ByteBuffer recipientPrivateKey;

    public SimpleSealedBox(final ByteBuffer recipientPublicKey) {
        checkLength(recipientPublicKey, CRYPTO_BOX_PUBLICKEYBYTES, "recipientPublicKey");
        this.recipientPublicKey = recipientPublicKey;
        this.recipientPrivateKey = null;
    }

    public SimpleSealedBox(final ByteBuffer recipientPublicKey, final ByteBuffer recipientPrivateKey) {
        checkLength(recipientPublicKey, CRYPTO_BOX_PUBLICKEYBYTES, "recipientPublicKey");
        checkLength(recipientPrivateKey, CRYPTO_BOX_SECRETKEYBYTES, "recipientPrivateKey");
        this.recipientPublicKey = recipientPublicKey;
        this.recipientPrivateKey = recipientPrivateKey;
    }

    @Override
    protected int nonceBytes() {
        return 0;
    }

    @Override
    protected int macBytes() {
        return 0;
    }

    @Override
    public BoxedData encrypt(ByteBuffer message) {
        checkMessage(message);
        final BoxedData boxed = new BoxedData(
                null,
                allocateDirect(message.limit() + CRYPTO_BOX_SEALBYTES),
                null);
        _encrypt(boxed, message);
        return boxed;
    }

    @Override
    protected void _encrypt(BoxedData boxed, ByteBuffer message) {
        isValid(sodium().crypto_box_seal(
                        boxed.getCiphertext(), message, message.limit(), recipientPublicKey),
                "failed encryption");
    }

    @Override
    public ByteBuffer decrypt(BoxedData boxed) {
        if (recipientPrivateKey == null)
            throw new IllegalStateException("Cannot decrypt with this box.");

        checkBoxed(boxed);
        final ByteBuffer msg = allocateDirect(boxed.ciphertextLength() - CRYPTO_BOX_SEALBYTES);
        _decrypt(msg, boxed);
        return msg;
    }

    @Override
    public void decrypt(ByteBuffer msg, BoxedData boxed) {
        if (recipientPrivateKey == null)
            throw new IllegalStateException("Cannot decrypt with this box.");

        super.decrypt(msg, boxed);
    }

    @Override
    protected void _decrypt(ByteBuffer msg, BoxedData boxed) {
        isValid(sodium().crypto_box_seal_open(
                        msg, boxed.getCiphertext(), boxed.ciphertextLength(), recipientPublicKey, recipientPrivateKey),
                "failed decryption");
    }

    @Override
    protected void checkBoxed(BoxedData boxed) {
        checkLengthIsGreaterThan(boxed.getCiphertext(), 0, "ciphertext");
    }

    @Override
    public void destroy() {
        zeroBuffer(recipientPublicKey);
        if (recipientPrivateKey != null)
            zeroBuffer(recipientPrivateKey);
    }
}
