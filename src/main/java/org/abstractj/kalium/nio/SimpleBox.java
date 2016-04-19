package org.abstractj.kalium.nio;

import java.nio.ByteBuffer;

import static java.nio.ByteBuffer.allocate;
import static java.nio.ByteBuffer.allocateDirect;
import static org.abstractj.kalium.NaCl.sodium;
import static org.abstractj.kalium.crypto.Util.checkLength;
import static org.abstractj.kalium.crypto.Util.checkLengthIsGreaterThan;


public abstract class SimpleBox {

    public static SimpleBox newSecretBox(final ByteBuffer secretKey) {
        return new SimpleSecretBox(secretKey);
    }

    public static SimpleBox newPublicBox(final ByteBuffer theirPublicKey, final ByteBuffer ourPrivateKey) {
        return new SimplePublicBox(theirPublicKey, ourPrivateKey);
    }

    public static SimpleBox newSealedBox(final ByteBuffer recipientPublicKey) {
        return new SimpleSealedBox(recipientPublicKey);
    }

    public static SimpleBox newSealedBox(final ByteBuffer recipientPublicKey, final ByteBuffer recipientPrivateKey) {
        return new SimpleSealedBox(recipientPublicKey, recipientPrivateKey);
    }

    public BoxedData encrypt(final ByteBuffer message) {
        checkMessage(message);
        final BoxedData boxed = new BoxedData(
                generateNonce(),
                allocateDirect(message.limit()),
                allocateDirect(macBytes()));
        _encrypt(boxed, message);
        return boxed;
    }

    public void encrypt(final BoxedData boxed, final ByteBuffer message) {
        checkMessage(message);
        checkBoxed(boxed);
        generateNonce(boxed.getNonce());
        _encrypt(boxed, message);
    }

    protected abstract void _encrypt(final BoxedData boxed, final ByteBuffer message);

    public ByteBuffer decrypt(final BoxedData boxed) {
        checkBoxed(boxed);

        final ByteBuffer msg;

        if (boxed.macLength() > 0) {
//            msg = allocateDirect(boxed.ciphertextLength());
            msg = allocate(boxed.ciphertextLength());
        } else {
            msg = allocateDirect(boxed.ciphertextLength() - macBytes());
        }

        _decrypt(msg, boxed);
        return msg;
    }

    public void decrypt(final ByteBuffer msg, final BoxedData boxed) {
        checkBoxed(boxed);
        checkMessage(msg);
        _decrypt(msg, boxed);
    }

    protected abstract void _decrypt(final ByteBuffer msg, final BoxedData boxed);

    protected abstract int nonceBytes();

    protected abstract int macBytes();

    protected ByteBuffer generateNonce() {
        final ByteBuffer nonce = allocateDirect(nonceBytes());
        generateNonce(nonce);
        return nonce;
    }

    protected void generateNonce(final ByteBuffer nonce) {
        sodium().randombytes(nonce, nonceBytes());
    }

    public abstract void destroy();

    protected void checkBoxed(final BoxedData boxed) {
        checkLengthIsGreaterThan(boxed.getCiphertext(), 0, "ciphertext");
        checkLength(boxed.getNonce(), nonceBytes(), "nonce");
        if (boxed.macLength() > 0)
            checkLength(boxed.getMac(), macBytes(), "mac");
    }

    protected void checkMessage(final ByteBuffer message) {
        checkLengthIsGreaterThan(message, 0, "message");
    }
}
