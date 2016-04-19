package org.abstractj.kalium.nio;

import java.nio.ByteBuffer;

import static java.nio.ByteBuffer.wrap;
import static org.abstractj.kalium.crypto.Util.zeroBuffer;

public class BoxedData {
    private final ByteBuffer nonce;
    private final ByteBuffer ciphertext;
    private final ByteBuffer mac;

    public BoxedData(final ByteBuffer nonce, final ByteBuffer ciphertext, final ByteBuffer mac) {
        this.nonce = nonce;
        this.ciphertext = ciphertext;
        this.mac = mac;
    }

    public static BoxedData fromArrays(final byte[] nonce, final byte[] ciphertext, final byte[] mac) {
        return new BoxedData(
                nonce != null ? wrap(nonce) : null,
                ciphertext != null ? wrap(ciphertext) : null,
                mac != null ? wrap(mac) : null);
    }

    public ByteBuffer getNonce() {
        return nonce;
    }

    public int nonceLength() {
        if (nonce == null)
            return 0;

        return nonce.limit();
    }

    public void copyNonceToArray(final byte[] array) {
        if (nonce == null)
            return;

        nonce.get(array);
        nonce.rewind();
    }

    public byte[] copyNonceToArray() {
        byte[] array = new byte[nonceLength()];
        copyNonceToArray(array);
        return array;
    }

    public ByteBuffer getCiphertext() {
        return ciphertext;
    }

    public int ciphertextLength() {
        if (ciphertext == null)
            return 0;

        return ciphertext.limit();
    }

    public void copyCiphertextToArray(final byte[] array) {
        if (ciphertext == null)
            return;

        ciphertext.get(array);
        ciphertext.rewind();
    }

    public byte[] copyCiphertextToArray() {
        byte[] array = new byte[ciphertextLength()];
        copyCiphertextToArray(array);
        return array;
    }

    public ByteBuffer getMac() {
        return mac;
    }

    public int macLength() {
        if (mac == null)
            return 0;

        return mac.limit();
    }

    public void copyMacToArray(final byte[] array) {
        if (mac == null)
            return;

        mac.get(array);
        mac.rewind();
    }

    public byte[] copyMacToArray() {
        byte[] array = new byte[macLength()];
        copyMacToArray(array);
        return array;
    }

    public void destroy() {
        if (nonce != null)
            zeroBuffer(nonce);

        if (ciphertext != null)
            zeroBuffer(ciphertext);

        if (mac != null)
            zeroBuffer(mac);
    }

}
