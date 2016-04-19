package org.abstractj.kalium.nio;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

import static org.abstractj.kalium.NaCl.Sodium.CRYPTO_BOX_PUBLICKEYBYTES;
import static org.abstractj.kalium.NaCl.Sodium.CRYPTO_BOX_SECRETKEYBYTES;
import static org.abstractj.kalium.NaCl.Sodium.CRYPTO_SECRETBOX_KEYBYTES;
import static org.abstractj.kalium.NaCl.sodium;

public class Keys {

    public interface KeyReader {
        ByteBuffer read() throws IOException;
    }

    public interface KeyWriter {
        void write(ByteBuffer key) throws IOException;
    }

    public static class FileSystemKeyReaderWriter implements KeyReader, KeyWriter {

        private final Path keyPath;

        public FileSystemKeyReaderWriter(Path keyPath) {
            this.keyPath = keyPath;
        }

        @Override
        public ByteBuffer read() throws IOException {
            FileChannel fc = FileChannel.open(keyPath, StandardOpenOption.READ);
            return fc.map(FileChannel.MapMode.READ_ONLY, 0, fc.size());
        }

        @Override
        public void write(ByteBuffer key) throws IOException {
            FileChannel fc = FileChannel.open(keyPath, StandardOpenOption.WRITE);
            fc.write(key);
            fc.close();
        }

    }

    public static class Pair {
        public final ByteBuffer publicKey;
        public final ByteBuffer secretKey;

        public Pair(ByteBuffer publicKey, ByteBuffer secretKey) {
            this.publicKey = publicKey;
            this.secretKey = secretKey;
        }
    }

    public static Pair newBoxKeypair() {
        final Pair keys = new Pair(
                ByteBuffer.allocateDirect(CRYPTO_BOX_PUBLICKEYBYTES),
                ByteBuffer.allocateDirect(CRYPTO_BOX_SECRETKEYBYTES));

        sodium().crypto_box_keypair(keys.publicKey, keys.secretKey);

        return keys;
    }

    public static ByteBuffer newSecretBoxKey() {
        final ByteBuffer key =
                ByteBuffer.allocateDirect(CRYPTO_SECRETBOX_KEYBYTES);

        sodium().randombytes(key, CRYPTO_SECRETBOX_KEYBYTES);

        return key;
    }
}
