package org.abstractj.kalium.nio;

import org.junit.Test;

import java.nio.ByteBuffer;

public class SimpleSealedBoxTest {
    @Test
    public void testName() throws Exception {
        Keys.Pair pair = Keys.newBoxKeypair();

        SimpleBox b = SimpleBox.newSealedBox(pair.publicKey, pair.secretKey);
        ByteBuffer m = ByteBuffer.wrap("This is the message.".getBytes());

        BoxedData bd = b.encrypt(m);
        b.decrypt(bd);
    }
}
