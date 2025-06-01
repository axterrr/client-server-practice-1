package ua.edu.ukma.clientserver;

import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import ua.edu.ukma.clientserver.model.Credentials;
import ua.edu.ukma.clientserver.model.MessageInfo;

import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Field;
import java.security.Key;
import java.util.Arrays;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

class ClientServerTest {

    private static final Key defaultKey = new SecretKeySpec(new byte[16], "AES");
    private static final byte[] defaultMessageEncoded = new byte[] {19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 90, -24, -110, 0, 0, 0, 12, 0, 0, 0, 75, -87, 19, -14, 20, 113, 5, -116, 66, 27, 0, 28, 86, -76, 44, 118, -84, 39, -36, -67, -44, -18, 87, 11, -85, 110, -117, 44, 107, -113, 93, 74, 109, 63, -96, 68, -30, 125, 2, 14, 20, -72, 62, 89, -48, -43, -121, -80, 104, -67, -62, -29, 34, -74, -52, 125, 109, -36, -44, 119, -122, -99, -51, -51, -31, -72, 93};
    private static final MessageInfo defaultMessage = MessageInfo.builder()
            .teamCode(12)
            .userId(75)
            .credentials(new Credentials("testUsername", "testPassword"))
            .build();

    private final Random random = new Random();

    @BeforeEach
    void setUp() throws NoSuchFieldException, IllegalAccessException {
        Field field = Client.class.getDeclaredField("clientCounter");
        field.setAccessible(true);
        field.set(null, (byte) 0);
    }

    @Test
    void testEncodeMessage() {
        Client client = new Client(defaultKey);
        byte[] encoded = client.encode(defaultMessage);
        assertArrayEquals(defaultMessageEncoded, encoded);
    }

    @Test
    void testDecodeMessage() {
        Server server = new Server(defaultKey);
        MessageInfo decoded = server.decode(defaultMessageEncoded);
        assertEquals(defaultMessage, decoded);
    }

    @Test
    void testServerThrowsExceptionWhenPackageWasChanged() {
        Server server = new Server(defaultKey);
        byte[] invalidEncodedMessage = Arrays.copyOf(defaultMessageEncoded, defaultMessageEncoded.length);
        int index = random.nextInt(invalidEncodedMessage.length);
        byte oldByte = invalidEncodedMessage[index];
        while (invalidEncodedMessage[index] == oldByte) {
            invalidEncodedMessage[index] = (byte) random.nextInt(-128, 128);
        }
        assertThrows(IllegalArgumentException.class, () -> server.decode(invalidEncodedMessage));
    }

    @Test
    void testPackageEncodingAndDecoding() {
        Key secretKey = generateKey();
        Server server = new Server(secretKey);
        Client client = new Client(secretKey);
        MessageInfo messageInfo = randomMessage();
        byte[] encoded = client.encode(messageInfo);
        MessageInfo decoded = server.decode(encoded);
        assertEquals(messageInfo, decoded);
    }

    @Test
    void testMessageNumberIncrease() {
        Client client = new Client(generateKey());
        MessageInfo messageInfo1 = randomMessage();
        MessageInfo messageInfo2 = randomMessage();
        client.encode(messageInfo1);
        client.encode(messageInfo2);
        assertEquals(messageInfo1.getMessageNumber() + 1, messageInfo2.getMessageNumber());
    }

    @Test
    void testClientNumberIncrease() {
        Key secretKey = generateKey();
        Client client1 = new Client(secretKey);
        Client client2 = new Client(secretKey);
        MessageInfo messageInfo1 = randomMessage();
        MessageInfo messageInfo2 = randomMessage();
        client1.encode(messageInfo1);
        client2.encode(messageInfo2);
        assertEquals(messageInfo1.getClientNumber() + 1, messageInfo2.getClientNumber());
    }

    @SneakyThrows
    private Key generateKey() {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        return keyGenerator.generateKey();
    }

    private MessageInfo randomMessage() {
        Credentials credentials = new Credentials(randomString(8), randomString(10));
        return MessageInfo.builder()
                .teamCode(random.nextInt(1000))
                .userId(random.nextInt(1000))
                .credentials(credentials)
                .build();
    }

    private String randomString(int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append((char) (Math.random() * 26 + 'a'));
        }
        return sb.toString();
    }
}
