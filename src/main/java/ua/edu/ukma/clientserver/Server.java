package ua.edu.ukma.clientserver;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import ua.edu.ukma.clientserver.model.Credentials;
import ua.edu.ukma.clientserver.model.MessageInfo;
import ua.edu.ukma.clientserver.util.CRC16;

import javax.crypto.Cipher;
import java.nio.ByteBuffer;
import java.security.Key;

public class Server {

    private final ObjectMapper objectMapper;
    private final Cipher cipher;

    @SneakyThrows
    public Server(Key secretKey) {
        objectMapper = new ObjectMapper();
        cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
    }

    public MessageInfo decode(byte[] bytes) {
        if (bytes == null || bytes.length < 29) {
            throw new IllegalArgumentException();
        }
        ByteBuffer buffer = ByteBuffer.wrap(bytes);

        byte bMagic = buffer.get();
        if (bMagic != 0x13) {
            throw new IllegalArgumentException();
        }

        int bSrc = buffer.getInt();
        long bPktId = buffer.getLong();
        int wLen = buffer.getInt();
        short wCrc1 = buffer.getShort();
        short expectedCrc1 = CRC16.calculate(bytes, 0, 17);
        if (expectedCrc1 != wCrc1) {
            throw new IllegalArgumentException();
        }

        int cType = buffer.getInt();
        int bUserId = buffer.getInt();
        int messageSize = wLen - 21;
        int dataSize = messageSize - 8;
        byte[] dataBytes = new byte[dataSize];
        buffer.get(dataBytes);
        short wCrc2 = buffer.getShort();
        short expectedCrc2 = CRC16.calculate(bytes, 19, messageSize);
        if (expectedCrc2 != wCrc2) {
            throw new IllegalArgumentException();
        }

        Credentials credentials = decryptData(dataBytes);
        return MessageInfo.builder()
                .clientNumber(bSrc)
                .messageNumber(bPktId)
                .teamCode(cType)
                .userId(bUserId)
                .credentials(credentials)
                .build();
    }

    @SneakyThrows
    private Credentials decryptData(byte[] dataBytes) {
        byte[] data = cipher.doFinal(dataBytes);
        return objectMapper.readValue(data, Credentials.class);
    }
}
