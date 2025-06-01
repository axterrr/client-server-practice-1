package ua.edu.ukma.clientserver;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import ua.edu.ukma.clientserver.model.Credentials;
import ua.edu.ukma.clientserver.model.MessageInfo;
import ua.edu.ukma.clientserver.util.CRC16;

import javax.crypto.Cipher;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.Key;

public class Client {

    private static int clientCounter = 0;
    private final ObjectMapper objectMapper;
    private final Cipher cipher;
    private final int clientNumber;
    private long messageCounter;

    @SneakyThrows
    public Client(Key secretKey) {
        objectMapper = new ObjectMapper();
        clientNumber = clientCounter++;
        messageCounter = 0;
        cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
    }

    public byte[] encode(MessageInfo messageInfo) {
        messageInfo.setClientNumber(clientNumber);
        messageInfo.setMessageNumber(messageCounter++);

        byte[] dataBytes = encryptData(messageInfo.getCredentials());
        int messageSize = dataBytes.length + 8;
        int packageSize = messageSize + 21;

        ByteBuffer buffer = ByteBuffer.allocate(packageSize).order(ByteOrder.BIG_ENDIAN);
        buffer.put((byte) 0x13)
                .putInt(messageInfo.getClientNumber())
                .putLong(messageInfo.getMessageNumber())
                .putInt(packageSize)
                .putShort(CRC16.calculate(buffer.array(), 0, 17))
                .putInt(messageInfo.getTeamCode())
                .putInt(messageInfo.getUserId())
                .put(dataBytes)
                .putShort(CRC16.calculate(buffer.array(), 19, messageSize));

        return buffer.array();
    }

    @SneakyThrows
    private byte[] encryptData(Credentials credentials) {
        byte[] bytes = objectMapper.writeValueAsBytes(credentials);
        return cipher.doFinal(bytes);
    }
}
