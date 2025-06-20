package ua.edu.ukma.clientserver.model;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class MessageInfo {
    private byte clientNumber;
    private long messageNumber;
    private int teamCode;
    private int userId;
    private Credentials credentials;
}
