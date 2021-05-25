package Lab7MutualAuthenticationProtocol;

import Lab1EncryptionAlgorithm.TwoFish;
import Lab4EncryptionModes.Cipher;
import Lab4EncryptionModes.EncryptionMode;
import Lab5RandomNumberGenerator.RandomNumberGenerator;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;

import static Lab4EncryptionModes.EncryptionMode.ECB;
import static Lab7MutualAuthenticationProtocol.UserRole.INITIATOR;
import static Lab7MutualAuthenticationProtocol.UserRole.SECOND_USER;
import static Utils.CommonUtils.convertByteArrayToLong;
import static Utils.CommonUtils.convertByteArrayToLongArray;

public class User {
    private final String name;
    private final byte[] userKey;
    private final Cipher cipherWithUserKey;
    private byte[] sessionKey;
    private Cipher cipherWithSessionKey;
    private byte[] identifier;
    private UserRole userRole;

    public User(String name, byte[] userKey, UserRole userRole) {
        this.name = name;
        this.userKey = userKey;
        cipherWithUserKey = new Cipher(new TwoFish(convertByteArrayToLongArray(userKey)), ECB);
        this.userRole = userRole;
    }

    public byte[][] sendRequestForSessionKey(TrustedServer server, String secondUserName) {
        RandomNumberGenerator randomNumberGenerator = new RandomNumberGenerator();
        identifier = randomNumberGenerator.generateRandomBytes(8);
        byte[] initiatorUserNameBytes = name.getBytes(StandardCharsets.UTF_8);
        byte[] secondUserNameBytes = secondUserName.getBytes(StandardCharsets.UTF_8);
        byte[] message = Arrays.copyOf(initiatorUserNameBytes, initiatorUserNameBytes.length + secondUserNameBytes.length + 8);
        System.arraycopy(secondUserNameBytes, 0, message, initiatorUserNameBytes.length, secondUserNameBytes.length);
        System.arraycopy(identifier, 0, message, secondUserNameBytes.length + initiatorUserNameBytes.length, 8);
        return server.sendResponseForSessionKey(this, cipherWithUserKey.encryptMessage(message));
    }

    public boolean verifyTrustedServerResponse(byte[][] response, String secondUserName) {
        byte[] firstResponseMessage = cipherWithUserKey.decryptMessage(response[0]);
        byte[] responseIdentifier = Arrays.copyOf(firstResponseMessage, 8);
        byte[] initiatorUserNameBytes = name.getBytes(StandardCharsets.UTF_8);
        byte[] secondUserNameBytes = secondUserName.getBytes(StandardCharsets.UTF_8);
        byte[] responseInitiatorName = new byte[initiatorUserNameBytes.length];
        System.arraycopy(firstResponseMessage, 8, responseInitiatorName, 0, responseInitiatorName.length);
        byte[] responseSecondUserName = new byte[secondUserNameBytes.length];
        System.arraycopy(firstResponseMessage, 8 + initiatorUserNameBytes.length, responseSecondUserName, 0, responseSecondUserName.length);
        boolean initiatorNameCheck = Arrays.equals(initiatorUserNameBytes, responseInitiatorName);
        boolean secondUserNameCheck = Arrays.equals(secondUserNameBytes, responseSecondUserName);
        boolean identifierCheck = Arrays.equals(identifier, responseIdentifier);
        return identifierCheck & secondUserNameCheck & initiatorNameCheck;
    }

    private boolean timeLabelCheck(long timeLabel, long allowableServerResponseTime, long allowableInitiatorMessageDeliveryTime) {
        return Duration.ofMillis(Math.abs(System.currentTimeMillis() - timeLabel))
                .minus(Duration.ofMillis(allowableInitiatorMessageDeliveryTime + allowableServerResponseTime))
                .isNegative();
    }

    public boolean getSessionKey(byte[] responseMessage, String anotherUserName) {
        byte[] decryptedMessage = cipherWithUserKey.decryptMessage(responseMessage);
        int anotherUserNameBytesLength = anotherUserName.getBytes(StandardCharsets.UTF_8).length;
        int currentUserNameBytesLength = name.getBytes(StandardCharsets.UTF_8).length;
        byte[] encryptedSessionKey = Arrays.copyOfRange(decryptedMessage, anotherUserNameBytesLength + currentUserNameBytesLength + 8, decryptedMessage.length);
        sessionKey = cipherWithUserKey.decryptMessage(encryptedSessionKey);
        if (userRole == SECOND_USER) {
            long timeLabel = convertByteArrayToLong(Arrays.copyOf(decryptedMessage, 8));
            return timeLabelCheck(timeLabel, 1000, 1000);
        }
        return true;
    }

    public byte[] encryptMessageWithSessionKey(byte[] message, EncryptionMode encryptionMode, int... encryptionModeParameters) {
        cipherWithSessionKey = new Cipher(new TwoFish(convertByteArrayToLongArray(sessionKey)), encryptionMode, encryptionModeParameters);
        return cipherWithSessionKey.encryptMessage(message);
    }

    public byte[] decryptMessageWithSessionKey(byte[] message, EncryptionMode encryptionMode, int... encryptionModeParameters) {
        cipherWithSessionKey = new Cipher(new TwoFish(convertByteArrayToLongArray(sessionKey)), encryptionMode, encryptionModeParameters);
        return cipherWithSessionKey.decryptMessage(message);
    }

    public void changeRole() {
        if (userRole == INITIATOR)
            userRole = SECOND_USER;
        else userRole = INITIATOR;
    }

    public String getName() {
        return name;
    }

    public byte[] getUserKey() {
        return userKey;
    }

    public UserRole getUserRole() {
        return userRole;
    }
}
