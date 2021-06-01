package Lab7MutualAuthenticationProtocol;

import Lab1EncryptionAlgorithm.TwoFish;
import Lab4EncryptionModes.Cipher;
import Lab5RandomNumberGenerator.RandomNumberGenerator;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;

import static Lab4EncryptionModes.EncryptionMode.ECB;
import static Utils.TransmissionChannelUtils.readMessageFromTransmissionChannel;
import static Utils.TransmissionChannelUtils.writeMessageToTransmissionChannel;
import static Lab7MutualAuthenticationProtocol.TrustedServer.registerUser;
import static Lab7MutualAuthenticationProtocol.UserRole.PRETENDER;
import static Utils.CommonUtils.convertByteArrayToLong;
import static Utils.CommonUtils.convertByteArrayToLongArray;

public class UserOfProtocolWithTrustedServer extends UserOfTransmissionProtocol {
    private final Cipher cipherWithUserKey;
    private byte[] identifier;

    public UserOfProtocolWithTrustedServer(String name, byte[] userKey, UserRole userRole) {
        super(name, userKey, userRole);
        cipherWithUserKey = new Cipher(new TwoFish(convertByteArrayToLongArray(userKey)), ECB);
        registerUser(name, userKey);
    }

    @Override
    public void authenticatePretender(UserOfTransmissionProtocol pretender) {
        NeedhamSchroederProtocol needhamSchroederProtocol = new NeedhamSchroederProtocol();
        for (int i = 0; i < 10; i++) {
            boolean authenticationResult = needhamSchroederProtocol.authenticateTwoUsers(this, pretender);
            if (authenticationResult)
                break;
        }
    }

    /**
     * Отправляет запрос доверенному серверу на получение сессионного ключа
     *
     * @param pretenderUserName имя второго пользователя
     * @author Ilya Ryzhov
     */
    void sendRequestForSessionKey(String pretenderUserName) {
        RandomNumberGenerator randomNumberGenerator = new RandomNumberGenerator();
        identifier = randomNumberGenerator.generateRandomBytes(8);
        byte[] initiatorUserNameBytes = name.getBytes(StandardCharsets.UTF_8);
        byte[] pretenderUserNameBytes = pretenderUserName.getBytes(StandardCharsets.UTF_8);
        byte[] message = Arrays.copyOf(initiatorUserNameBytes, initiatorUserNameBytes.length + pretenderUserNameBytes.length + 8);
        System.arraycopy(pretenderUserNameBytes, 0, message, initiatorUserNameBytes.length, pretenderUserNameBytes.length);
        System.arraycopy(identifier, 0, message, pretenderUserNameBytes.length + initiatorUserNameBytes.length, 8);
        writeMessageToTransmissionChannel(cipherWithUserKey.encryptMessage(message));
    }

    /**
     * Проверяет ответ сервера: сверяет идентификатор и имя второго пользователя
     *
     * @param pretenderUserName имя второго пользователя
     * @return true- если проверка прошла успешно, false- в противном случае
     * @author Ilya Ryzhov
     */
    boolean verifyTrustedServerResponse(String pretenderUserName) {
        byte[] encryptedMessage = readMessageFromTransmissionChannel();
        byte[] messageWithInitiatorIdentifier = cipherWithUserKey.decryptMessage(encryptedMessage);
        byte[] responseIdentifier = Arrays.copyOf(messageWithInitiatorIdentifier, 8);
        byte[] initiatorUserNameBytes = name.getBytes(StandardCharsets.UTF_8);
        byte[] pretenderUserNameBytes = pretenderUserName.getBytes(StandardCharsets.UTF_8);
        byte[] responsePretenderUserName = new byte[pretenderUserNameBytes.length];
        System.arraycopy(messageWithInitiatorIdentifier, 8 + initiatorUserNameBytes.length, responsePretenderUserName, 0, responsePretenderUserName.length);
        boolean pretenderUserNameCheck = Arrays.equals(pretenderUserNameBytes, responsePretenderUserName);
        boolean identifierCheck = Arrays.equals(identifier, responseIdentifier);
        boolean verificationResult = identifierCheck & pretenderUserNameCheck;
        if (verificationResult)
            getSessionKeyFromMessage(encryptedMessage, pretenderUserName);
        return verificationResult;
    }

    private boolean timeLabelCheck(long timeLabel, long allowableServerResponseTime, long allowableInitiatorMessageDeliveryTime) {
        return Duration.ofMillis(Math.abs(System.currentTimeMillis() - timeLabel))
                .minus(Duration.ofMillis(allowableInitiatorMessageDeliveryTime + allowableServerResponseTime))
                .isNegative();
    }

    /**
     * Получает сессионный ключ из сообщения
     *
     * @param responseMessage зашифрованное сообщение, из которого нужно получить сессионный ключ
     * @param anotherUserName имя другого субъкта обмена данными
     * @return true- если ключ был получен успешно, false- в противном случае
     * @author Ilya Ryzhov
     */
    boolean getSessionKeyFromMessage(byte[] responseMessage, String anotherUserName) {
        byte[] decryptedMessage = cipherWithUserKey.decryptMessage(responseMessage);
        int currentUserNameBytesLength = name.getBytes(StandardCharsets.UTF_8).length;
        int anotherUserNameBytesLength = anotherUserName.getBytes(StandardCharsets.UTF_8).length;
        byte[] encryptedSessionKey = Arrays.copyOfRange(decryptedMessage, anotherUserNameBytesLength + currentUserNameBytesLength + 8, decryptedMessage.length);
        sessionKey = cipherWithUserKey.decryptMessage(encryptedSessionKey);
        if (userRole == PRETENDER) {
            boolean initiatorNameCheck = Arrays.equals(anotherUserName.getBytes(StandardCharsets.UTF_8),
                    Arrays.copyOfRange(decryptedMessage, 8, 8 + anotherUserNameBytesLength));
            long timeLabel = convertByteArrayToLong(Arrays.copyOf(decryptedMessage, 8));
            return timeLabelCheck(timeLabel, 1000, 1000) & initiatorNameCheck;
        }
        return true;
    }
}
