package Lab7MutualAuthenticationProtocol;

import Lab1EncryptionAlgorithm.TwoFish;
import Lab4EncryptionModes.Cipher;
import Lab4EncryptionModes.EncryptionMode;
import Lab5RandomNumberGenerator.RandomNumberGenerator;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;

import static Lab4EncryptionModes.EncryptionMode.ECB;
import static Lab7MutualAuthenticationProtocol.TransmissionChannel.readMessageFromTransmissionChannel;
import static Lab7MutualAuthenticationProtocol.TransmissionChannel.writeMessageToTransmissionChannel;
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

    /**
     * Отправляет запрос доверенному серверу на получение сессионного ключа
     *
     * @param secondUserName имя второго пользователя
     * @author Ilya Ryzhov
     */
    public void sendRequestForSessionKey(String secondUserName) {
        RandomNumberGenerator randomNumberGenerator = new RandomNumberGenerator();
        identifier = randomNumberGenerator.generateRandomBytes(8);
        byte[] initiatorUserNameBytes = name.getBytes(StandardCharsets.UTF_8);
        byte[] secondUserNameBytes = secondUserName.getBytes(StandardCharsets.UTF_8);
        byte[] message = Arrays.copyOf(initiatorUserNameBytes, initiatorUserNameBytes.length + secondUserNameBytes.length + 8);
        System.arraycopy(secondUserNameBytes, 0, message, initiatorUserNameBytes.length, secondUserNameBytes.length);
        System.arraycopy(identifier, 0, message, secondUserNameBytes.length + initiatorUserNameBytes.length, 8);
        writeMessageToTransmissionChannel(cipherWithUserKey.encryptMessage(message));
    }

    /**
     * Проверяет ответ сервера: сверяет идентификатор и имя второго пользователя
     *
     * @param secondUserName имя второго пользователя
     * @return true- если проверка прошла успешно, false- в противном случае
     * @author Ilya Ryzhov
     */
    public boolean verifyTrustedServerResponse(String secondUserName) {
        byte[] encryptedMessage = readMessageFromTransmissionChannel();
        byte[] messageWithInitiatorIdentifier = cipherWithUserKey.decryptMessage(encryptedMessage);
        byte[] responseIdentifier = Arrays.copyOf(messageWithInitiatorIdentifier, 8);
        byte[] initiatorUserNameBytes = name.getBytes(StandardCharsets.UTF_8);
        byte[] secondUserNameBytes = secondUserName.getBytes(StandardCharsets.UTF_8);
        byte[] responseSecondUserName = new byte[secondUserNameBytes.length];
        System.arraycopy(messageWithInitiatorIdentifier, 8 + initiatorUserNameBytes.length, responseSecondUserName, 0, responseSecondUserName.length);
        boolean secondUserNameCheck = Arrays.equals(secondUserNameBytes, responseSecondUserName);
        boolean identifierCheck = Arrays.equals(identifier, responseIdentifier);
        boolean verificationResult = identifierCheck & secondUserNameCheck;
        if (verificationResult)
            getSessionKeyFromMessage(encryptedMessage, secondUserName);
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
    public boolean getSessionKeyFromMessage(byte[] responseMessage, String anotherUserName) {
        byte[] decryptedMessage = cipherWithUserKey.decryptMessage(responseMessage);
        int currentUserNameBytesLength = name.getBytes(StandardCharsets.UTF_8).length;
        int anotherUserNameBytesLength = anotherUserName.getBytes(StandardCharsets.UTF_8).length;
        byte[] encryptedSessionKey = Arrays.copyOfRange(decryptedMessage, anotherUserNameBytesLength + currentUserNameBytesLength + 8, decryptedMessage.length);
        sessionKey = cipherWithUserKey.decryptMessage(encryptedSessionKey);
        if (userRole == SECOND_USER) {
            boolean initiatorNameCheck = Arrays.equals(anotherUserName.getBytes(StandardCharsets.UTF_8),
                    Arrays.copyOfRange(decryptedMessage, 8, 8 + anotherUserNameBytesLength));
            long timeLabel = convertByteArrayToLong(Arrays.copyOf(decryptedMessage, 8));
            return timeLabelCheck(timeLabel, 1000, 1000) & initiatorNameCheck;
        }
        return true;
    }

    /**
     * Шифрует сообщение на сессионном ключе
     *
     * @param message                  шифруемое сообщение
     * @param encryptionMode           режим шифрования
     * @param encryptionModeParameters параметры, необходимые для режима
     * @return зашифрованное сообщение
     * @author Ilya Ryzhov
     */
    public byte[] encryptMessageWithSessionKey(byte[] message, EncryptionMode encryptionMode, int... encryptionModeParameters) {
        cipherWithSessionKey = new Cipher(new TwoFish(convertByteArrayToLongArray(sessionKey)), encryptionMode, encryptionModeParameters);
        return cipherWithSessionKey.encryptMessage(message);
    }

    /**
     * Расшифровывает сообщение с использованием сессионного ключа
     *
     * @param message                  расшифровываемое сообщение
     * @param encryptionMode           режим шифрования
     * @param encryptionModeParameters параметры, необходимые для режима
     * @return расшифрованное сообщение
     * @author Ilya Ryzhov
     */
    public byte[] decryptMessageWithSessionKey(byte[] message, EncryptionMode encryptionMode, int... encryptionModeParameters) {
        cipherWithSessionKey = new Cipher(new TwoFish(convertByteArrayToLongArray(sessionKey)), encryptionMode, encryptionModeParameters);
        return cipherWithSessionKey.decryptMessage(message);
    }

    /**
     * Меняет роль пользователя с инициатора на второго пользователя и наоборот
     *
     * @author Ilya Ryzhov
     */
    public void changeRole() {
        if (userRole == INITIATOR)
            userRole = SECOND_USER;
        else userRole = INITIATOR;
    }

    /**
     * Возвращает имя пользователя
     *
     * @return имя пользователя
     * @author Ilya Ryzhov
     */
    public String getName() {
        return name;
    }

    /**
     * Возвращает ключ пользователя
     *
     * @return ключ пользователя
     * @author Ilya Ryzhov
     */
    public byte[] getUserKey() {
        return userKey;
    }

    /**
     * Возвращает текущую роль пользователя
     *
     * @return текущая роль пользователя
     * @author Ilya Ryzhov
     */
    public UserRole getUserRole() {
        return userRole;
    }
}
