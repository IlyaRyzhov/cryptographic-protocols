package mutualAuthenticationProtocol;

import encryptionAlgorithm.Twofish;
import encryptionModes.Cipher;
import randomNumberGenerator.RandomNumberGenerator;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;

import static encryptionModes.EncryptionMode.ECB;
import static encryptionModes.EncryptionMode.OFB;
import static mutualAuthenticationProtocol.TrustedServer.registerUser;
import static mutualAuthenticationProtocol.UserRole.INITIATOR;
import static mutualAuthenticationProtocol.UserRole.PRETENDER;
import static Utils.CommonUtils.convertByteArrayToLong;
import static Utils.CommonUtils.convertByteArrayToLongArray;
import static Utils.TransmissionChannelUtils.readMessageFromTransmissionChannel;
import static Utils.TransmissionChannelUtils.writeMessageToTransmissionChannel;

public class UserOfNeedhamSchroederProtocol extends UserOfTransmissionProtocol {
    private final Cipher cipherWithUserKeyOFB;
    private final Cipher cipherWithUserKeyECB;
    private byte[] identifier;

    public UserOfNeedhamSchroederProtocol(String name, byte[] userKey, UserRole userRole) {
        super(name, userKey, userRole);
        Twofish twofishWithUserKey = new Twofish(convertByteArrayToLongArray(userKey));
        cipherWithUserKeyOFB = new Cipher(twofishWithUserKey, OFB, 2, twofishWithUserKey.getBlockSizeInBytes());
        cipherWithUserKeyECB = new Cipher(twofishWithUserKey, ECB);
        registerUser(name, userKey);
    }

    /**
     * @see AuthenticationProtocolAbstract
     */
    @Override
    public void authenticatePretender(UserOfTransmissionProtocol pretender) {
        if (userRole == INITIATOR) {
            NeedhamSchroederProtocol needhamSchroederProtocol = new NeedhamSchroederProtocol();
            while (true) {
                boolean authenticationResult = needhamSchroederProtocol.authenticateTwoUsers(this, pretender);
                if (authenticationResult)
                    break;
            }
        }
    }

    /**
     * Отправляет вектор инициализации в канал
     *
     * @author Ilya Ryzhov
     */
    public void sendInitializationVector() {
        writeMessageToTransmissionChannel(cipherWithUserKeyOFB.getEncryptionAlgorithmWithMode().getInitializationVector());
    }

    /**
     * Отправляет запрос доверенному серверу на получение сессионного ключа
     *
     * @param pretenderUserName имя второго пользователя
     * @author Ilya Ryzhov
     */
    public void sendRequestForSessionKey(String pretenderUserName) {
        RandomNumberGenerator randomNumberGenerator = new RandomNumberGenerator();
        identifier = randomNumberGenerator.generateRandomBytes(8);
        byte[] initiatorUserNameBytes = name.getBytes(StandardCharsets.UTF_8);
        byte[] pretenderUserNameBytes = pretenderUserName.getBytes(StandardCharsets.UTF_8);
        byte[] message = Arrays.copyOf(initiatorUserNameBytes, initiatorUserNameBytes.length + pretenderUserNameBytes.length + 8);
        System.arraycopy(pretenderUserNameBytes, 0, message, initiatorUserNameBytes.length, pretenderUserNameBytes.length);
        System.arraycopy(identifier, 0, message, pretenderUserNameBytes.length + initiatorUserNameBytes.length, 8);
        writeMessageToTransmissionChannel(cipherWithUserKeyOFB.encryptMessage(message));
    }

    /**
     * Проверяет ответ сервера: сверяет идентификатор и имя второго пользователя
     *
     * @param pretenderUserName имя второго пользователя
     * @return true- если проверка прошла успешно, false- в противном случае
     * @author Ilya Ryzhov
     */
    public boolean verifyTrustedServerResponse(String pretenderUserName) {
        byte[] encryptedMessage = readMessageFromTransmissionChannel();
        byte[] messageWithInitiatorIdentifier = cipherWithUserKeyECB.decryptMessage(encryptedMessage);
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
    public boolean getSessionKeyFromMessage(byte[] responseMessage, String anotherUserName) {
        byte[] decryptedMessage = cipherWithUserKeyECB.decryptMessage(responseMessage);
        int currentUserNameBytesLength = name.getBytes(StandardCharsets.UTF_8).length;
        int anotherUserNameBytesLength = anotherUserName.getBytes(StandardCharsets.UTF_8).length;
        byte[] encryptedSessionKey = Arrays.copyOfRange(decryptedMessage, anotherUserNameBytesLength + currentUserNameBytesLength + 8, decryptedMessage.length);
        sessionKey = cipherWithUserKeyECB.decryptMessage(encryptedSessionKey);
        if (userRole == PRETENDER) {
            boolean initiatorNameCheck = Arrays.equals(anotherUserName.getBytes(StandardCharsets.UTF_8),
                    Arrays.copyOfRange(decryptedMessage, 8, 8 + anotherUserNameBytesLength));
            long timeLabel = convertByteArrayToLong(Arrays.copyOf(decryptedMessage, 8));
            return timeLabelCheck(timeLabel, 1000, 1000) & initiatorNameCheck;
        }
        return true;
    }
}
