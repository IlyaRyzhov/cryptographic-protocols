package Lab7MutualAuthenticationProtocol;

import Lab1EncryptionAlgorithm.TwoFish;
import Lab2HashAlgorithm.BlueMidnightWish;
import Lab3DigitalSignatureAlgorithm.BonehLynnShachamSignature;
import Lab4EncryptionModes.Cipher;
import Lab4EncryptionModes.EncryptionMode;

import java.util.Arrays;

import static Lab2HashAlgorithm.BlueMidnightWishDigestSize.BLUE_MIDNIGHT_WISH_512;
import static Lab4EncryptionModes.EncryptionMode.MGM;
import static Lab7MutualAuthenticationProtocol.UserRole.INITIATOR;
import static Lab7MutualAuthenticationProtocol.UserRole.PRETENDER;
import static Utils.CommonUtils.convertByteArrayToLongArray;
import static Utils.EncryptionModesUtils.incrementCounter;
import static Utils.TransmissionChannelUtils.readMessageFromTransmissionChannel;
import static Utils.TransmissionChannelUtils.writeMessageToTransmissionChannel;

public abstract class UserOfTransmissionProtocol {
    public final String name;
    public UserRole userRole;
    protected final byte[] userKey;
    protected byte[] sessionKey;
    private Cipher cipherWithSessionKey;
    private byte[] receivedMessage;
    private byte[] receivedSignature;
    private byte[] initializationVector;
    private final int signatureLengthInBytes;
    private final BonehLynnShachamSignature bonehLynnShachamSignatureWithUserKey;

    public UserOfTransmissionProtocol(String name, byte[] userKey, UserRole userRole) {
        this.name = name;
        this.userKey = userKey;
        this.userRole = userRole;
        this.bonehLynnShachamSignatureWithUserKey = new BonehLynnShachamSignature(userKey, new BlueMidnightWish(BLUE_MIDNIGHT_WISH_512));
        this.signatureLengthInBytes = bonehLynnShachamSignatureWithUserKey.getSignatureLengthInBytes();
    }

    /**
     * Проводит процесс аутентификации с желаемым пользователем
     *
     * @author Ilya Ryzhov
     */
    public abstract void authenticatePretender(UserOfTransmissionProtocol pretender);

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
        return new Cipher(new TwoFish(convertByteArrayToLongArray(sessionKey)), encryptionMode, encryptionModeParameters).encryptMessage(message);
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
        return new Cipher(new TwoFish(convertByteArrayToLongArray(sessionKey)), encryptionMode, encryptionModeParameters).decryptMessage(message);
    }

    /**
     * Шифрует сообщение на сессионном ключе
     *
     * @param message шифруемое сообщение
     * @return зашифрованное сообщение
     * @author Ilya Ryzhov
     */
    public byte[] encryptMessageWithSessionKey(byte[] message) {
        byte[] encryptedMessage = cipherWithSessionKey.encryptMessage(message);
        incrementInitializationVector();
        return encryptedMessage;
    }

    /**
     * Расшифровывает сообщение с использованием сессионного ключа
     *
     * @param message расшифровываемое сообщение
     * @return расшифрованное сообщение
     * @author Ilya Ryzhov
     */
    public byte[] decryptMessageWithSessionKey(byte[] message) {
        byte[] decryptedMessage = cipherWithSessionKey.decryptMessage(message);
        incrementInitializationVector();
        return decryptedMessage;
    }

    private void incrementInitializationVector() {
        incrementCounter(cipherWithSessionKey.getEncryptionAlgorithmWithMode().getInitializationVector());
    }

    /**
     * Меняет роль пользователя с инициатора на второго пользователя и наоборот
     *
     * @author Ilya Ryzhov
     */
    public void changeRole() {
        if (userRole == INITIATOR)
            userRole = PRETENDER;
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
     * Возвращает текущую роль пользователя
     *
     * @return текущая роль пользователя
     * @author Ilya Ryzhov
     */
    public UserRole getUserRole() {
        return userRole;
    }

    /**
     * Отправляет сообщение в канал передачи
     *
     * @param message отправляемое сообщение
     * @author Ilya Ryzhov
     */
    public void sendMessage(byte[] message) {
        writeMessageToTransmissionChannel(message);
    }

    /**
     * Читает сообщение из канала и записывает в поле receivedMessage
     *
     * @author Ilya Ryzhov
     */
    public void receiveMessage() {
        receivedMessage = readMessageFromTransmissionChannel();
    }

    /**
     * Записывает в поле receivedSignature подпись сообщения пулученного из канала сообщения
     *
     * @author Ilya Ryzhov
     */
    public void getSignatureFromReceivedMessage() {
        receivedSignature = Arrays.copyOf(receivedMessage, signatureLengthInBytes);
    }

    /**
     * Возвращает подпись, последнего полученного сообщения
     *
     * @return подпись сообщения
     * @author Ilya Ryzhov
     */
    public byte[] getReceivedSignature() {
        return receivedSignature;
    }

    /**
     * Возвращает последнее полученное сообщение
     *
     * @return последнее полученное сообщение
     * @author Ilya Ryzhov
     */
    public byte[] getReceivedMessage() {
        return receivedMessage;
    }

    /**
     * Изменяет последнее полученное сообщение
     *
     * @param receivedMessage новое последнее полученное сообщение
     * @author Ilya Ryzhov
     */
    public void setReceivedMessage(byte[] receivedMessage) {
        this.receivedMessage = receivedMessage;
    }

    /**
     * Возвращает используемую реализацию цифровой подписи
     *
     * @return используемая реализация цифровой подписи(BLS)
     * @author Ilya Ryzhov
     */
    public BonehLynnShachamSignature getBonehLynnShachamSignatureWithUserKey() {
        return bonehLynnShachamSignatureWithUserKey;
    }

    /**
     * Вычисляет вектор инициализации из полученного сообщения и записывает в поле initializationVector,
     * если подпись вектора инициализации совпадает
     *
     * @param senderPublicKey открытый ключ отправителя сообщения
     * @return true если подпись совпадает, false в противном случае
     * @author Ilya Ryzhov
     */
    public boolean getInitializationVectorFromReceivedMessage(byte[] senderPublicKey) {
        byte[] initializationVector = Arrays.copyOfRange(receivedMessage, signatureLengthInBytes, receivedMessage.length);
        boolean signatureVerificationResult = bonehLynnShachamSignatureWithUserKey.verifySignature(initializationVector, receivedSignature, senderPublicKey);
        if (signatureVerificationResult) {
            this.initializationVector = initializationVector;
            return true;
        } else return false;
    }

    /**
     * Вычленяет самое сообщение из полученного сообщения(убирает из него подпись) и записывает в поле receivedMessage,
     * если подпись сообщения совпадает
     *
     * @param senderPublicKey открытый ключ отправителя сообщения
     * @return true если подпись совпадает, false в противном случае
     * @author Ilya Ryzhov
     */
    public boolean getMessageFromReceivedMessage(byte[] senderPublicKey) {
        byte[] message = Arrays.copyOfRange(receivedMessage, signatureLengthInBytes, receivedMessage.length);
        boolean signatureVerificationResult = bonehLynnShachamSignatureWithUserKey.verifySignature(message, receivedSignature, senderPublicKey);
        if (signatureVerificationResult) {
            this.receivedMessage = message;
            return true;
        } else return false;
    }

    /**
     * Устанавливает вектор инициализации, используемый в cipherWithSessionKey
     *
     * @param initializationVector новый вектор инициализации
     * @author Ilya Ryzhov
     */
    public void setInitializationVector(byte[] initializationVector) {
        this.initializationVector = initializationVector;
    }

    /**
     * Инициализирует cipherWithSessionKey
     *
     * @author Ilya Ryzhov
     */
    public void initializeCipherWithSessionKey() {
        cipherWithSessionKey = new Cipher(new TwoFish(convertByteArrayToLongArray(sessionKey)), MGM,
                initializationVector.length, bonehLynnShachamSignatureWithUserKey.getSignatureLengthInBytes());
        cipherWithSessionKey.getEncryptionAlgorithmWithMode().setInitializationVector(initializationVector);
    }

    /**
     * Возвращает вектор инициализации, используемый в cipherWithSessionKey
     *
     * @return вектор инициализации
     * @author Ilya Ryzhov
     */
    public byte[] getInitializationVector() {
        return initializationVector;
    }
}
