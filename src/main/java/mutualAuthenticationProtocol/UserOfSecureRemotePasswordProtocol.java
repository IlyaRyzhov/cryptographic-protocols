package mutualAuthenticationProtocol;

import randomNumberGenerator.RandomNumberGenerator;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static mutualAuthenticationProtocol.UserRole.INITIATOR;
import static Utils.CommonUtils.concatenateByteArrays;
import static Utils.EncryptionModesUtils.xorByteArrays;
import static Utils.TransmissionChannelUtils.readMessageFromTransmissionChannel;
import static Utils.TransmissionChannelUtils.writeMessageToTransmissionChannel;
import static mutualAuthenticationProtocol.SecureRemotePasswordProtocol.*;

public class UserOfSecureRemotePasswordProtocol extends UserOfTransmissionProtocol {
    private byte[] userSecretKey;
    private final Map<String, List<byte[]>> namePasswordVerifierMap;
    private final Set<String> pretenderNames;
    private BigInteger initiatorIdentifier;
    private BigInteger pretenderIdentifier;
    private byte[] randomIdentifier;

    public UserOfSecureRemotePasswordProtocol(String name, byte[] userKey, UserRole userRole) {
        super(name, userKey, userRole);
        namePasswordVerifierMap = new LinkedHashMap<>();
        pretenderNames = new LinkedHashSet<>();
    }

    /**
     * @see AuthenticationProtocolAbstract
     */
    @Override
    public void authenticatePretender(UserOfTransmissionProtocol pretender) {
        if (userRole == INITIATOR) {
            SecureRemotePasswordProtocol secureRemotePasswordProtocol = new SecureRemotePasswordProtocol();
            while (true) {
                boolean authenticationResult = secureRemotePasswordProtocol.authenticateTwoUsers(this, pretender);
                if (authenticationResult)
                    break;
            }
        }
    }

    /**
     * Отправляет имя пользователя в канал передачи
     *
     * @author Ilya Ryzhov
     */
    public void sendUserName() {
        writeMessageToTransmissionChannel(name.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Отправляет соль в канал передачи
     *
     * @author Ilya Ryzhov
     */
    public void sendSalt() {
        byte[] salt = new RandomNumberGenerator().generateRandomBytes(64);
        userSecretKey = getUserSecretKey(salt, userKey);
        writeMessageToTransmissionChannel(salt);
    }

    /**
     * Отправляет верификатор пароля в канал передачи
     *
     * @author Ilya Ryzhov
     */
    public void sendPasswordVerifier() {
        BigInteger passwordVerifier = generatingElement.modPow(new BigInteger(1, userSecretKey).mod(groupModule), groupModule);
        writeMessageToTransmissionChannel(passwordVerifier.toByteArray());
    }

    /**
     * Считывает соль из канала передачи и сопоставляет ее отправителю
     *
     * @param senderName имя отправителя
     * @author Ilya Ryzhov
     */
    public void addSaltFromChannel(String senderName) {
        byte[] salt = readMessageFromTransmissionChannel();
        namePasswordVerifierMap.computeIfAbsent(senderName, k -> new ArrayList<>());
        namePasswordVerifierMap.get(senderName).add(salt);
    }

    /**
     * Считывает имя отправителя из канала передачи
     *
     * @author Ilya Ryzhov
     */
    public void addUserNameFromChannel() {
        namePasswordVerifierMap.put(new String(readMessageFromTransmissionChannel(), StandardCharsets.UTF_8), null);
    }

    /**
     * Считывает верификатор пароля из канала передачи и сопоставляет его отправителю
     *
     * @param senderName имя отправителя
     * @author Ilya Ryzhov
     */
    public void addPasswordVerifierFromChannel(String senderName) {
        namePasswordVerifierMap.get(senderName).add(readMessageFromTransmissionChannel());
    }

    /**
     * Отправляет в канал передачи идентификатор инициатора
     *
     * @author Ilya Ryzhov
     */
    public void sendInitiatorIdentifier() {
        writeMessageToTransmissionChannel(initiatorIdentifier.toByteArray());
    }

    /**
     * Отправляет в канал передачи идентификатор аутентифицируемого пользователя
     *
     * @author Ilya Ryzhov
     */
    public void sendPretenderIdentifier() {
        writeMessageToTransmissionChannel(pretenderIdentifier.toByteArray());
    }

    /**
     * Вычисляет ключ сессии для инициатора
     *
     * @param salt     соль инициатора
     * @param password пароль инициатора
     * @author Ilya Ryzhov
     */
    public void getSessionKeyForInitiator(byte[] salt, byte[] password) {
        BigInteger uParameter = new BigInteger(1, hashFunction.computeHash(concatenateByteArrays(initiatorIdentifier.toByteArray(), pretenderIdentifier.toByteArray()))).mod(groupModule);
        BigInteger userSecretKey = new BigInteger(1, getUserSecretKey(salt, password)).mod(groupModule);
        BigInteger degree = ((new BigInteger(1, randomIdentifier).mod(groupModule)).add(uParameter.multiply(userSecretKey).mod(groupModule))).mod(groupModule);
        BigInteger generatingElementPowSecretKey = generatingElement.modPow(userSecretKey, groupModule);
        BigInteger sParameter = ((pretenderIdentifier.subtract(kParameter.multiply(generatingElementPowSecretKey).mod(groupModule))).mod(groupModule)).modPow(degree, groupModule);
        sessionKey = hashFunction.computeHash(sParameter.toByteArray());
    }

    /**
     * Вычисляет ключ сессии для аутентифицируемого пользователя
     *
     * @param initiatorName имя инициатора процесса аутентификации
     * @author Ilya Ryzhov
     */
    public void getSessionKeyForPretender(String initiatorName) {
        BigInteger uParameter = new BigInteger(1, hashFunction.computeHash(concatenateByteArrays(initiatorIdentifier.toByteArray(), pretenderIdentifier.toByteArray()))).mod(groupModule);
        BigInteger initiatorPasswordVerifier = new BigInteger(1, namePasswordVerifierMap.get(initiatorName).get(1)).mod(groupModule);
        BigInteger degree = new BigInteger(1, randomIdentifier).mod(groupModule);
        BigInteger sParameter = (initiatorIdentifier.multiply(initiatorPasswordVerifier.modPow(uParameter, groupModule)).mod(groupModule)).modPow(degree, groupModule);
        sessionKey = hashFunction.computeHash(sParameter.toByteArray());
    }

    /**
     * Вычисляет сообщение проверки ключа сессии для инициатора(отправляет инициатор)
     *
     * @param salt          соль инициатора
     * @param initiatorName имя инициатора
     * @return сообщение проверки ключа сессии для инициатора
     * @author Ilya Ryzhov
     */
    public byte[] getInitiatorKeyCheckMessage(byte[] salt, String initiatorName) {
        byte[] initiatorKeyCheckMessage = hashFunction.computeHash(groupModule.toByteArray());
        xorByteArrays(initiatorKeyCheckMessage, hashFunction.computeHash(generatingElement.toByteArray()), initiatorKeyCheckMessage.length);
        initiatorKeyCheckMessage = concatenateByteArrays(initiatorKeyCheckMessage, hashFunction.computeHash(initiatorName.getBytes(StandardCharsets.UTF_8)));
        initiatorKeyCheckMessage = concatenateByteArrays(initiatorKeyCheckMessage, salt);
        initiatorKeyCheckMessage = concatenateByteArrays(initiatorKeyCheckMessage, initiatorIdentifier.toByteArray());
        initiatorKeyCheckMessage = concatenateByteArrays(initiatorKeyCheckMessage, pretenderIdentifier.toByteArray());
        initiatorKeyCheckMessage = concatenateByteArrays(initiatorKeyCheckMessage, sessionKey);
        return hashFunction.computeHash(initiatorKeyCheckMessage);
    }

    /**
     * Вычисляет сообщение проверки ключа сессии для аутентифицируемого пользователя(отправляет аутентифицируемый пользователь)
     *
     * @param initiatorKeyCheckMessage сообщение проверки ключа сессии для инициатора
     * @return сообщение проверки ключа сессии для аутентифицируемого пользователя
     * @author Ilya Ryzhov
     */
    public byte[] getPretenderKeyCheckMessage(byte[] initiatorKeyCheckMessage) {
        return hashFunction.computeHash(concatenateByteArrays(concatenateByteArrays(initiatorIdentifier.toByteArray(), initiatorKeyCheckMessage), sessionKey));
    }

    /**
     * Вычисляет секретный ключ пользователя из соли и пароля
     *
     * @param salt     соль пользователя
     * @param password пароль пользователя
     * @return секретный ключ
     * @author Ilya Ryzhov
     */
    private byte[] getUserSecretKey(byte[] salt, byte[] password) {
        return hashFunction.computeHash(concatenateByteArrays(salt, password));
    }

    /**
     * Возвращает таблицу соответствий имен пользователя их соли и верификатору пароля
     *
     * @return таблицу соответствий имен пользователя(по сути база данных)
     * @author Ilya Ryzhov
     */
    public Map<String, List<byte[]>> getNamePasswordVerifierMap() {
        return namePasswordVerifierMap;
    }

    /**
     * Возвращает имена известных аутентифицируемых пользователей
     *
     * @return имена известных аутентифицируемых пользователей
     * @author Ilya Ryzhov
     */
    public Set<String> getPretenderNames() {
        return pretenderNames;
    }

    /**
     * Возвращает сгенерированный при прохождении процесса аутентификации идентификатор
     *
     * @return идентификатор пользователя(секретное одноразовое число)
     * @author Ilya Ryzhov
     */
    public byte[] getRandomIdentifier() {
        return randomIdentifier;
    }

    /**
     * Устанавливает идентификатор пользователя
     *
     * @param randomIdentifier идентификатор пользователя(секретное одноразовое число)
     * @author Ilya Ryzhov
     */
    public void setRandomIdentifier(byte[] randomIdentifier) {
        this.randomIdentifier = randomIdentifier;
    }

    /**
     * Устанавливает идентификатор инициатора
     *
     * @param initiatorIdentifier идентификатор инициатора
     * @author Ilya Ryzhov
     */
    public void setInitiatorIdentifier(BigInteger initiatorIdentifier) {
        this.initiatorIdentifier = initiatorIdentifier;
    }

    /**
     * Устанавливает идентификатор аутентифицируемого пользователя
     *
     * @param pretenderIdentifier идентификатор аутентифицируемого пользователя
     * @author Ilya Ryzhov
     */
    public void setPretenderIdentifier(BigInteger pretenderIdentifier) {
        this.pretenderIdentifier = pretenderIdentifier;
    }
}
