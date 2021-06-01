package Lab7MutualAuthenticationProtocol;

import Lab1EncryptionAlgorithm.TwoFish;
import Lab2HashAlgorithm.BlueMidnightWish;
import Lab2HashAlgorithm.BlueMidnightWishDigestSize;
import Lab2HashAlgorithm.HashFunction;
import Lab4EncryptionModes.Cipher;
import Lab5RandomNumberGenerator.RandomNumberGenerator;
import Lab6KeyDerivation.KeyDerivation;
import Utils.CommonUtils;

import java.nio.charset.StandardCharsets;
import java.util.*;

import static Lab4EncryptionModes.EncryptionMode.ECB;
import static Utils.TransmissionChannelUtils.*;
import static Utils.CommonUtils.convertByteArrayToLongArray;
import static Utils.CommonUtils.convertLongArrayToByteArray;

class TrustedServer {
    private static final Map<String, byte[]> nameKeyMap;

    static {
        nameKeyMap = new LinkedHashMap<>();
    }

    /**
     * Добавляет данные о пользователе в базу данных сервера
     *
     * @param name    имя пользователя
     * @param userKey ключ пользователя
     * @author Ilya Ryzhov
     */
    static void registerUser(String name, byte[] userKey) {
        if (!nameKeyMap.containsKey(name))
            nameKeyMap.put(name, userKey);
        else throw new IllegalArgumentException("Пользователь уже существует в системе");
    }

    /**
     * Отправляет ответ на запрос инициатора сессионного ключа
     *
     * @param requestSender отправитель запроса(инициатор)
     * @return два сообщения. Первое- сообщение с идентификатором инициатора, зашифрованное ключом инициатора,
     * второе- сообщение с временной меткой, зашифрованное ключом второго пользователя
     * @author Ilya Ryzhov
     */
    static byte[][] sendResponseForSessionKeyWithInitiatorIdentifier(UserOfProtocolWithTrustedServer requestSender) {
        byte[] message = readMessageFromTransmissionChannel();
        String senderUsername = requestSender.getName();
        byte[] initiatorKey = nameKeyMap.get(senderUsername);
        if (initiatorKey == null)
            throw new IllegalArgumentException("Пользователя с именем " + senderUsername + " не существует в базе данных");
        Cipher ECBCipherWithInitiatorKey = new Cipher(new TwoFish(convertByteArrayToLongArray(initiatorKey)), ECB);
        byte[] decryptedMessage = ECBCipherWithInitiatorKey.decryptMessage(message);//A,B,R
        String namesOfExchangingUsers = new String(Arrays.copyOf(decryptedMessage, decryptedMessage.length - 8), StandardCharsets.UTF_8);
        if (!namesOfExchangingUsers.startsWith(senderUsername))
            throw new IllegalArgumentException("Имя инициатора информационного обмена не совпадает с именем отправителя запроса");
        else {
            String initiatorName = namesOfExchangingUsers.substring(0, senderUsername.length());
            String pretenderUserName = namesOfExchangingUsers.substring(senderUsername.length());
            byte[] pretenderUserKey = nameKeyMap.get(pretenderUserName);
            if (pretenderUserKey == null)
                throw new IllegalArgumentException("Пользователь, с которым устанавливается информационный обмен не существует в базе данных");
            byte[] sessionKey = getSessionKey(initiatorKey, pretenderUserKey, initiatorName, pretenderUserName);
            byte[] encryptedSessionKeyWithInitiatorKey = ECBCipherWithInitiatorKey.encryptMessage(sessionKey);
            byte[] messageWithInitiatorIdentifier = new byte[decryptedMessage.length + encryptedSessionKeyWithInitiatorKey.length];
            System.arraycopy(decryptedMessage, decryptedMessage.length - 8, messageWithInitiatorIdentifier, 0, 8);
            System.arraycopy(decryptedMessage, 0, messageWithInitiatorIdentifier, 8, decryptedMessage.length - 8);
            System.arraycopy(encryptedSessionKeyWithInitiatorKey, 0, messageWithInitiatorIdentifier, decryptedMessage.length, encryptedSessionKeyWithInitiatorKey.length);
            messageWithInitiatorIdentifier = ECBCipherWithInitiatorKey.encryptMessage(messageWithInitiatorIdentifier);
            Cipher ECBCipherWithPretenderUserKey = new Cipher(new TwoFish(convertByteArrayToLongArray(pretenderUserKey)), ECB);
            byte[] timeLabel = convertLongArrayToByteArray(new long[]{System.currentTimeMillis()});
            byte[] encryptedSessionKeyWithPretenderUserKey = ECBCipherWithPretenderUserKey.encryptMessage(sessionKey);
            byte[] messageWithTimeLabel = new byte[decryptedMessage.length + encryptedSessionKeyWithPretenderUserKey.length];
            System.arraycopy(timeLabel, 0, messageWithTimeLabel, 0, 8);
            System.arraycopy(decryptedMessage, 0, messageWithTimeLabel, 8, decryptedMessage.length - 8);
            System.arraycopy(encryptedSessionKeyWithPretenderUserKey, 0, messageWithTimeLabel, decryptedMessage.length, encryptedSessionKeyWithPretenderUserKey.length);
            messageWithTimeLabel = ECBCipherWithPretenderUserKey.encryptMessage(messageWithTimeLabel);
            return new byte[][]{messageWithInitiatorIdentifier, messageWithTimeLabel};
        }
    }

    private static byte[] getSessionKey(byte[] initiatorKey, byte[] pretenderUserKey, String initiatorName, String pretenderUserName) {
        byte[] concatenatedKey = Arrays.copyOf(initiatorKey, initiatorKey.length + pretenderUserKey.length);
        System.arraycopy(pretenderUserKey, 0, concatenatedKey, initiatorKey.length, pretenderUserKey.length);
        HashFunction blueMidnightWish = new BlueMidnightWish(BlueMidnightWishDigestSize.BLUE_MIDNIGHT_WISH_512);
        boolean[] flags = new boolean[8];
        Arrays.fill(flags, 2, flags.length, true);
        KeyDerivation keyDerivation = new KeyDerivation(blueMidnightWish, flags);
        byte[] salt = new RandomNumberGenerator().generateRandomBytes(64);
        byte[] usageLabel = Arrays.copyOf(blueMidnightWish.computeHash("SessionKeyGenerator".getBytes(StandardCharsets.UTF_8)), 32);
        byte[] informationAboutParticipants = Arrays.copyOf(blueMidnightWish.computeHash((initiatorName + pretenderUserName).getBytes(StandardCharsets.UTF_8)), 16);
        long timeLabel = System.currentTimeMillis();
        byte[] additionalInformation = Arrays.copyOf(CommonUtils.convertLongArrayToByteArray(new long[]{timeLabel}), 16);
        return keyDerivation.generateDerivedKey(concatenatedKey, salt, 256, usageLabel, informationAboutParticipants, additionalInformation);
    }
}
