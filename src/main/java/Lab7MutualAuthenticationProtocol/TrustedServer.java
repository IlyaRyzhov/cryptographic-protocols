package Lab7MutualAuthenticationProtocol;

import Lab1EncryptionAlgorithm.TwoFish;
import Lab2HashAlgorithm.BlueMidnightWish;
import Lab2HashAlgorithm.BlueMidnightWishDigestSize;
import Lab4EncryptionModes.Cipher;
import Lab5RandomNumberGenerator.RandomNumberGenerator;
import Lab6KeyDerivation.KeyDerivation;
import Utils.CommonUtils;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

import static Lab4EncryptionModes.EncryptionMode.ECB;
import static Utils.CommonUtils.convertByteArrayToLongArray;
import static Utils.CommonUtils.convertLongArrayToByteArray;

public class TrustedServer {
    private final Map<String, byte[]> nameKeyMap;

    public TrustedServer() {
        nameKeyMap = new LinkedHashMap<>();
    }

    public void registerUser(String name, byte[] userKey) {
        if (!nameKeyMap.containsKey(name))
            nameKeyMap.put(name, userKey);
        else throw new IllegalArgumentException("Пользователь уже существует в системе");
    }

    public byte[][] sendResponseForSessionKey(User user, byte[] message) {
        String senderUsername = user.getName();
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
            String secondUserName = namesOfExchangingUsers.substring(senderUsername.length());
            byte[] secondUserKey = nameKeyMap.get(secondUserName);
            if (secondUserKey == null)
                throw new IllegalArgumentException("Пользователь, с которым устанавливается информационный обмен не существует в базе данных");
            byte[] sessionKey = getSessionKey(initiatorKey, secondUserKey, initiatorName, secondUserName);
            byte[] encryptedSessionKeyWithInitiatorKey = ECBCipherWithInitiatorKey.encryptMessage(sessionKey);
            byte[] firstResponseMessage = new byte[decryptedMessage.length + encryptedSessionKeyWithInitiatorKey.length];
            System.arraycopy(decryptedMessage, decryptedMessage.length - 8, firstResponseMessage, 0, 8);
            System.arraycopy(decryptedMessage, 0, firstResponseMessage, 8, decryptedMessage.length - 8);
            System.arraycopy(encryptedSessionKeyWithInitiatorKey, 0, firstResponseMessage, decryptedMessage.length, encryptedSessionKeyWithInitiatorKey.length);
            firstResponseMessage = ECBCipherWithInitiatorKey.encryptMessage(firstResponseMessage);
            Cipher ECBCipherWithSecondUserKey = new Cipher(new TwoFish(convertByteArrayToLongArray(secondUserKey)), ECB);
            byte[] timeLabel = convertLongArrayToByteArray(new long[]{System.currentTimeMillis()});
            byte[] encryptedSessionKeyWithSecondUserKey = ECBCipherWithSecondUserKey.encryptMessage(sessionKey);
            byte[] secondResponseMessage = new byte[decryptedMessage.length + encryptedSessionKeyWithSecondUserKey.length];
            System.arraycopy(timeLabel, 0, secondResponseMessage, 0, 8);
            System.arraycopy(decryptedMessage, 0, secondResponseMessage, 8, decryptedMessage.length - 8);
            System.arraycopy(encryptedSessionKeyWithSecondUserKey, 0, secondResponseMessage, decryptedMessage.length, encryptedSessionKeyWithSecondUserKey.length);
            secondResponseMessage = ECBCipherWithSecondUserKey.encryptMessage(secondResponseMessage);
            return new byte[][]{firstResponseMessage, secondResponseMessage};
        }
    }

    private byte[] getSessionKey(byte[] initiatorKey, byte[] secondUserKey, String initiatorName, String secondUserName) {
        byte[] concatenatedKey = Arrays.copyOf(initiatorKey, initiatorKey.length + secondUserKey.length);
        System.arraycopy(secondUserKey, 0, concatenatedKey, initiatorKey.length, secondUserKey.length);
        BlueMidnightWish blueMidnightWish = new BlueMidnightWish(BlueMidnightWishDigestSize.BLUE_MIDNIGHT_WISH_512);
        boolean[] flags = new boolean[8];
        Arrays.fill(flags, 2, flags.length, true);
        KeyDerivation keyDerivation = new KeyDerivation(blueMidnightWish, flags);
        byte[] salt = new RandomNumberGenerator().generateRandomBytes(64);
        byte[] usageLabel = Arrays.copyOf(blueMidnightWish.computeHash("SessionKeyGenerator".getBytes(StandardCharsets.UTF_8)), 32);
        byte[] informationAboutParticipants = Arrays.copyOf(blueMidnightWish.computeHash((initiatorName + secondUserName).getBytes(StandardCharsets.UTF_8)), 16);
        long timeLabel = System.currentTimeMillis();
        byte[] additionalInformation = Arrays.copyOf(CommonUtils.convertLongArrayToByteArray(new long[]{timeLabel}), 16);
        return keyDerivation.generateDerivedKey(concatenatedKey, salt, 256, usageLabel, informationAboutParticipants, additionalInformation);
    }
}
