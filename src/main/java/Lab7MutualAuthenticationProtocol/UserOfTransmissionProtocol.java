package Lab7MutualAuthenticationProtocol;

import Lab1EncryptionAlgorithm.TwoFish;
import Lab4EncryptionModes.Cipher;
import Lab4EncryptionModes.EncryptionMode;

import static Lab7MutualAuthenticationProtocol.UserRole.INITIATOR;
import static Lab7MutualAuthenticationProtocol.UserRole.PRETENDER;
import static Utils.CommonUtils.convertByteArrayToLongArray;

public abstract class UserOfTransmissionProtocol {
    public final String name;
    public UserRole userRole;
    protected final byte[] userKey;
    protected byte[] sessionKey;
    private Cipher cipherWithSessionKey;

    public UserOfTransmissionProtocol(String name, byte[] userKey, UserRole userRole) {
        this.name = name;
        this.userKey = userKey;
        this.userRole = userRole;
    }

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
}
