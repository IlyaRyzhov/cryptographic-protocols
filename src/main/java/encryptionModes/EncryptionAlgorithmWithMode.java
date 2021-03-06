package encryptionModes;

import java.io.File;

public interface EncryptionAlgorithmWithMode {
    /**
     * Шифрует сообщение
     *
     * @param plainMessage шифруемое сообщение
     * @return зашифрованное сообщение
     * @author Ilya Ryzhov
     */
    byte[] encryptMessage(byte[] plainMessage);

    /**
     * Расшифровывает сообщение
     *
     * @param encryptedMessage зашифрованное сообщение
     * @return расшифрованное сообщение
     * @author Ilya Ryzhov
     */
    byte[] decryptMessage(byte[] encryptedMessage);

    /**
     * Шифрует файл
     *
     * @param fileToEncrypt        шифруемый файл
     * @param pathForEncryptedFile путь, где должен находиться зашифрованный файл
     * @author Ilya Ryzhov
     */
    void encryptFile(File fileToEncrypt, String pathForEncryptedFile);

    /**
     * @param fileToDecrypt        расшифровывает файл
     * @param pathForDecryptedFile путь, где должен находиться расшифрованный файл
     * @author Ilya Ryzhov
     */
    void decryptFile(File fileToDecrypt, String pathForDecryptedFile);
}
