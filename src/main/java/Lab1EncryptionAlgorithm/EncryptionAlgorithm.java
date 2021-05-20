package Lab1EncryptionAlgorithm;

public interface EncryptionAlgorithm {
    /**
     * Шифрует один блок данных
     *
     * @param plainText шифруемый блок
     * @return зашифрованный блок
     * @author Ilya Ryzhov
     */
    byte[] encryptOneBlock(byte[] plainText);

    /**
     * Расшифровывает один блок данных
     *
     * @param cipherText расшифровываемый блок
     * @return расшифрованный блок
     * @author Ilya Ryzhov
     */
    byte[] decryptOneBlock(byte[] cipherText);

    /**
     * Возвращает размер шифруемый блоков
     *
     * @return размер шифруемый блоков
     * @author Ilya Ryzhov
     */
    int getBlockSizeInBytes();

    /**
     * Возвращает размер ключа в байтах
     *
     * @return размер ключа в байтах
     * @author Ilya Ryzhov
     */
    int getKeySizeInBytes();

    /**
     * Устанавливает новый ключ
     *
     * @param key новый ключ
     * @author Ilya Ryzhov
     */
    void setKey(long[] key);

    /**
     * Возвращает экземпляр класса, реализующего интерфейс EncryptionAlgorithm
     *
     * @return новый экземпляр EncryptionAlgorithm
     * @author Ilya Ryzhov
     */
    EncryptionAlgorithm getInstance();
}
