package encryptionModes;

import encryptionAlgorithm.EncryptionAlgorithm;

import java.io.File;

public class Cipher implements EncryptionAlgorithmWithMode {
    private final EncryptionMode encryptionMode;
    private EncryptionAlgorithmAbstract encryptionAlgorithmWithMode;

    /**
     * Создает экземпляр шифра, работающего в режимах ECB, CBC, CTR_ACPKM, MGM, OFB
     *
     * @param encryptionAlgorithm      алгоритм шифрования
     * @param encryptionMode           режим шифрования
     * @param encryptionModeParameters дополнительные параметры для режимов.
     *                                 <br>Для режима ECB не требуется параметров.
     *                                 <br>Для режима CBC подается количество блоков базового алгоритма шифрования в регистре сдвига.
     *                                 <br>Для режима CTR_ACPKM сначала подается количество блоков базового алгоритма шифрования в секции, затем длина гаммы в байтах.
     *                                 <br>Для режима MGM сначала подается длина гаммы в байтах, затем длина дополнительных имитозащищаемых данных в байтах.
     *                                 <br>Для режима OFB сначала подается количество блоков базового алгоритма шифрования в регистре сдвига, затем длина гаммы в байтах
     * @author Ilya Ryzhov
     */
    public Cipher(EncryptionAlgorithm encryptionAlgorithm, EncryptionMode encryptionMode, int... encryptionModeParameters) {
        this.encryptionMode = encryptionMode;
        switch (encryptionMode) {
            case ECB:
                encryptionAlgorithmWithMode = new EncryptionAlgorithmWithECB(encryptionAlgorithm);
                break;
            case CBC:
                encryptionAlgorithmWithMode = new EncryptionAlgorithmWithCBC(encryptionAlgorithm, encryptionModeParameters[0]);
                break;
            case CTR_ACPKM:
                encryptionAlgorithmWithMode = new EncryptionAlgorithmWithCTRACPKM(encryptionAlgorithm, encryptionModeParameters[0], encryptionModeParameters[1]);
                break;
            case MGM:
                encryptionAlgorithmWithMode = new EncryptionAlgorithmWithMGM(encryptionAlgorithm, encryptionModeParameters[0], encryptionModeParameters[1]);
                break;
            case OFB:
                encryptionAlgorithmWithMode = new EncryptionAlgorithmWithOFB(encryptionAlgorithm, encryptionModeParameters[0], encryptionModeParameters[1]);
                break;
        }
    }

    /**
     * @see EncryptionAlgorithmWithMode
     */
    @Override
    public byte[] encryptMessage(byte[] plainText) {
        return encryptionAlgorithmWithMode.encryptMessage(plainText);
    }

    /**
     * @see EncryptionAlgorithmWithMode
     */
    @Override
    public byte[] decryptMessage(byte[] cipherText) {
        return encryptionAlgorithmWithMode.decryptMessage(cipherText);
    }

    /**
     * @see EncryptionAlgorithmWithMode
     */
    @Override
    public void encryptFile(File fileToEncrypt, String pathForEncryptedFile) {
        encryptionAlgorithmWithMode.encryptFile(fileToEncrypt, pathForEncryptedFile);
    }

    /**
     * @see EncryptionAlgorithmWithMode
     */
    @Override
    public void decryptFile(File fileToDecrypt, String pathForDecryptedFile) {
        encryptionAlgorithmWithMode.decryptFile(fileToDecrypt, pathForDecryptedFile);
    }

    /**
     * @see EncryptionAlgorithmAbstract
     */
    public void setBufferSize(int bufferSize) {
        encryptionAlgorithmWithMode.setBufferSize(bufferSize);
    }

    /**
     * Возвращает используемый режим шифрования
     *
     * @return режим шифрования
     * @author Ilya Ryzhov
     */
    public EncryptionMode getEncryptionMode() {
        return encryptionMode;
    }

    /**
     * Возвращает используемую реализацию класса EncryptionAlgorithmAbstract
     *
     * @return реализация алгоритма шифрования с режимом шифрования
     * @author Ilya Ryzhov
     */
    public EncryptionAlgorithmAbstract getEncryptionAlgorithmWithMode() {
        return encryptionAlgorithmWithMode;
    }
}
