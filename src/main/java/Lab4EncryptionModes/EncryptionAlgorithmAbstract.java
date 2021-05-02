package Lab4EncryptionModes;

import Lab1EncryptionAlgorithm.EncryptionAlgorithm;

import java.io.*;
import java.util.Arrays;

import static Utils.CommonUtils.getAbsoluteDecryptedFileName;
import static Utils.CommonUtils.getAbsoluteEncryptedFileName;

abstract class EncryptionAlgorithmAbstract implements EncryptionAlgorithmWithMode {
    protected final EncryptionAlgorithm encryptionAlgorithm;
    protected final int blockSizeInBytes;
    protected int bufferSize;
    protected static final int DEFAULT_BUFFER_SIZE = 1048576;

    /**
     * @param encryptionAlgorithm класс, реализующий интерфейс EncryptionAlgorithm
     * @author ILya Ryzhov
     */
    protected EncryptionAlgorithmAbstract(EncryptionAlgorithm encryptionAlgorithm) {
        this.encryptionAlgorithm = encryptionAlgorithm;
        this.blockSizeInBytes = encryptionAlgorithm.getBlockSizeInBytes();
    }

    private int findLastOne(byte[] message) {
        int indexOfLastOne = 0;
        for (int i = message.length - 1; i >= 0; i--) {
            if (message[i] == 0x1) {
                indexOfLastOne = i;
                break;
            }
        }
        return indexOfLastOne;
    }

    /**
     * Убирает дополнение из сообщения
     *
     * @param message сообщение, у которого нужно убрать дополнение
     * @return сообщение без padding-байтов
     * @author ILya Ryzhov
     */
    protected final byte[] removePadding(byte[] message) {
        int indexOfLastOne = findLastOne(message);
        return Arrays.copyOfRange(message, 0, indexOfLastOne);
    }

    /**
     * Возвращает последний дополненный блок сообщения
     *
     * @param message дополняемое сообщение
     * @return последний дополненный блок
     * @author ILya Ryzhov
     */
    protected final byte[] getPaddingBlock(byte[] message) {
        int remainderBytes = message.length % blockSizeInBytes;
        byte[] paddingBlock = new byte[blockSizeInBytes];
        if (remainderBytes == 0) {
            paddingBlock[0] = 1;
        } else {
            System.arraycopy(message, message.length - remainderBytes, paddingBlock, 0, remainderBytes);
            paddingBlock[remainderBytes] = 1;
        }
        return paddingBlock;
    }

    /**
     * @see EncryptionAlgorithmWithMode
     */
    @Override
    public final void encryptFile(File fileToEncrypt, String pathForEncryptedFile) {
        try (BufferedInputStream inputStream = new BufferedInputStream(new FileInputStream(fileToEncrypt), bufferSize);
             BufferedOutputStream outputStream = new BufferedOutputStream(new FileOutputStream(getAbsoluteEncryptedFileName(fileToEncrypt, pathForEncryptedFile)), bufferSize)) {
            encryptDataInFile(inputStream, outputStream);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * @see EncryptionAlgorithmWithMode
     */
    @Override
    public final void decryptFile(File fileToDecrypt, String pathForDecryptedFile) {
        try (BufferedInputStream inputStream = new BufferedInputStream(new FileInputStream(fileToDecrypt), bufferSize);
             BufferedOutputStream outputStream = new BufferedOutputStream(new FileOutputStream(getAbsoluteDecryptedFileName(fileToDecrypt, pathForDecryptedFile)), bufferSize)) {
            decryptDataInFile(inputStream, outputStream);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * @see EncryptionAlgorithm
     */
    public final void setKey(long[] key) {
        encryptionAlgorithm.setKey(key);
    }

    /**
     * Устанавливает размер буфера в bufferSize
     *
     * @param bufferSize новый размер буфера
     * @author ILya Ryzhov
     */
    protected void setBufferSize(int bufferSize) {
        this.bufferSize = bufferSize;
    }

    /**
     * Считывает данные из bufferedInputStream и записывает зашифрованные данные в bufferedOutputStream
     *
     * @param bufferedInputStream  поток, из которого читаются данные
     * @param bufferedOutputStream поток, в который записываются зашифрованные данные
     * @author ILya Ryzhov
     */
    protected abstract void encryptDataInFile(BufferedInputStream bufferedInputStream, BufferedOutputStream bufferedOutputStream) throws IOException;

    /**
     * Считывает данные из bufferedInputStream и записывает расшифрованные данные в bufferedOutputStream
     *
     * @param bufferedInputStream  поток, из которого читаются данные
     * @param bufferedOutputStream поток, в который записываются расшифрованные данные
     * @author ILya Ryzhov
     */
    protected abstract void decryptDataInFile(BufferedInputStream bufferedInputStream, BufferedOutputStream bufferedOutputStream) throws IOException;
}
