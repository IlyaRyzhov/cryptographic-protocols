package Lab4EncryptionModes;

import Lab1EncryptionAlgorithm.EncryptionAlgorithm;

import java.io.*;
import java.util.Arrays;

import static Utils.CommonUtils.getAbsoluteDecryptedFileName;
import static Utils.CommonUtils.getAbsoluteEncryptedFileName;

abstract class EncryptionAlgorithmAbstract implements EncryptionAlgorithmWithMode {
    protected final EncryptionAlgorithm encryptionAlgorithm;
    protected final int blockSizeInBytes;
    //TODO оптимизировать, проверять кратность в функциях
    protected int bufferSize;//кратен длине обрабатываемого в режиме блока(либо блока базового шифра либо гаммы)
    protected static final int DEFAULT_BUFFER_SIZE = 1048576;

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

    protected final byte[] removePadding(byte[] message) {
        int indexOfLastOne = findLastOne(message);
        return Arrays.copyOfRange(message, 0, indexOfLastOne);
    }

    protected final byte[] padMessage(byte[] message) {
        byte[] paddedMessage = new byte[(message.length / blockSizeInBytes + 1) * blockSizeInBytes];
        System.arraycopy(message, 0, paddedMessage, 0, message.length);
        paddedMessage[message.length] = 1;
        return paddedMessage;
    }

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

    @Override
    public final void encryptFile(File fileToEncrypt, String pathForEncryptedFile) {
        try (BufferedInputStream inputStream = new BufferedInputStream(new FileInputStream(fileToEncrypt), bufferSize);
             BufferedOutputStream outputStream = new BufferedOutputStream(new FileOutputStream(getAbsoluteEncryptedFileName(fileToEncrypt, pathForEncryptedFile)), bufferSize)) {
            encryptDataInFile(inputStream, outputStream);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public final void decryptFile(File fileToDecrypt, String pathForDecryptedFile) {
        try (BufferedInputStream inputStream = new BufferedInputStream(new FileInputStream(fileToDecrypt), bufferSize);
             BufferedOutputStream outputStream = new BufferedOutputStream(new FileOutputStream(getAbsoluteDecryptedFileName(fileToDecrypt, pathForDecryptedFile)), bufferSize)) {
            decryptDataInFile(inputStream, outputStream);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void setBufferSize(int bufferSize) {
        this.bufferSize = bufferSize;
    }

    protected abstract void encryptDataInFile(BufferedInputStream bufferedInputStream, BufferedOutputStream bufferedOutputStream) throws IOException;

    protected abstract void decryptDataInFile(BufferedInputStream bufferedInputStream, BufferedOutputStream bufferedOutputStream) throws IOException;
}
