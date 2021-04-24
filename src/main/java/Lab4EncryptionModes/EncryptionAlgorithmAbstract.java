package Lab4EncryptionModes;

import Lab1EncryptionAlgorithm.EncryptionAlgorithm;

import java.io.*;
import java.util.Arrays;

import static Utils.CommonUtils.getAbsoluteDecryptedFileName;
import static Utils.CommonUtils.getAbsoluteEncryptedFileName;

abstract class EncryptionAlgorithmAbstract implements EncryptionAlgorithmWithMode {
    protected final EncryptionAlgorithm encryptionAlgorithm;

    protected final int blockSizeInBytes;

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
        int numberOfBlocksInEncryptedMessage = (message.length / blockSizeInBytes) + 1;
        int remainderBytes = message.length % blockSizeInBytes;
        byte[] paddingBlock = new byte[blockSizeInBytes];
        if (remainderBytes == 0) {
            paddingBlock[0] = 1;
        } else {
            System.arraycopy(message, (numberOfBlocksInEncryptedMessage - 1) * blockSizeInBytes, paddingBlock, 0, remainderBytes);
            paddingBlock[remainderBytes] = 1;
        }
        return paddingBlock;
    }

    @Override
    public final void encryptFile(File fileToEncrypt, String pathForEncryptedFile, int bufferSize) {
        try (BufferedInputStream inputStream = new BufferedInputStream(new FileInputStream(fileToEncrypt), bufferSize);
             BufferedOutputStream outputStream = new BufferedOutputStream(new FileOutputStream(getAbsoluteEncryptedFileName(fileToEncrypt, pathForEncryptedFile)), bufferSize)) {
            encryptDataInFile(inputStream, outputStream, bufferSize);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public final void decryptFile(File fileToDecrypt, String pathForDecryptedFile, int bufferSize) {
        try (BufferedInputStream inputStream = new BufferedInputStream(new FileInputStream(fileToDecrypt), bufferSize);
             BufferedOutputStream outputStream = new BufferedOutputStream(new FileOutputStream(getAbsoluteDecryptedFileName(fileToDecrypt, pathForDecryptedFile)), bufferSize)) {
            decryptDataInFile(inputStream, outputStream, bufferSize);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    protected abstract void encryptDataInFile(BufferedInputStream bufferedInputStream, BufferedOutputStream bufferedOutputStream, int bufferSize) throws IOException;

    protected abstract void decryptDataInFile(BufferedInputStream bufferedInputStream, BufferedOutputStream bufferedOutputStream, int bufferSize) throws IOException;
}
