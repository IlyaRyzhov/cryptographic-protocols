package Lab4EncryptionModes;

import Lab1EncryptionAlgorithm.EncryptionAlgorithm;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.util.Arrays;

class EncryptionAlgorithmWithECB extends EncryptionAlgorithmAbstract {

    /**
     * @see EncryptionAlgorithmAbstract
     */
    public EncryptionAlgorithmWithECB(EncryptionAlgorithm encryptionAlgorithm) {
        super(encryptionAlgorithm);
        setBufferSize(DEFAULT_BUFFER_SIZE);
    }

    /**
     * @see EncryptionAlgorithmAbstract
     */
    @Override
    protected void setBufferSize(int bufferSize) {
        this.bufferSize = Math.max(bufferSize - bufferSize % blockSizeInBytes, blockSizeInBytes);
    }

    /**
     * @see EncryptionAlgorithmWithMode
     */
    @Override
    public byte[] encryptMessage(byte[] plainMessage) {
        int numberOfBlocksInEncryptedMessage = (plainMessage.length / blockSizeInBytes) + 1;
        byte[] encryptedMessage = new byte[numberOfBlocksInEncryptedMessage * blockSizeInBytes];
        byte[] paddingBlock = getPaddingBlock(plainMessage);
        byte[] encryptedBlock;
        encryptMessageWithoutRemainderBytes(plainMessage, encryptedMessage);
        encryptedBlock = encryptionAlgorithm.encryptOneBlock(paddingBlock);
        System.arraycopy(encryptedBlock, 0, encryptedMessage, encryptedMessage.length - blockSizeInBytes, blockSizeInBytes);
        return encryptedMessage;
    }

    private void encryptMessageWithoutRemainderBytes(byte[] plainData, byte[] encryptedData) {
        byte[] encryptedBlock;
        for (int i = 0; i < plainData.length; i += blockSizeInBytes) {
            encryptedBlock = encryptionAlgorithm.encryptOneBlock(Arrays.copyOfRange(plainData, i, i + blockSizeInBytes));
            System.arraycopy(encryptedBlock, 0, encryptedData, i, blockSizeInBytes);
        }
    }

    /**
     * @see EncryptionAlgorithmWithMode
     */
    @Override
    public byte[] decryptMessage(byte[] encryptedMessage) {
        byte[] decryptedMessage = new byte[encryptedMessage.length];
        decryptMessageWithoutRemovingPadding(encryptedMessage, decryptedMessage);
        return removePadding(decryptedMessage);
    }

    private void decryptMessageWithoutRemovingPadding(byte[] encryptedData, byte[] decryptedData) {
        byte[] decryptedBlock;
        for (int i = 0; i < encryptedData.length; i += blockSizeInBytes) {
            decryptedBlock = encryptionAlgorithm.decryptOneBlock(Arrays.copyOfRange(encryptedData, i, i + blockSizeInBytes));
            System.arraycopy(decryptedBlock, 0, decryptedData, i, blockSizeInBytes);
        }
    }

    /**
     * @see EncryptionAlgorithmAbstract
     */
    @Override
    protected void encryptDataInFile(BufferedInputStream bufferedInputStream, BufferedOutputStream bufferedOutputStream) throws IOException {
        while (bufferedInputStream.available() > 0) {
            byte[] plainData = bufferedInputStream.readNBytes(bufferSize);
            byte[] encryptedData = new byte[plainData.length];
            if (bufferedInputStream.available() > 0) {
                encryptMessageWithoutRemainderBytes(plainData, encryptedData);
            } else {
                encryptedData = encryptMessage(plainData);
            }
            bufferedOutputStream.write(encryptedData);
        }
    }

    /**
     * @see EncryptionAlgorithmAbstract
     */
    @Override
    protected void decryptDataInFile(BufferedInputStream bufferedInputStream, BufferedOutputStream bufferedOutputStream) throws IOException {
        while (bufferedInputStream.available() > 0) {
            byte[] encryptedData = bufferedInputStream.readNBytes(bufferSize);
            byte[] decryptedData = new byte[encryptedData.length];
            if (bufferedInputStream.available() > 0) {
                decryptMessageWithoutRemovingPadding(encryptedData, decryptedData);
            } else {
                decryptedData = decryptMessage(decryptedData);
            }
            bufferedOutputStream.write(decryptedData);
        }
    }
}
