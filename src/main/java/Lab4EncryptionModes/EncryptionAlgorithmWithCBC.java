package Lab4EncryptionModes;

import Lab1EncryptionAlgorithm.EncryptionAlgorithm;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.util.Arrays;

import static Utils.EncryptionModesUtils.*;

class EncryptionAlgorithmWithCBC extends EncryptionAlgorithmAbstract implements EncryptionModeWithInitializationVector {
    private byte[] initializationVector;

    public EncryptionAlgorithmWithCBC(EncryptionAlgorithm encryptionAlgorithm, int numberOfBlocksInShiftRegister) {
        super(encryptionAlgorithm);
        initializationVector = new byte[numberOfBlocksInShiftRegister * blockSizeInBytes];
        generateInitializationVector(initializationVector);
        setBufferSize(DEFAULT_BUFFER_SIZE);
    }

    @Override
    public byte[] encryptMessage(byte[] plainMessage) {
        byte[] currentInitializationVector = Arrays.copyOf(initializationVector, initializationVector.length);
        int numberOfBlocksInEncryptedMessage = (plainMessage.length / blockSizeInBytes) + 1;
        byte[] encryptedMessage = new byte[numberOfBlocksInEncryptedMessage * blockSizeInBytes];
        byte[] paddingBlock = getPaddingBlock(plainMessage);
        encryptMessageWithoutRemainderBytes(currentInitializationVector, plainMessage, encryptedMessage);
        xorByteArrays(currentInitializationVector, paddingBlock, blockSizeInBytes);
        encryptOneBlockOfMessage(currentInitializationVector, encryptedMessage, numberOfBlocksInEncryptedMessage - 1);
        return encryptedMessage;
    }

    private void encryptMessageWithoutRemainderBytes(byte[] currentInitializationVector, byte[] plainMessage, byte[] encryptedMessage) {
        int numberOfBlocksInMessage = plainMessage.length / blockSizeInBytes;
        for (int i = 0; i < numberOfBlocksInMessage; i++) {
            xorByteArrays(currentInitializationVector, plainMessage, i * blockSizeInBytes, blockSizeInBytes);
            encryptOneBlockOfMessage(currentInitializationVector, encryptedMessage, i);
        }
    }

    @Override
    public byte[] decryptMessage(byte[] encryptedMessage) {
        byte[] currentInitializationVector = Arrays.copyOf(initializationVector, initializationVector.length);
        byte[] decryptedMessage = new byte[encryptedMessage.length];
        decryptDataInMessage(currentInitializationVector, encryptedMessage, decryptedMessage);
        return removePadding(decryptedMessage);
    }

    @Override
    protected void setBufferSize(int bufferSize) {
        this.bufferSize = Math.max(bufferSize - bufferSize % blockSizeInBytes, blockSizeInBytes);
    }

    @Override
    protected void encryptDataInFile(BufferedInputStream bufferedInputStream, BufferedOutputStream bufferedOutputStream) throws IOException {
        byte[] currentInitializationVector = Arrays.copyOf(initializationVector, initializationVector.length);
        while (bufferedInputStream.available() > 0) {
            byte[] plainData = bufferedInputStream.readNBytes(bufferSize);
            byte[] encryptedDataWithoutPadding = new byte[plainData.length - plainData.length % blockSizeInBytes];
            encryptMessageWithoutRemainderBytes(currentInitializationVector, plainData, encryptedDataWithoutPadding);
            bufferedOutputStream.write(encryptedDataWithoutPadding);
            if (bufferedInputStream.available() == 0) {
                byte[] paddingBlock = getPaddingBlock(plainData);
                xorByteArrays(currentInitializationVector, paddingBlock, blockSizeInBytes);
                encryptOneBlockOfMessage(currentInitializationVector, paddingBlock, 0);
                bufferedOutputStream.write(paddingBlock);
            }
        }
    }

    @Override
    protected void decryptDataInFile(BufferedInputStream bufferedInputStream, BufferedOutputStream bufferedOutputStream) throws IOException {
        byte[] currentInitializationVector = Arrays.copyOf(initializationVector, initializationVector.length);
        while (bufferedInputStream.available() > 0) {
            byte[] encryptedData = bufferedInputStream.readNBytes(bufferSize);
            byte[] decryptedData = new byte[encryptedData.length];
            decryptDataInMessage(currentInitializationVector, encryptedData, decryptedData);
            if (bufferedInputStream.available() > 0)
                bufferedOutputStream.write(decryptedData);
            else {
                bufferedOutputStream.write(removePadding(decryptedData));
            }
        }
    }

    private void decryptDataInMessage(byte[] currentInitializationVector, byte[] encryptedMessage, byte[] decryptedMessage) {
        for (int i = 0; i < encryptedMessage.length; i += blockSizeInBytes) {
            byte[] encryptedBlock = Arrays.copyOfRange(encryptedMessage, i, i + blockSizeInBytes);
            byte[] decryptedBlock = encryptionAlgorithm.decryptOneBlock(encryptedBlock);
            xorByteArrays(decryptedBlock, currentInitializationVector, blockSizeInBytes);
            shiftLeftRegisterWithFillingLSB(currentInitializationVector, encryptedBlock);
            System.arraycopy(decryptedBlock, 0, decryptedMessage, i, blockSizeInBytes);
        }
    }

    private void encryptOneBlockOfMessage(byte[] currentInitializationVector, byte[] encryptedMessage, int offsetBlocksInEncryptedMessage) {
        byte[] encryptedBlock = encryptionAlgorithm.encryptOneBlock(Arrays.copyOf(currentInitializationVector, blockSizeInBytes));
        shiftLeftRegisterWithFillingLSB(currentInitializationVector, encryptedBlock);
        System.arraycopy(encryptedBlock, 0, encryptedMessage, offsetBlocksInEncryptedMessage * blockSizeInBytes, blockSizeInBytes);
    }

    @Override
    public byte[] getInitializationVector() {
        return initializationVector;
    }

    @Override
    public void setInitializationVector(byte[] initializationVector) {
        this.initializationVector = initializationVector;
    }
}
