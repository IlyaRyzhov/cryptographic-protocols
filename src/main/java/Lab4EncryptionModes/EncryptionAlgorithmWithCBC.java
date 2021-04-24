package Lab4EncryptionModes;

import Lab1EncryptionAlgorithm.EncryptionAlgorithm;

import java.io.*;
import java.util.Arrays;

import static Utils.CommonUtils.getAbsoluteDecryptedFileName;
import static Utils.CommonUtils.getAbsoluteEncryptedFileName;
import static Utils.EncryptionModesUtils.*;

class EncryptionAlgorithmWithCBC extends EncryptionAlgorithmAbstract implements EncryptionModeWithInitializationVector {
    private byte[] initializationVector;

    public EncryptionAlgorithmWithCBC(EncryptionAlgorithm encryptionAlgorithm, int numberOfBlocksInShiftRegister) {
        super(encryptionAlgorithm);
        initializationVector = new byte[numberOfBlocksInShiftRegister * blockSizeInBytes];
        generateInitializationVector(initializationVector);
    }

    @Override
    public byte[] encryptMessage(byte[] plainText) {
        byte[] currentInitializationVector = Arrays.copyOf(initializationVector, initializationVector.length);
        int numberOfBlocksInEncryptedMessage = (plainText.length / blockSizeInBytes) + 1;
        byte[] encryptedMessage = new byte[numberOfBlocksInEncryptedMessage * blockSizeInBytes];
        byte[] paddingBlock = getPaddingBlock(plainText);
        encryptSequenceOfBlocksInMessage(currentInitializationVector, plainText, encryptedMessage);
        xorByteArrays(currentInitializationVector, paddingBlock);
        encryptOneBlockOfMessage(currentInitializationVector, encryptedMessage, numberOfBlocksInEncryptedMessage - 1);
        return encryptedMessage;
    }

    private void encryptSequenceOfBlocksInMessage(byte[] currentInitializationVector, byte[] plainData, byte[] cipherData) {
        int numberOfBlocksInMessage = plainData.length / blockSizeInBytes;
        for (int i = 0; i < numberOfBlocksInMessage; i++) {
            xorByteArrays(currentInitializationVector, plainData, i * blockSizeInBytes, blockSizeInBytes);
            encryptOneBlockOfMessage(currentInitializationVector, cipherData, i);
        }
    }

    @Override
    public byte[] decryptMessage(byte[] cipherText) {
        byte[] currentInitializationVector = Arrays.copyOf(initializationVector, initializationVector.length);
        byte[] decryptedMessage = new byte[cipherText.length];
        decryptSequenceOfBlocksInMessage(currentInitializationVector, cipherText, decryptedMessage);
        return removePadding(decryptedMessage);
    }

    @Override
    protected void encryptDataInFile(BufferedInputStream bufferedInputStream, BufferedOutputStream bufferedOutputStream, int bufferSize) throws IOException {
        byte[] currentInitializationVector = Arrays.copyOf(initializationVector, initializationVector.length);
        while (bufferedInputStream.available() > 0) {
            byte[] plainData = bufferedInputStream.readNBytes(bufferSize);
            byte[] cipherData = new byte[plainData.length - plainData.length % bufferSize];
            encryptSequenceOfBlocksInMessage(currentInitializationVector, plainData, cipherData);
            bufferedOutputStream.write(cipherData);
            /*int numberOfBlocksToEncrypt = plainData.length / blockSizeInBytes;
            int remainderBytes = plainData.length % blockSizeInBytes;
            byte[] cipherData = new byte[numberOfBlocksToEncrypt * blockSizeInBytes];
            for (int i = 0; i < numberOfBlocksToEncrypt; i++) {
                for (int j = 0; j < blockSizeInBytes; j++) {
                    currentInitializationVector[j] ^= plainData[j + i * blockSizeInBytes];
                }
                xorByteArrays(currentInitializationVector, plainData, i * blockSizeInBytes, blockSizeInBytes);
                encryptOneBlockOfMessage(currentInitializationVector, cipherData, i);
            }*/
            if (bufferedInputStream.available() == 0) {
                cipherData = encryptMessage(plainData);
            }


        }
    }

    @Override
    protected void decryptDataInFile(BufferedInputStream bufferedInputStream, BufferedOutputStream bufferedOutputStream, int bufferSize) throws IOException {
        byte[] currentInitializationVector = Arrays.copyOf(initializationVector, initializationVector.length);
        while (bufferedInputStream.available() > 0) {
            byte[] cipherData = new byte[Math.min(1048576, bufferedInputStream.available())];
            bufferedInputStream.read(cipherData, 0, cipherData.length);
            int numberOfBlocksToDecrypt = cipherData.length / blockSizeInBytes;
            byte[] plainData = new byte[numberOfBlocksToDecrypt * blockSizeInBytes];
            decryptSequenceOfBlocksInMessage(currentInitializationVector, cipherData, plainData);
            if (bufferedInputStream.available() > 0)
                bufferedOutputStream.write(plainData);
            else {
                bufferedOutputStream.write(removePadding(plainData));
            }
        }
    }

    private void decryptSequenceOfBlocksInMessage(byte[] currentInitializationVector, byte[] cipherData, byte[] plainData) {
        int numberOfBlocksToDecrypt = cipherData.length / blockSizeInBytes;
        for (int i = 0; i < numberOfBlocksToDecrypt; i++) {
            byte[] encryptedBlock = Arrays.copyOfRange(cipherData, i * blockSizeInBytes, (i + 1) * blockSizeInBytes);
            byte[] decryptedBlock = encryptionAlgorithm.decryptOneBlock(encryptedBlock);
            xorByteArrays(decryptedBlock, currentInitializationVector, blockSizeInBytes);
            shiftLeftRegisterWithFillingLSB(currentInitializationVector, encryptedBlock);
            System.arraycopy(decryptedBlock, 0, plainData, i * blockSizeInBytes, blockSizeInBytes);
        }
    }

    private void encryptOneBlockOfMessage(byte[] currentInitializationVector, byte[] cipherData, int offsetBlocksInCipherData) {
        byte[] encryptedBlock = encryptionAlgorithm.encryptOneBlock(Arrays.copyOf(currentInitializationVector, blockSizeInBytes));
        shiftLeftRegisterWithFillingLSB(currentInitializationVector, encryptedBlock);
        System.arraycopy(encryptedBlock, 0, cipherData, offsetBlocksInCipherData * blockSizeInBytes, blockSizeInBytes);
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
