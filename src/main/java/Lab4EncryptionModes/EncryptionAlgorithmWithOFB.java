package Lab4EncryptionModes;

import Lab1EncryptionAlgorithm.EncryptionAlgorithm;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.util.Arrays;

import static Utils.EncryptionModesUtils.*;

public class EncryptionAlgorithmWithOFB extends EncryptionAlgorithmAbstract implements EncryptionModeWithInitializationVector {
    private byte[] initializationVector;

    private final int gammaLengthInBytes;

    public EncryptionAlgorithmWithOFB(EncryptionAlgorithm encryptionAlgorithm, int numberOfBlocksInShiftRegister, int gammaLengthInBytes) {
        super(encryptionAlgorithm);
        initializationVector = new byte[numberOfBlocksInShiftRegister * blockSizeInBytes];
        generateInitializationVector(initializationVector);
        this.gammaLengthInBytes = gammaLengthInBytes;
    }

    @Override
    public byte[] encryptMessage(byte[] plainText) {
        byte[] currentInitializationVector = Arrays.copyOf(initializationVector, initializationVector.length);
        return encryptDataInMessage(currentInitializationVector, plainText);
    }

    @Override
    public byte[] decryptMessage(byte[] cipherText) {
        return encryptMessage(cipherText);
    }

    private byte[] encryptDataInMessage(byte[] currentInitializationVector, byte[] plainData) {
        byte[] cipherData = new byte[plainData.length];
        for (int i = 0; i < plainData.length; i += gammaLengthInBytes) {
            byte[] gamma = encryptionAlgorithm.encryptOneBlock(Arrays.copyOf(currentInitializationVector, blockSizeInBytes));
            shiftLeftRegisterWithFillingLSB(currentInitializationVector, gamma);
            byte[] encryptedBlock = Arrays.copyOfRange(plainData, i, Math.min(i + gammaLengthInBytes, plainData.length));
            xorByteArrays(encryptedBlock, gamma);
            System.arraycopy(encryptedBlock, 0, cipherData, i, encryptedBlock.length);
        }
        return cipherData;
    }

    @Override
    protected void encryptDataInFile(BufferedInputStream bufferedInputStream, BufferedOutputStream bufferedOutputStream, int bufferSize) throws IOException {
        byte[] currentInitializationVector = Arrays.copyOf(initializationVector, initializationVector.length);
        while (bufferedInputStream.available() > 0) {
            byte[] plainData = bufferedInputStream.readNBytes(bufferSize);
            bufferedOutputStream.write(encryptDataInMessage(currentInitializationVector, plainData));
        }
    }

    @Override
    protected void decryptDataInFile(BufferedInputStream bufferedInputStream, BufferedOutputStream bufferedOutputStream, int bufferSize) throws IOException {
        encryptDataInFile(bufferedInputStream,bufferedOutputStream,bufferSize);
    }

    @Override
    public void setInitializationVector(byte[] initializationVector) {
        this.initializationVector = initializationVector;
    }

    @Override
    public byte[] getInitializationVector() {
        return initializationVector;
    }
}
