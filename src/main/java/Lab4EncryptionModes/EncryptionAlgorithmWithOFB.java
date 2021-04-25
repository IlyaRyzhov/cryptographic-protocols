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
        this.gammaLengthInBytes = gammaLengthInBytes;
        initializationVector = new byte[numberOfBlocksInShiftRegister * blockSizeInBytes];
        generateInitializationVector(initializationVector);
        setBufferSize(DEFAULT_BUFFER_SIZE);
    }

    @Override
    public byte[] encryptMessage(byte[] plainMessage) {
        byte[] currentInitializationVector = Arrays.copyOf(initializationVector, initializationVector.length);
        return encryptDataInMessage(currentInitializationVector, plainMessage);
    }

    @Override
    public byte[] decryptMessage(byte[] encryptedMessage) {
        return encryptMessage(encryptedMessage);
    }

    private byte[] encryptDataInMessage(byte[] currentInitializationVector, byte[] plainData) {
        byte[] encryptedData = new byte[plainData.length];
        for (int i = 0; i < plainData.length; i += gammaLengthInBytes) {
            byte[] gamma = encryptionAlgorithm.encryptOneBlock(Arrays.copyOf(currentInitializationVector, blockSizeInBytes));
            shiftLeftRegisterWithFillingLSB(currentInitializationVector, gamma);
            byte[] encryptedBlock = Arrays.copyOfRange(plainData, i, Math.min(i + gammaLengthInBytes, plainData.length));
            xorByteArrays(encryptedBlock, gamma, encryptedBlock.length);
            System.arraycopy(encryptedBlock, 0, encryptedData, i, encryptedBlock.length);
        }
        return encryptedData;
    }

    @Override
    protected void encryptDataInFile(BufferedInputStream bufferedInputStream, BufferedOutputStream bufferedOutputStream) throws IOException {
        byte[] currentInitializationVector = Arrays.copyOf(initializationVector, initializationVector.length);
        while (bufferedInputStream.available() > 0) {
            byte[] plainData = bufferedInputStream.readNBytes(bufferSize);
            bufferedOutputStream.write(encryptDataInMessage(currentInitializationVector, plainData));
        }
    }

    @Override
    protected void decryptDataInFile(BufferedInputStream bufferedInputStream, BufferedOutputStream bufferedOutputStream) throws IOException {
        encryptDataInFile(bufferedInputStream, bufferedOutputStream);
    }

    @Override
    public void setBufferSize(int bufferSize) {
        this.bufferSize = Math.max(bufferSize - bufferSize % gammaLengthInBytes, gammaLengthInBytes);
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
