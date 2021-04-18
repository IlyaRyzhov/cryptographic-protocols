package Lab4EncryptionModes;

import Lab1EncryptionAlgorithm.EncryptionAlgorithm;

import java.io.File;
import java.util.Arrays;

public class EncryptionAlgorithmWithOutputFeedback extends EncryptionAlgorithmAbstract implements EncryptionModeWithInitializationVector {
    private byte[] initializationVector;

    private final int gammaLength;

    protected EncryptionAlgorithmWithOutputFeedback(EncryptionAlgorithm encryptionAlgorithm, int numberOfBlocksInShiftRegister, int gammaLength) {
        super(encryptionAlgorithm);
        initializationVector = new byte[numberOfBlocksInShiftRegister * encryptionAlgorithm.getBlockSizeInBytes()];
        generateInitializationVector(initializationVector);
        this.gammaLength = gammaLength;
    }

    @Override
    public byte[] encryptMessage(byte[] plainText) {
        byte[] currentInitializationVector = new byte[initializationVector.length];
        System.arraycopy(initializationVector, 0, currentInitializationVector, 0, initializationVector.length);
        int blockSizeInBytes = encryptionAlgorithm.getBlockSizeInBytes();
        int numberOfBlocks = plainText.length / gammaLength;
        byte[] encryptedMessage = new byte[plainText.length];
        for (int i = 0; i < numberOfBlocks; i++) {
            byte[] mostSignificantBytesOfShiftRegister = Arrays.copyOf(currentInitializationVector, blockSizeInBytes);
            byte[] gamma = encryptionAlgorithm.encryptOneBlock(mostSignificantBytesOfShiftRegister);
        }
        return new byte[0];
    }

    @Override
    public byte[] decryptMessage(byte[] cipherText) {
        return new byte[0];
    }

    @Override
    public void encryptFile(File fileToEncrypt, String pathForEncryptedFile) {

    }

    @Override
    public void decryptFile(File fileToDecrypt, String pathForDecryptedFile) {

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
