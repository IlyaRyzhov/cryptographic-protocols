package Lab4EncryptionModes;

import Lab1EncryptionAlgorithm.EncryptionAlgorithm;

import java.io.File;
/*
public class EncryptionAlgorithmWithOutputFeedback extends EncryptionAlgorithmAbstract implements EncryptionModeWithInitializationVector {
    private byte[] initializationVector;

    protected EncryptionAlgorithmWithOutputFeedback(EncryptionAlgorithm encryptionAlgorithm) {
        super(encryptionAlgorithm);
        initializationVector = new byte[numberOfBlocksInShiftRegister * encryptionAlgorithm.getBlockSizeInBytes()];
        generateInitializationVector();
    }

    @Override
    public byte[] encryptMessage(byte[] plainText) {
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
        return new byte[0];
    }
}*/
