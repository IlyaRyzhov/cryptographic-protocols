package Lab4EncryptionModes;

import Lab1EncryptionAlgorithm.EncryptionAlgorithm;
import Lab1EncryptionAlgorithm.TwoFish;

import java.io.File;
import java.util.Arrays;

class EncryptionAlgorithmWithCipherBlockChaining extends AbstractEncryptionAlgorithm {
    private byte[] initializationVector;

    public EncryptionAlgorithmWithCipherBlockChaining(EncryptionAlgorithm encryptionAlgorithm, int numberOfBlocksInShiftRegister) {
        super(encryptionAlgorithm);
        initializationVector = new byte[numberOfBlocksInShiftRegister * encryptionAlgorithm.getBlockSizeInBytes()];
        generateInitializationVector(initializationVector);
    }

    public EncryptionAlgorithmWithCipherBlockChaining(EncryptionAlgorithm encryptionAlgorithm, byte[] initializationVector) {
        super(encryptionAlgorithm);
        setInitializationVector(initializationVector);
    }

    @Override
    public byte[] encryptMessage(byte[] plainText) {
        byte[] paddedMessage = padMessage(plainText);
        byte[] currentInitializationVector = new byte[initializationVector.length];
        System.arraycopy(initializationVector, 0, currentInitializationVector, 0, initializationVector.length);
        int blockSizeInBytes = encryptionAlgorithm.getBlockSizeInBytes();
        int numberOfBlocks = paddedMessage.length / blockSizeInBytes;
        byte[] encryptedMessage = new byte[paddedMessage.length];
        for (int i = 0; i < numberOfBlocks; i++) {
            for (int j = 0; j < blockSizeInBytes; j++) {
                currentInitializationVector[j] ^= paddedMessage[j + i * blockSizeInBytes];
            }
            byte[] encryptedBlock = encryptionAlgorithm.encryptOneBlock(Arrays.copyOf(currentInitializationVector, blockSizeInBytes));
            byte[] rightPartOfCurrentInitializationVector = Arrays.copyOfRange(currentInitializationVector, blockSizeInBytes, initializationVector.length);
            System.arraycopy(rightPartOfCurrentInitializationVector, 0, currentInitializationVector, 0, rightPartOfCurrentInitializationVector.length);
            System.arraycopy(encryptedBlock, 0, currentInitializationVector, rightPartOfCurrentInitializationVector.length, encryptedBlock.length);
            System.arraycopy(encryptedBlock, 0, encryptedMessage, i * blockSizeInBytes, blockSizeInBytes);
        }
        return encryptedMessage;
    }

    @Override
    public byte[] decryptMessage(byte[] cipherText) {
        byte[] currentInitializationVector = new byte[initializationVector.length];
        System.arraycopy(initializationVector, 0, currentInitializationVector, 0, initializationVector.length);
        int blockSizeInBytes = encryptionAlgorithm.getBlockSizeInBytes();
        int numberOfBlocks = cipherText.length / blockSizeInBytes;
        byte[] decryptedMessage = new byte[cipherText.length];
        for (int i = 0; i < numberOfBlocks; i++) {
            byte[] decryptedBlock = encryptionAlgorithm.decryptOneBlock(Arrays.copyOfRange(cipherText, i * blockSizeInBytes, (i + 1) * blockSizeInBytes));
            for (int j = 0; j < blockSizeInBytes; j++) {
                decryptedBlock[j] ^= currentInitializationVector[j];
            }
            byte[] rightPartOfCurrentInitializationVector = Arrays.copyOfRange(currentInitializationVector, blockSizeInBytes, initializationVector.length);
            System.arraycopy(rightPartOfCurrentInitializationVector, 0, currentInitializationVector, 0, rightPartOfCurrentInitializationVector.length);
            System.arraycopy(cipherText, i * blockSizeInBytes, currentInitializationVector, rightPartOfCurrentInitializationVector.length, blockSizeInBytes);
            System.arraycopy(decryptedBlock, 0, decryptedMessage, i * blockSizeInBytes, blockSizeInBytes);
        }
        return removePadding(decryptedMessage);
    }

    @Override
    public void encryptFile(File fileToEncrypt, String pathForEncryptedFile) {

    }

    @Override
    public void decryptFile(File fileToDecrypt, String pathForDecryptedFile) {

    }

    @Override
    protected byte[] getInitializationVector() {
        return initializationVector;
    }

    @Override
    public void setInitializationVector(byte[] initializationVector) {
        this.initializationVector = initializationVector;
    }

    public static void main(String[] args) {
        TwoFish twoFish = new TwoFish(new long[2]);
        EncryptionAlgorithmWithCipherBlockChaining encryptionAlgorithmWithCipherBlockChaining = new EncryptionAlgorithmWithCipherBlockChaining(twoFish, 3);
        byte[] pt = new byte[16];
        Arrays.fill(pt, (byte) 0xff);
        byte[] ct = encryptionAlgorithmWithCipherBlockChaining.encryptMessage(pt);
        for (int i = 0; i < ct.length; i++) {
            System.out.print(Integer.toHexString(ct[i] & 0xff));
        }
        System.out.println();
        pt = encryptionAlgorithmWithCipherBlockChaining.decryptMessage(ct);
        for (int i = 0; i < pt.length; i++) {
            System.out.print(Integer.toHexString(pt[i] & 0xff));
        }
        System.out.println();
        ct = encryptionAlgorithmWithCipherBlockChaining.encryptMessage(pt);
        for (int i = 0; i < ct.length; i++) {
            System.out.print(Integer.toHexString(ct[i] & 0xff));
        }
    }

}
