package Lab4EncryptionModes;

import Lab1EncryptionAlgorithm.EncryptionAlgorithm;
import Lab1EncryptionAlgorithm.TwoFish;

import java.io.*;
import java.util.Arrays;

import static Utils.CommonUtils.createAbsoluteDecryptedFileName;
import static Utils.CommonUtils.createAbsoluteEncryptedFileName;

public class EncryptionAlgorithmWithOutputFeedback extends EncryptionAlgorithmAbstract implements EncryptionModeWithInitializationVector {
    private byte[] initializationVector;

    private final int gammaLengthInBytes;

    protected EncryptionAlgorithmWithOutputFeedback(EncryptionAlgorithm encryptionAlgorithm, int numberOfBlocksInShiftRegister, int gammaLengthInBytes) {
        super(encryptionAlgorithm);
        initializationVector = new byte[numberOfBlocksInShiftRegister * encryptionAlgorithm.getBlockSizeInBytes()];
        generateInitializationVector(initializationVector);
        this.gammaLengthInBytes = gammaLengthInBytes;
    }

    @Override
    public byte[] encryptMessage(byte[] plainText) {
        byte[] currentInitializationVector = new byte[initializationVector.length];
        System.arraycopy(initializationVector, 0, currentInitializationVector, 0, initializationVector.length);
        int blockSizeInBytes = encryptionAlgorithm.getBlockSizeInBytes();
        int numberOfBlocks = plainText.length / gammaLengthInBytes;
        byte[] encryptedMessage = new byte[plainText.length];
        encryptMessageWithoutRemainderBytes(currentInitializationVector, blockSizeInBytes, plainText, numberOfBlocks, encryptedMessage);
        int remainderBytes = plainText.length % gammaLengthInBytes;
        encryptRemainderBytes(currentInitializationVector, blockSizeInBytes, plainText, numberOfBlocks, remainderBytes, encryptedMessage);
        return encryptedMessage;
    }

    @Override
    public byte[] decryptMessage(byte[] cipherText) {
        return encryptMessage(cipherText);
    }

    @Override
    public void encryptFile(File fileToEncrypt, String pathForEncryptedFile) {
        byte[] currentInitializationVector = new byte[initializationVector.length];
        System.arraycopy(initializationVector, 0, currentInitializationVector, 0, initializationVector.length);
        int blockSizeInBytes = encryptionAlgorithm.getBlockSizeInBytes();
        try (BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(fileToEncrypt), 1048576);
             BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(createAbsoluteEncryptedFileName(fileToEncrypt, pathForEncryptedFile)), 1048576)) {
            encryptDataInFile(currentInitializationVector, blockSizeInBytes, bufferedInputStream, bufferedOutputStream);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void encryptRemainderBytes(byte[] currentInitializationVector, int blockSizeInBytes, byte[] plainData, int numberOfBlocksToEncrypt, int remainderBytes, byte[] cipherData) {
        if (remainderBytes != 0) {
            byte[] gamma = encryptionAlgorithm.encryptOneBlock(Arrays.copyOf(currentInitializationVector, blockSizeInBytes));
            shiftLeftRegisterWithFillingLSB(currentInitializationVector, gamma);
            byte[] encryptedBlock = Arrays.copyOfRange(plainData, numberOfBlocksToEncrypt * gammaLengthInBytes, plainData.length);
            for (int j = 0; j < encryptedBlock.length; j++) {
                encryptedBlock[j] ^= gamma[j];
            }
            System.arraycopy(encryptedBlock, 0, cipherData, numberOfBlocksToEncrypt * gammaLengthInBytes, remainderBytes);
        }
    }

    private void encryptMessageWithoutRemainderBytes(byte[] currentInitializationVector, int blockSizeInBytes, byte[] plainData,
                                                     int numberOfBlocksToEncrypt, byte[] cipherData) {
        for (int i = 0; i < numberOfBlocksToEncrypt; i++) {
            byte[] gamma = encryptionAlgorithm.encryptOneBlock(Arrays.copyOf(currentInitializationVector, blockSizeInBytes));
            shiftLeftRegisterWithFillingLSB(currentInitializationVector, gamma);
            byte[] encryptedBlock = Arrays.copyOfRange(plainData, i * gammaLengthInBytes, (i + 1) * gammaLengthInBytes);
            for (int j = 0; j < encryptedBlock.length; j++) {
                encryptedBlock[j] ^= gamma[j];
            }
            System.arraycopy(encryptedBlock, 0, cipherData, i * gammaLengthInBytes, gammaLengthInBytes);
        }
    }

    @Override
    public void decryptFile(File fileToDecrypt, String pathForDecryptedFile) {
        byte[] currentInitializationVector = new byte[initializationVector.length];
        System.arraycopy(initializationVector, 0, currentInitializationVector, 0, initializationVector.length);
        int blockSizeInBytes = encryptionAlgorithm.getBlockSizeInBytes();
        try (BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(fileToDecrypt), 1048576);
             BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(createAbsoluteDecryptedFileName(fileToDecrypt, pathForDecryptedFile)), 1048576)) {
            encryptDataInFile(currentInitializationVector, blockSizeInBytes, bufferedInputStream, bufferedOutputStream);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void encryptDataInFile(byte[] currentInitializationVector, int blockSizeInBytes, BufferedInputStream bufferedInputStream,
                                   BufferedOutputStream bufferedOutputStream) throws IOException {
        while (bufferedInputStream.available() > 0) {
            byte[] cipherData = new byte[Math.min(1048576, bufferedInputStream.available())];
            bufferedInputStream.read(cipherData, 0, cipherData.length);
            int numberOfBlocksToDecrypt = cipherData.length / gammaLengthInBytes;
            int remainderBytes = cipherData.length % gammaLengthInBytes;
            byte[] plainData = new byte[cipherData.length];
            encryptMessageWithoutRemainderBytes(currentInitializationVector, blockSizeInBytes, cipherData, numberOfBlocksToDecrypt, plainData);
            encryptRemainderBytes(currentInitializationVector, blockSizeInBytes, cipherData, numberOfBlocksToDecrypt, remainderBytes, plainData);
            bufferedOutputStream.write(plainData);
        }
    }

    @Override
    public void setInitializationVector(byte[] initializationVector) {
        this.initializationVector = initializationVector;
    }

    @Override
    public byte[] getInitializationVector() {
        return initializationVector;
    }

    public static void main(String[] args) {
        TwoFish fish = new TwoFish(new long[2]);
        EncryptionAlgorithmWithOutputFeedback encryptionAlgorithmWithOutputFeedback = new EncryptionAlgorithmWithOutputFeedback(fish, 2, 10);
        encryptionAlgorithmWithOutputFeedback.encryptFile(new File("C:\\Users\\fvd\\Desktop\\100MB.txt"), "C:\\Users\\fvd\\Desktop");
        encryptionAlgorithmWithOutputFeedback.decryptFile(new File("C:\\Users\\fvd\\Desktop\\100MB.txt.encrypted"), "C:\\Users\\fvd\\Desktop");
        byte[] pt = new byte[16];
        Arrays.fill(pt, (byte) 0xff);
        byte[] ct = encryptionAlgorithmWithOutputFeedback.encryptMessage(pt);
        System.out.println(Arrays.toString(ct));
        System.out.println(Arrays.toString(encryptionAlgorithmWithOutputFeedback.decryptMessage(ct)));
    }
}
