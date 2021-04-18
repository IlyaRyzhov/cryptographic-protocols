package Lab4EncryptionModes;

import Lab1EncryptionAlgorithm.EncryptionAlgorithm;
import Lab1EncryptionAlgorithm.TwoFish;

import java.io.*;
import java.util.Arrays;

import static Utils.CommonUtils.*;

public class EncryptionAlgorithmWithCTRACPKM extends EncryptionAlgorithmAbstract implements EncryptionModeWithInitializationVector {
    private byte[] initializationVector;
    private final int numberOfBlocksInSection;
    private final int gammaLengthInBytes;

    private final byte[] dSubstitution;

    {
        dSubstitution = new byte[]{
                (byte) 0x80, (byte) 0x81, (byte) 0x82, (byte) 0x83,
                (byte) 0x84, (byte) 0x85, (byte) 0x86, (byte) 0x87,
                (byte) 0x88, (byte) 0x89, (byte) 0x8A, (byte) 0x8B,
                (byte) 0x8C, (byte) 0x8D, (byte) 0x8E, (byte) 0x8F,
                (byte) 0x90, (byte) 0x91, (byte) 0x92, (byte) 0x93,
                (byte) 0x94, (byte) 0x95, (byte) 0x96, (byte) 0x97,
                (byte) 0x98, (byte) 0x99, (byte) 0x9A, (byte) 0x9B,
                (byte) 0x9C, (byte) 0x9D, (byte) 0x9E, (byte) 0x9F};
    }

    //4<=gammaLengthInBytes<=3/4*blockSizeInBytes
    //blockSizeInBytes% gammaLengthInBytes==0
    protected EncryptionAlgorithmWithCTRACPKM(EncryptionAlgorithm encryptionAlgorithm, int numberOfBlocksInSection, int gammaLengthInBytes) {
        super(encryptionAlgorithm);
        if (encryptionAlgorithm.getBlockSizeInBytes() % gammaLengthInBytes != 0)
            throw new IllegalArgumentException("Длина гаммы должна делить длину блока");
        initializationVector = new byte[encryptionAlgorithm.getBlockSizeInBytes() / 2];
        generateInitializationVector(initializationVector);
        this.gammaLengthInBytes = gammaLengthInBytes;
        this.numberOfBlocksInSection = numberOfBlocksInSection;
    }


    @Override
    public byte[] encryptMessage(byte[] plainText) {
        int blockSizeInBytes = encryptionAlgorithm.getBlockSizeInBytes();
        int lengthOfSectionInBytes = numberOfBlocksInSection * blockSizeInBytes;
        int numberOfBlocksWithLengthOfGamma = (int) Math.ceil((double) plainText.length / gammaLengthInBytes);
        int remainderBytes = plainText.length % gammaLengthInBytes;
        byte[] encryptedMessage = new byte[plainText.length];
        byte[] counter = Arrays.copyOf(initializationVector, blockSizeInBytes);
        EncryptionAlgorithm encryptionAlgorithm = this.encryptionAlgorithm.getInstance();
        byte[] blockOfPlainText = new byte[gammaLengthInBytes];
        int numberOfBlocksWithLengthOfGammaInSection = lengthOfSectionInBytes / gammaLengthInBytes;
        for (int i = 0; i < numberOfBlocksWithLengthOfGamma; i++) {
            if (i % numberOfBlocksWithLengthOfGammaInSection == 0 && i != 0)
                encryptionAlgorithm.setKey(convertByteArrayToLongArray(getNextSectionKey(encryptionAlgorithm)));
            if (remainderBytes != 0 && i == numberOfBlocksWithLengthOfGamma - 1) {
                blockOfPlainText = Arrays.copyOfRange(plainText, i * gammaLengthInBytes, plainText.length);
            } else {
                System.arraycopy(plainText, i * gammaLengthInBytes, blockOfPlainText, 0, gammaLengthInBytes);
            }
            byte[] encryptedCounter = Arrays.copyOf(encryptionAlgorithm.encryptOneBlock(counter), blockOfPlainText.length);
            for (int j = 0; j < encryptedCounter.length; j++) {
                encryptedCounter[j] ^= blockOfPlainText[j];
            }
            System.arraycopy(encryptedCounter, 0, encryptedMessage, i * gammaLengthInBytes, encryptedCounter.length);
            incrementCounter(counter);
        }
        return encryptedMessage;
    }

    @Override
    public byte[] decryptMessage(byte[] cipherText) {
        return encryptMessage(cipherText);
    }

    @Override
    public void encryptFile(File fileToEncrypt, String pathForEncryptedFile) {
        int blockSizeInBytes = encryptionAlgorithm.getBlockSizeInBytes();
        int lengthOfSectionInBytes = numberOfBlocksInSection * blockSizeInBytes;
        byte[] counter = Arrays.copyOf(initializationVector, blockSizeInBytes);
        EncryptionAlgorithm encryptionAlgorithm = this.encryptionAlgorithm.getInstance();
        byte[] blockOfPlainText = new byte[gammaLengthInBytes];
        int numberOfBlocksWithLengthOfGammaInSection = lengthOfSectionInBytes / gammaLengthInBytes;
        int numberOfProcessedBlocksWithLengthOfGamma = 0;
        try (BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(fileToEncrypt), 1048576);
             BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(createAbsoluteEncryptedFileName(fileToEncrypt, pathForEncryptedFile)), 1048576)) {
            encryptDataInFile(counter, encryptionAlgorithm, blockOfPlainText, numberOfBlocksWithLengthOfGammaInSection, numberOfProcessedBlocksWithLengthOfGamma, bufferedInputStream, bufferedOutputStream);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void decryptFile(File fileToDecrypt, String pathForDecryptedFile) {
        int blockSizeInBytes = encryptionAlgorithm.getBlockSizeInBytes();
        int lengthOfSectionInBytes = numberOfBlocksInSection * blockSizeInBytes;
        byte[] counter = Arrays.copyOf(initializationVector, blockSizeInBytes);
        EncryptionAlgorithm encryptionAlgorithm = this.encryptionAlgorithm.getInstance();
        byte[] blockOfPlainText = new byte[gammaLengthInBytes];
        int numberOfBlocksWithLengthOfGammaInSection = lengthOfSectionInBytes / gammaLengthInBytes;
        int numberOfProcessedBlocksWithLengthOfGamma = 0;
        try (BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(fileToDecrypt), 1048576);
             BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(createAbsoluteDecryptedFileName(fileToDecrypt, pathForDecryptedFile)), 1048576)) {
            encryptDataInFile(counter, encryptionAlgorithm, blockOfPlainText, numberOfBlocksWithLengthOfGammaInSection,
                    numberOfProcessedBlocksWithLengthOfGamma, bufferedInputStream, bufferedOutputStream);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void encryptDataInFile(byte[] counter, EncryptionAlgorithm encryptionAlgorithm, byte[] blockOfPlainText,
                                   int numberOfBlocksWithLengthOfGammaInSection, int numberOfProcessedBlocksWithLengthOfGamma,
                                   BufferedInputStream bufferedInputStream, BufferedOutputStream bufferedOutputStream) throws IOException {
        while (bufferedInputStream.available() > 0) {
            byte[] plainData = new byte[Math.min(1048576, bufferedInputStream.available())];
            bufferedInputStream.read(plainData, 0, plainData.length);
            int numberOfBlocksWithLengthOfGamma = (int) Math.ceil((double) plainData.length / gammaLengthInBytes);
            int remainderBytes = plainData.length % gammaLengthInBytes;
            byte[] cipherData = new byte[plainData.length];
            for (int i = 0; i < numberOfBlocksWithLengthOfGamma; i++) {
                if (numberOfProcessedBlocksWithLengthOfGamma % numberOfBlocksWithLengthOfGammaInSection == 0 && numberOfProcessedBlocksWithLengthOfGamma != 0)
                    encryptionAlgorithm.setKey(convertByteArrayToLongArray(getNextSectionKey(encryptionAlgorithm)));
                if (remainderBytes != 0 && i == numberOfBlocksWithLengthOfGamma - 1) {
                    blockOfPlainText = Arrays.copyOfRange(plainData, i * gammaLengthInBytes, plainData.length);
                } else {
                    System.arraycopy(plainData, i * gammaLengthInBytes, blockOfPlainText, 0, gammaLengthInBytes);
                }
                byte[] encryptedCounter = Arrays.copyOf(encryptionAlgorithm.encryptOneBlock(counter), blockOfPlainText.length);
                for (int j = 0; j < encryptedCounter.length; j++) {
                    encryptedCounter[j] ^= blockOfPlainText[j];
                }
                System.arraycopy(encryptedCounter, 0, cipherData, i * gammaLengthInBytes, encryptedCounter.length);
                incrementCounter(counter);
                numberOfProcessedBlocksWithLengthOfGamma++;
            }
            bufferedOutputStream.write(cipherData);
        }
    }

    @Override
    public void setInitializationVector(byte[] initializationVector) {

    }

    @Override
    public byte[] getInitializationVector() {
        return new byte[0];
    }

    private byte[] getNextSectionKey(EncryptionAlgorithm encryptionAlgorithmCurrent) {
        int keySizeInBytes = encryptionAlgorithmCurrent.getKeySizeInBytes();
        int blockSizeInBytes = encryptionAlgorithmCurrent.getBlockSizeInBytes();
        int numberOfKeyParts = (int) Math.ceil((double) keySizeInBytes / blockSizeInBytes);
        byte[] nextKey = new byte[blockSizeInBytes * numberOfKeyParts];
        for (int i = 0; i < numberOfKeyParts; i++) {
            byte[] partOfNextKey = encryptionAlgorithmCurrent.encryptOneBlock(Arrays.copyOfRange(dSubstitution, i * blockSizeInBytes, (i + 1) * blockSizeInBytes));
            System.arraycopy(partOfNextKey, 0, nextKey, i * blockSizeInBytes, blockSizeInBytes);
        }
        return Arrays.copyOf(nextKey, keySizeInBytes);
    }

    private void incrementCounter(byte[] counter) {
        for (int i = counter.length - 1; i >= 0; i--) {
            counter[i]++;
            if (counter[i] != 0)
                break;
        }
    }

    public static void main(String[] args) {
        TwoFish twoFish = new TwoFish(new long[2]);
        EncryptionAlgorithmWithCTRACPKM encryptionAlgorithmWithCTRACPKM = new EncryptionAlgorithmWithCTRACPKM(twoFish, 2, 8);
        encryptionAlgorithmWithCTRACPKM.encryptFile(new File("C:\\Users\\fvd\\Desktop\\100MB.txt"), "C:\\Users\\fvd\\Desktop");
        encryptionAlgorithmWithCTRACPKM.decryptFile(new File("C:\\Users\\fvd\\Desktop\\100MB.txt.encrypted"), "C:\\Users\\fvd\\Desktop");

        byte[] pt = new byte[65];
        byte[] ct = encryptionAlgorithmWithCTRACPKM.encryptMessage(pt);
        System.out.println(Arrays.toString(ct));
        System.out.println(Arrays.toString(encryptionAlgorithmWithCTRACPKM.decryptMessage(ct)));
    }
}
