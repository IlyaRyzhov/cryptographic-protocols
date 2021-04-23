package Lab4EncryptionModes;

import Lab1EncryptionAlgorithm.EncryptionAlgorithm;
import Lab1EncryptionAlgorithm.GOST34122015;
import Lab1EncryptionAlgorithm.TwoFish;

import java.io.*;
import java.util.Arrays;

import static Utils.CommonUtils.createAbsoluteDecryptedFileName;
import static Utils.CommonUtils.createAbsoluteEncryptedFileName;
import static Utils.EncryptionModesUtils.xorByteArrays;

public class EncryptionAlgorithmWithOutputFeedback extends EncryptionAlgorithmAbstract implements EncryptionModeWithInitializationVector {
    private byte[] initializationVector;

    private final int gammaLengthInBytes;

    protected EncryptionAlgorithmWithOutputFeedback(EncryptionAlgorithm encryptionAlgorithm, int numberOfBlocksInShiftRegister, int gammaLengthInBytes) {
        super(encryptionAlgorithm);
        initializationVector = new byte[numberOfBlocksInShiftRegister * blockSizeInBytes];
        generateInitializationVector(initializationVector);
        this.gammaLengthInBytes = gammaLengthInBytes;
    }

    @Override
    public byte[] encryptMessage(byte[] plainText) {
        byte[] currentInitializationVector = new byte[initializationVector.length];
        System.arraycopy(initializationVector, 0, currentInitializationVector, 0, initializationVector.length);
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
        try (BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(fileToEncrypt), 1048576);
             BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(createAbsoluteEncryptedFileName(fileToEncrypt, pathForEncryptedFile)), 1048576)) {
            encryptDataInFile(currentInitializationVector, blockSizeInBytes, bufferedInputStream, bufferedOutputStream);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void encryptRemainderBytes(byte[] currentInitializationVector, int blockSizeInBytes, byte[] plainData,
                                       int numberOfBlocksToEncrypt, int remainderBytes, byte[] cipherData) {
        if (remainderBytes != 0) {
            byte[] gamma = encryptionAlgorithm.encryptOneBlock(Arrays.copyOf(currentInitializationVector, blockSizeInBytes));
            shiftLeftRegisterWithFillingLSB(currentInitializationVector, gamma);
            byte[] encryptedBlock = Arrays.copyOfRange(plainData, numberOfBlocksToEncrypt * gammaLengthInBytes, plainData.length);
            xorByteArrays(encryptedBlock, gamma);
            System.arraycopy(encryptedBlock, 0, cipherData, numberOfBlocksToEncrypt * gammaLengthInBytes, remainderBytes);
        }
    }

    private void encryptMessageWithoutRemainderBytes(byte[] currentInitializationVector, int blockSizeInBytes, byte[] plainData,
                                                     int numberOfBlocksToEncrypt, byte[] cipherData) {
        for (int i = 0; i < numberOfBlocksToEncrypt; i++) {
            byte[] gamma = encryptionAlgorithm.encryptOneBlock(Arrays.copyOf(currentInitializationVector, blockSizeInBytes));
            shiftLeftRegisterWithFillingLSB(currentInitializationVector, gamma);
            byte[] encryptedBlock = Arrays.copyOfRange(plainData, i * gammaLengthInBytes, (i + 1) * gammaLengthInBytes);
            xorByteArrays(encryptedBlock, gamma);
            System.arraycopy(encryptedBlock, 0, cipherData, i * gammaLengthInBytes, gammaLengthInBytes);
        }
    }

    @Override
    public void decryptFile(File fileToDecrypt, String pathForDecryptedFile) {
        byte[] currentInitializationVector = new byte[initializationVector.length];
        System.arraycopy(initializationVector, 0, currentInitializationVector, 0, initializationVector.length);
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
/*        TwoFish fish = new TwoFish(new long[2]);
        EncryptionAlgorithmWithOutputFeedback encryptionAlgorithmWithOutputFeedback = new EncryptionAlgorithmWithOutputFeedback(fish, 2, 10);
        encryptionAlgorithmWithOutputFeedback.encryptFile(new File("C:\\Users\\fvd\\Desktop\\100MB.txt"), "C:\\Users\\fvd\\Desktop");
        encryptionAlgorithmWithOutputFeedback.decryptFile(new File("C:\\Users\\fvd\\Desktop\\100MB.txt.encrypted"), "C:\\Users\\fvd\\Desktop");
        byte[] pt = new byte[16];
        Arrays.fill(pt, (byte) 0xff);
        byte[] ct = encryptionAlgorithmWithOutputFeedback.encryptMessage(pt);
        System.out.println(Arrays.toString(ct));
        System.out.println(Arrays.toString(encryptionAlgorithmWithOutputFeedback.decryptMessage(ct)));*/
        byte[] iv = new byte[]{0x12, 0x34, 0x56, 0x78, (byte) 0x90, (byte) 0xab, (byte) 0xce, (byte) 0xf0, (byte) 0xa1, (byte) 0xb2,
                (byte) 0xc3, (byte) 0xd4, (byte) 0xe5, (byte) 0xf0, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78,
                (byte) 0x89, (byte) 0x90, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19};
        GOST34122015 gost34122015 = new GOST34122015(new byte[]{(byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xdd, (byte) 0xee, (byte) 0xff,
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0xfe, (byte) 0xdc, (byte) 0xba, (byte) 0x98,
                0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef});
        byte[] pt1 = new byte[]{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, (byte) 0xff, (byte) 0xee, (byte) 0xdd, (byte) 0xcc, (byte) 0xbb, (byte) 0xaa, (byte) 0x99,
                (byte) 0x88, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xee, (byte) 0xff,
                0x0a, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb,
                (byte) 0xcc, (byte) 0xee, (byte) 0xff, 0x0a, 0x00, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99,
                (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xee, (byte) 0xff, 0x0a, 0x00, 0x11};
        EncryptionAlgorithmWithOutputFeedback encryptionAlgorithmWithOutputFeedback = new EncryptionAlgorithmWithOutputFeedback(gost34122015, 2, 16);
        encryptionAlgorithmWithOutputFeedback.setInitializationVector(iv);
        System.out.println(pt1.length);
        byte[] ct = encryptionAlgorithmWithOutputFeedback.encryptMessage(pt1);
        for (int i = 0; i < ct.length; i++) {
            System.out.print(Integer.toHexString(ct[i] & 0xff));
        }
    }
}
