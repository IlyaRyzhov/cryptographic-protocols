package Lab4EncryptionModes;

import Lab1EncryptionAlgorithm.EncryptionAlgorithm;
import Utils.EncryptionModesUtils;

import java.io.File;
import java.util.Arrays;

import static Utils.CommonUtils.convertLongArrayToByteArray;
import static Utils.EncryptionModesUtils.*;

public class EncryptionAlgorithmWithMGM extends EncryptionAlgorithmAbstract implements EncryptionModeWithInitializationVector {
    private byte[] initializationVector;
    private final int gammaLengthInBytes;
    private final int additionalAuthenticatedDataLengthInBytes;

    private static final byte[] primitivePolynomial;

    static {
        primitivePolynomial = new byte[17];
        primitivePolynomial[0] = 1;
        primitivePolynomial[16] = (byte) 0b10000111;
    }

    public EncryptionAlgorithmWithMGM(EncryptionAlgorithm encryptionAlgorithm, int gammaLengthInBytes, int additionalAuthenticatedDataLengthInBytes) {
        super(encryptionAlgorithm);
        initializationVector = new byte[encryptionAlgorithm.getBlockSizeInBytes()];
        generateInitializationVector(initializationVector);
        if (initializationVector[0] < 0)
            initializationVector[0] ^= 0x80;
        this.gammaLengthInBytes = gammaLengthInBytes;
        this.additionalAuthenticatedDataLengthInBytes = additionalAuthenticatedDataLengthInBytes;
    }

    //TODO  проверка ad=0 pd=0
    @Override
    public byte[] encryptMessage(byte[] plainTextWithAdditionalAuthenticatedData) {
        byte[] additionalAuthenticatedData = Arrays.copyOf(plainTextWithAdditionalAuthenticatedData, additionalAuthenticatedDataLengthInBytes);
        byte[] plainData = Arrays.copyOfRange(plainTextWithAdditionalAuthenticatedData, additionalAuthenticatedDataLengthInBytes, plainTextWithAdditionalAuthenticatedData.length);
        byte[] cipherData = encryptPlainData(plainData, encryptionAlgorithm.encryptOneBlock(initializationVector));
        byte[] imitationInsert = computeImitationInsert(additionalAuthenticatedData, cipherData);
        byte[] result = new byte[plainTextWithAdditionalAuthenticatedData.length + imitationInsert.length];
        System.arraycopy(plainTextWithAdditionalAuthenticatedData, 0, result, 0, additionalAuthenticatedDataLengthInBytes);
        System.arraycopy(cipherData, 0, result, additionalAuthenticatedDataLengthInBytes, cipherData.length);
        System.arraycopy(imitationInsert, 0, result, plainTextWithAdditionalAuthenticatedData.length, imitationInsert.length);
        return result;
    }

    @Override
    public byte[] decryptMessage(byte[] cipherText) {
        byte[] additionalAuthenticatedData = Arrays.copyOf(cipherText, additionalAuthenticatedDataLengthInBytes);
        byte[] cipherData = Arrays.copyOfRange(cipherText, additionalAuthenticatedDataLengthInBytes, cipherText.length - gammaLengthInBytes);
        byte[] computedImitationInsert = computeImitationInsert(additionalAuthenticatedData, cipherData);
        byte[] realImitationInsert = Arrays.copyOfRange(cipherText, cipherText.length - gammaLengthInBytes, cipherText.length);
        if (!Arrays.equals(computedImitationInsert, realImitationInsert)) {
            return null;
        }
        byte[] plainText = encryptPlainData(cipherData, encryptionAlgorithm.encryptOneBlock(initializationVector));
        byte[] result = new byte[cipherText.length - gammaLengthInBytes];
        System.arraycopy(additionalAuthenticatedData, 0, result, 0, additionalAuthenticatedDataLengthInBytes);
        System.arraycopy(plainText, 0, result, additionalAuthenticatedDataLengthInBytes, cipherData.length);
        return result;
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
        if (initializationVector[0] < 0)
            this.initializationVector[0] ^= 0x80;
    }

    @Override
    public byte[] getInitializationVector() {
        return initializationVector;
    }

    private byte[] computeImitationInsert(byte[] additionalAuthenticatedData, byte[] cipherData) {
        byte[] gammaForH = Arrays.copyOf(initializationVector, initializationVector.length);
        gammaForH[0] ^= 0x80;
        gammaForH = encryptionAlgorithm.encryptOneBlock(gammaForH);
        byte[] currentImitationInsert = new byte[blockSizeInBytes];
        computeCurrentImitationInsertFromData(additionalAuthenticatedData, gammaForH, currentImitationInsert);
        computeCurrentImitationInsertFromData(cipherData, gammaForH, currentImitationInsert);
        byte[] lastBlock = convertLongArrayToByteArray(new long[]{additionalAuthenticatedData.length * 8L, (cipherData.length) * 8L});
        iterationOfComputationOfImitationInsert(lastBlock, getNextH(gammaForH), currentImitationInsert);
        return Arrays.copyOf(encryptionAlgorithm.encryptOneBlock(currentImitationInsert), gammaLengthInBytes);
    }


    private void computeCurrentImitationInsertFromData(byte[] data, byte[] gammaForH, byte[] currentImitationInsert) {
        byte[] currentH;
        byte[] currentData;
        for (int i = 0; i < data.length; i += blockSizeInBytes) {
            currentH = getNextH(gammaForH);
            currentData = Arrays.copyOfRange(data, i, Math.min(i + blockSizeInBytes, data.length));
            if (currentData.length != blockSizeInBytes)
                currentData = Arrays.copyOf(currentData, blockSizeInBytes);
            iterationOfComputationOfImitationInsert(currentData, currentH, currentImitationInsert);
        }
    }

    private void iterationOfComputationOfImitationInsert(byte[] data, byte[] h, byte[] currentImitationInsert) {
        byte[] productOfDataAndH = multiplyPolynomialsModPrimitivePolynomial(data, h, primitivePolynomial);
        xorByteArrays(currentImitationInsert, productOfDataAndH);
    }

    private byte[] encryptPlainData(byte[] plainData, byte[] firstGamma) {
        int remainder = plainData.length % blockSizeInBytes;
        byte[] blockOfPlainText;
        byte[] encryptedBlock;
        byte[] encryptedData = new byte[plainData.length];
        for (int i = 0; i < plainData.length; i += blockSizeInBytes) {
            if (i != plainData.length - remainder) {
                blockOfPlainText = Arrays.copyOfRange(plainData, i, i + blockSizeInBytes);
            } else blockOfPlainText = Arrays.copyOfRange(plainData, i, plainData.length);
            encryptedBlock = encryptionAlgorithm.encryptOneBlock(firstGamma);
            xorByteArrays(encryptedBlock, blockOfPlainText);
            System.arraycopy(encryptedBlock, 0, encryptedData, i, blockOfPlainText.length);
            EncryptionModesUtils.rightIncrementGamma(firstGamma);
        }
        return encryptedData;
    }

    private byte[] getNextH(byte[] currentGamma) {
        byte[] nextH = new byte[blockSizeInBytes];
        System.arraycopy(encryptionAlgorithm.encryptOneBlock(currentGamma), 0, nextH, 0, blockSizeInBytes);
        leftIncrementGamma(currentGamma);
        return nextH;
    }


    public static void main(String[] args) {
        /*GOST34122015 gost34122015 = new GOST34122015(new byte[]{(byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xdd, (byte) 0xee, (byte) 0xff,
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0xfe, (byte) 0xdc, (byte) 0xba, (byte) 0x98,
                0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef});
        byte[] iv = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, (byte) 0xFF, (byte) 0xee, (byte) 0xDD, (byte) 0xcc, (byte) 0xbb,
                (byte) 0xaa, (byte) 0x99, (byte) 0x88};
        byte[] pt1 = new byte[]{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, (byte) 0xff, (byte) 0xee, (byte) 0xdd, (byte) 0xcc, (byte) 0xbb, (byte) 0xaa, (byte) 0x99,
                (byte) 0x88, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xee, (byte) 0xff,
                0x0a, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb,
                (byte) 0xcc, (byte) 0xee, (byte) 0xff, 0x0a, 0x00, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99,
                (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xee, (byte) 0xff, 0x0a, 0x00, 0x11, (byte) 0xaa, (byte) 0xbb, (byte) 0xcc};
        byte[] ad = new byte[]{0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                0x04, 0x04, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, (byte) 0xea, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05};
        System.out.println(ad.length);
        System.out.println(pt1.length);
        byte[] data = new byte[]{0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                0x04, 0x04, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, (byte) 0xea, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x11, 0x22, 0x33, 0x44,
                0x55, 0x66, 0x77, 0x00, (byte) 0xff, (byte) 0xee, (byte) 0xdd, (byte) 0xcc, (byte) 0xbb, (byte) 0xaa, (byte) 0x99,
                (byte) 0x88, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xee, (byte) 0xff,
                0x0a, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb,
                (byte) 0xcc, (byte) 0xee, (byte) 0xff, 0x0a, 0x00, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99,
                (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xee, (byte) 0xff, 0x0a, 0x00, 0x11, (byte) 0xaa, (byte) 0xbb, (byte) 0xcc};
        System.out.println(data.length);
        EncryptionAlgorithmWithMGM encryptionAlgorithmWithMGM = new EncryptionAlgorithmWithMGM(gost34122015, iv.length, 41);
        encryptionAlgorithmWithMGM.setInitializationVector(iv);
        byte[] ct = encryptionAlgorithmWithMGM.encryptMessage(data);
        printByteArrayHexFormat(ct);
        byte[] pt = encryptionAlgorithmWithMGM.decryptMessage(ct);
        printByteArrayHexFormat(pt);*/
    }
}
