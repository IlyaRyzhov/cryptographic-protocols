package Lab4EncryptionModes;

import Lab1EncryptionAlgorithm.EncryptionAlgorithm;
import Lab1EncryptionAlgorithm.GOST34122015;
import Utils.EncryptionModesUtils;

import java.io.File;
import java.util.Arrays;

import static Utils.CommonUtils.convertLongArrayToByteArray;
import static Utils.CommonUtils.printByteArrayHexFormat;
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

    protected EncryptionAlgorithmWithMGM(EncryptionAlgorithm encryptionAlgorithm, int gammaLengthInBytes, int additionalAuthenticatedDataLengthInBytes) {
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
        byte[] gammaForH = Arrays.copyOf(initializationVector, initializationVector.length);
        gammaForH[0] ^= 0x80;
        gammaForH = encryptionAlgorithm.encryptOneBlock(gammaForH);
        byte[] currentH;
        byte[] currentAdditionalAuthenticationData;
        byte[] currentImitationInsert = new byte[blockSizeInBytes];
        for (int i = 0; i < additionalAuthenticatedDataLengthInBytes; i += blockSizeInBytes) {
            currentH = getNextH(gammaForH);
            currentAdditionalAuthenticationData = Arrays.copyOfRange(plainTextWithAdditionalAuthenticatedData, i, Math.min(i + blockSizeInBytes, additionalAuthenticatedDataLengthInBytes));
            if (currentAdditionalAuthenticationData.length != blockSizeInBytes)
                currentAdditionalAuthenticationData = Arrays.copyOf(currentAdditionalAuthenticationData, blockSizeInBytes);
            iterationOfComputationOfImitationInsert(currentAdditionalAuthenticationData, currentH, currentImitationInsert);
        }
        byte[] plainData = Arrays.copyOfRange(plainTextWithAdditionalAuthenticatedData, additionalAuthenticatedDataLengthInBytes, plainTextWithAdditionalAuthenticatedData.length);
        byte[] cipherData = encryptPlainData(plainData, encryptionAlgorithm.encryptOneBlock(initializationVector));
        byte[] currentCipherData;
        for (int i = 0; i < cipherData.length; i += blockSizeInBytes) {
            currentH = getNextH(gammaForH);
            currentCipherData = Arrays.copyOfRange(cipherData, i, Math.min(i + blockSizeInBytes, cipherData.length));
            if (currentCipherData.length != blockSizeInBytes)
                currentCipherData = Arrays.copyOf(currentCipherData, blockSizeInBytes);
            iterationOfComputationOfImitationInsert(currentCipherData, currentH, currentImitationInsert);
        }
        currentH = getNextH(gammaForH);
        long[] lastBlock = {additionalAuthenticatedDataLengthInBytes * 8L, (plainTextWithAdditionalAuthenticatedData.length - additionalAuthenticatedDataLengthInBytes) * 8L};
        currentCipherData = convertLongArrayToByteArray(lastBlock);
        iterationOfComputationOfImitationInsert(currentCipherData, currentH, currentImitationInsert);
        byte[] imitationInsert = Arrays.copyOf(encryptionAlgorithm.encryptOneBlock(currentImitationInsert), gammaLengthInBytes);
        byte[] result = new byte[plainTextWithAdditionalAuthenticatedData.length + imitationInsert.length];
        System.arraycopy(plainTextWithAdditionalAuthenticatedData, 0, result, 0, additionalAuthenticatedDataLengthInBytes);
        System.arraycopy(cipherData, 0, result, additionalAuthenticatedDataLengthInBytes, cipherData.length);
        System.arraycopy(imitationInsert,0,result,plainTextWithAdditionalAuthenticatedData.length,imitationInsert.length);
        return result;
/*        int numberOfBlocksInAdditionalData = (int) Math.ceil((double) additionalAuthenticatedDataLengthInBytes / blockSizeInBytes);
        int paddedAdditionalDataLength = numberOfBlocksInAdditionalData * blockSizeInBytes;
        byte[] paddedAdditionalData = new byte[paddedAdditionalDataLength];
        System.arraycopy(plainTextWithAdditionalData, 0, paddedAdditionalData, 0, additionalAuthenticatedDataLengthInBytes);
        byte[] plainData = Arrays.copyOfRange(plainTextWithAdditionalData, additionalAuthenticatedDataLengthInBytes, plainTextWithAdditionalData.length);
        byte[] cipherData = encryptPlainData(plainData, encryptionAlgorithm.encryptOneBlock(initializationVector));//? mb error
        int numberOfBlocksInCipherData = (int) Math.ceil((double) cipherData.length / blockSizeInBytes);
        int paddedCipherDataLength = numberOfBlocksInCipherData * blockSizeInBytes;
        byte[] paddedCipherData = Arrays.copyOf(cipherData, paddedCipherDataLength);
        byte[] gammaForHVector = Arrays.copyOf(initializationVector, initializationVector.length);
        gammaForHVector[0] ^= 0x80;
        gammaForHVector = encryptionAlgorithm.encryptOneBlock(gammaForHVector);
        byte[] imitationInsert = new byte[blockSizeInBytes];
        byte[] currentH;
        byte[] currentA;
        byte[] currentC;
        byte[] product;
        for (int i = 0; i < paddedAdditionalDataLength; i += blockSizeInBytes) {
            currentH = getNextH(gammaForHVector);
            currentA = Arrays.copyOfRange(paddedAdditionalData, i, i + blockSizeInBytes);
            product = multiplyPolynomialsModPrimitivePolynomial(currentA, currentH);
            xorByteArrays(imitationInsert, product);
        }
        for (int i = 0; i < paddedCipherDataLength; i += blockSizeInBytes) {
            currentH = getNextH(gammaForHVector);
            currentC = Arrays.copyOfRange(paddedCipherData, i, i + blockSizeInBytes);
            product = multiplyPolynomialsModPrimitivePolynomial(currentC, currentH);
            xorByteArrays(imitationInsert, product);
        }
        long[] lastBlock = {additionalAuthenticatedDataLengthInBytes * 8L, (plainTextWithAdditionalData.length - additionalAuthenticatedDataLengthInBytes) * 8L};
        currentC = convertLongArrayToByteArray(lastBlock);
        currentH = getNextH(gammaForHVector);
        product = multiplyPolynomialsModPrimitivePolynomial(currentC, currentH);
        xorByteArrays(imitationInsert, product);
        imitationInsert = Arrays.copyOf(encryptionAlgorithm.encryptOneBlock(imitationInsert), gammaLengthInBytes);
        byte[] result = new byte[additionalAuthenticatedDataLengthInBytes + cipherData.length + imitationInsert.length];
        System.arraycopy(Arrays.copyOf(paddedAdditionalData, additionalAuthenticatedDataLengthInBytes), 0, result, 0, additionalAuthenticatedDataLengthInBytes);
        System.arraycopy(cipherData, 0, result, additionalAuthenticatedDataLengthInBytes, cipherData.length);
        System.arraycopy(imitationInsert, 0, result, cipherData.length + additionalAuthenticatedDataLengthInBytes, imitationInsert.length);
        return result;*/
    }

    @Override
    public byte[] decryptMessage(byte[] cipherText) {
      /*  int numberOfBlocksInAdditionalData = (int) Math.ceil((double) additionalAuthenticatedDataLengthInBytes / blockSizeInBytes);
        int paddedAdditionalDataLength = numberOfBlocksInAdditionalData * blockSizeInBytes;
        byte[] paddedAdditionalData = new byte[paddedAdditionalDataLength];
        System.arraycopy(cipherText, 0, paddedAdditionalData, 0, additionalAuthenticatedDataLengthInBytes);
        byte[] cipherData = Arrays.copyOfRange(cipherText, additionalAuthenticatedDataLengthInBytes, cipherText.length - gammaLengthInBytes);
        int numberOfBlocksInCipherData = (int) Math.ceil((double) cipherData.length / blockSizeInBytes);
        int paddedCipherDataLength = numberOfBlocksInCipherData * blockSizeInBytes;
        byte[] paddedCipherData = Arrays.copyOf(cipherData, paddedCipherDataLength);
        byte[] gammaForHVector = Arrays.copyOf(initializationVector, initializationVector.length);
        gammaForHVector[0] ^= 0x80;
        gammaForHVector = encryptionAlgorithm.encryptOneBlock(gammaForHVector);
        byte[] hVector = getNextH(numberOfBlocksInAdditionalData + numberOfBlocksInCipherData + 1, gammaForHVector);
        byte[] computedImitationInsert = new byte[blockSizeInBytes];
*/
        return null;
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

    private void iterationOfComputationOfImitationInsert(byte[] data, byte[] h, byte[] currentImitationInsert) {
        byte[] productOfDataAndH = multiplyPolynomialsModPrimitivePolynomial(data, h);
        xorByteArrays(currentImitationInsert, productOfDataAndH);
    }

    public byte[] encryptPlainData(byte[] plainData, byte[] firstGamma) {
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

    //TODO исправить неправильно
    //TODO  другой инкремент, по первой половине, мб исправить и в других режимах
    //подается гамма (e(1||iv))
    public byte[] getNextH(byte[] currentGamma) {
        byte[] nextH = new byte[blockSizeInBytes];
        System.arraycopy(encryptionAlgorithm.encryptOneBlock(currentGamma), 0, nextH, 0, blockSizeInBytes);
        leftIncrementGamma(currentGamma);
        return nextH;
    }

    private byte[] multiplyPolynomialsModPrimitivePolynomial(byte[] firstPolynomial, byte[] secondPolynomial) {
        int degreeOfMonomial = 0;
        byte[] product = new byte[firstPolynomial.length];
        for (int i = secondPolynomial.length - 1; i >= 0; i--) {
            byte currentByte = secondPolynomial[i];
            for (int j = 0; j < 8; j++) {
                int lastBitOfByte = currentByte & 1;
                if (lastBitOfByte == 1) {
                    byte[] addendum = Arrays.copyOf(firstPolynomial, firstPolynomial.length);
                    for (int k = 0; k < degreeOfMonomial; k++) {
                        addendum = multiplyPolynomialByX(addendum);
                    }
                    addPolynomials(product, addendum);
                }
                currentByte >>>= 1;
                degreeOfMonomial++;
            }
        }
        return product;
    }

    //polynomial- 16bytes
    private void polynomialModPrimitive(byte[] polynomial) {
        polynomial[15] ^= primitivePolynomial[16];
    }

    private void addPolynomials(byte[] firstPolynomial, byte[] secondPolynomial) {
        for (int i = 0; i < firstPolynomial.length; i++) {
            firstPolynomial[i] ^= secondPolynomial[i];
        }
    }

    //poly-16bytes
    private byte[] multiplyPolynomialByX(byte[] polynomial) {
        byte[] polynomialCopy = Arrays.copyOf(polynomial, polynomial.length);
        int previousByteFirstBit = 0;
        int currentByteFirstBit;
        for (int i = polynomialCopy.length - 1; i >= 0; i--) {
            if (polynomialCopy[i] < 0) {
                currentByteFirstBit = 1;
            } else currentByteFirstBit = 0;
            polynomialCopy[i] <<= 1;
            polynomialCopy[i] ^= previousByteFirstBit;
            previousByteFirstBit = currentByteFirstBit;
            if (i == 0 && currentByteFirstBit == 1)
                polynomialModPrimitive(polynomialCopy);
        }
        return polynomialCopy;
    }

    public static void main(String[] args) {
        GOST34122015 gost34122015 = new GOST34122015(new byte[]{(byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xdd, (byte) 0xee, (byte) 0xff,
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
        printByteArrayHexFormat(encryptionAlgorithmWithMGM.encryptMessage(data));

    }
}
