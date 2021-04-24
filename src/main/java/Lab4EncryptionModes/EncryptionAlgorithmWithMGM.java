package Lab4EncryptionModes;

import Lab1EncryptionAlgorithm.EncryptionAlgorithm;
import Utils.EncryptionModesUtils;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.IOException;
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

/*
    //TODO переделать работу с файлом
    @Override
    public void encryptFile(File fileToEncrypt, String pathForEncryptedFile) {

    }

    //TODO переделать работу с файлом
    @Override
    public void decryptFile(File fileToDecrypt, String pathForDecryptedFile) {

    }
*/

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
        byte[] plainBlock;
        byte[] encryptedBlock;
        byte[] encryptedData = new byte[plainData.length];
        for (int i = 0; i < plainData.length; i += blockSizeInBytes) {
            plainBlock = Arrays.copyOfRange(plainData, i, Math.min(i + blockSizeInBytes, plainData.length));
            encryptedBlock = encryptionAlgorithm.encryptOneBlock(firstGamma);
            xorByteArrays(encryptedBlock, plainBlock);
            System.arraycopy(encryptedBlock, 0, encryptedData, i, plainBlock.length);
            EncryptionModesUtils.rightIncrementGamma(firstGamma);
        }
        return encryptedData;
    }

    private byte[] getNextH(byte[] currentGamma) {
        byte[] nextH = encryptionAlgorithm.encryptOneBlock(currentGamma);
        leftIncrementGamma(currentGamma);
        return nextH;
    }

    @Override
    protected void encryptDataInFile(BufferedInputStream bufferedInputStream, BufferedOutputStream bufferedOutputStream, int bufferSize) throws IOException {

    }

    @Override
    protected void decryptDataInFile(BufferedInputStream bufferedInputStream, BufferedOutputStream bufferedOutputStream, int bufferSize) throws IOException {

    }
}
