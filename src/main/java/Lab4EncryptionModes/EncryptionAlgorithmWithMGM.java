package Lab4EncryptionModes;

import Lab1EncryptionAlgorithm.EncryptionAlgorithm;
import Utils.EncryptionModesUtils;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.util.Arrays;

import static Utils.CommonUtils.convertLongArrayToByteArray;
import static Utils.EncryptionModesUtils.*;

class EncryptionAlgorithmWithMGM extends EncryptionAlgorithmAbstract implements EncryptionModeWithInitializationVector {
    private byte[] initializationVector;
    private final int gammaLengthInBytes;
    private final int additionalAuthenticatedDataLengthInBytes;

    private static final byte[] primitivePolynomial;

    static {
        primitivePolynomial = new byte[17];
        primitivePolynomial[0] = 1;
        primitivePolynomial[16] = (byte) 0b10000111;
    }

    /**
     * @param encryptionAlgorithm                      класс, реализующий интерфейс EncryptionAlgorithm
     * @param gammaLengthInBytes                       длина гаммы в байтах
     * @param additionalAuthenticatedDataLengthInBytes длина дополнительных имитозащищаемых данных в байтах
     * @author ILya Ryzhov
     */
    public EncryptionAlgorithmWithMGM(EncryptionAlgorithm encryptionAlgorithm, int gammaLengthInBytes, int additionalAuthenticatedDataLengthInBytes) {
        super(encryptionAlgorithm);
        initializationVector = new byte[encryptionAlgorithm.getBlockSizeInBytes()];
        generateInitializationVector(initializationVector);
        if (initializationVector[0] < 0)
            initializationVector[0] ^= 0x80;
        this.gammaLengthInBytes = gammaLengthInBytes;
        this.additionalAuthenticatedDataLengthInBytes = additionalAuthenticatedDataLengthInBytes;
        setBufferSize(DEFAULT_BUFFER_SIZE);
    }

    /**
     * @see EncryptionAlgorithmWithMode
     */
    @Override
    public byte[] encryptMessage(byte[] plainTextWithAdditionalAuthenticatedData) {
        byte[] additionalAuthenticatedData = Arrays.copyOf(plainTextWithAdditionalAuthenticatedData, additionalAuthenticatedDataLengthInBytes);
        byte[] plainData = Arrays.copyOfRange(plainTextWithAdditionalAuthenticatedData, additionalAuthenticatedDataLengthInBytes, plainTextWithAdditionalAuthenticatedData.length);
        byte[] encryptedData = encryptPlainData(plainData, encryptionAlgorithm.encryptOneBlock(initializationVector));
        byte[] imitationInsert = computeImitationInsert(additionalAuthenticatedData, encryptedData);
        byte[] result = new byte[plainTextWithAdditionalAuthenticatedData.length + imitationInsert.length];
        System.arraycopy(plainTextWithAdditionalAuthenticatedData, 0, result, 0, additionalAuthenticatedDataLengthInBytes);
        System.arraycopy(encryptedData, 0, result, additionalAuthenticatedDataLengthInBytes, encryptedData.length);
        System.arraycopy(imitationInsert, 0, result, plainTextWithAdditionalAuthenticatedData.length, imitationInsert.length);
        return result;
    }

    /**
     * @see EncryptionAlgorithmWithMode
     */
    @Override
    public byte[] decryptMessage(byte[] encryptedMessage) {
        byte[] additionalAuthenticatedData = Arrays.copyOf(encryptedMessage, additionalAuthenticatedDataLengthInBytes);
        byte[] encryptedData = Arrays.copyOfRange(encryptedMessage, additionalAuthenticatedDataLengthInBytes, encryptedMessage.length - gammaLengthInBytes);
        byte[] computedImitationInsert = computeImitationInsert(additionalAuthenticatedData, encryptedData);
        byte[] realImitationInsert = Arrays.copyOfRange(encryptedMessage, encryptedMessage.length - gammaLengthInBytes, encryptedMessage.length);
        if (!Arrays.equals(computedImitationInsert, realImitationInsert)) {
            return null;
        }
        byte[] plainData = encryptPlainData(encryptedData, encryptionAlgorithm.encryptOneBlock(initializationVector));
        byte[] result = new byte[encryptedMessage.length - gammaLengthInBytes];
        System.arraycopy(additionalAuthenticatedData, 0, result, 0, additionalAuthenticatedDataLengthInBytes);
        System.arraycopy(plainData, 0, result, additionalAuthenticatedDataLengthInBytes, encryptedData.length);
        return result;
    }

    /**
     * @see EncryptionAlgorithmAbstract
     */
    @Override
    protected void encryptDataInFile(BufferedInputStream bufferedInputStream, BufferedOutputStream bufferedOutputStream) throws IOException {
        byte[] gammaForH = getGammaForH();
        byte[] currentImitationInsert = new byte[blockSizeInBytes];
        int lengthOfEncryptedDataInBytes = bufferedInputStream.available() - additionalAuthenticatedDataLengthInBytes;
        getImitationInsertFromAADInFile(bufferedInputStream, bufferedOutputStream, gammaForH, currentImitationInsert);
        byte[] gammaForEncryptedData = encryptionAlgorithm.encryptOneBlock(initializationVector);
        while (bufferedInputStream.available() > 0) {
            byte[] plainData = bufferedInputStream.readNBytes(bufferSize);
            byte[] encryptedData = encryptPlainData(plainData, gammaForEncryptedData);
            computeCurrentImitationInsertFromData(encryptedData, gammaForH, currentImitationInsert);
            bufferedOutputStream.write(encryptedData);
        }
        byte[] lastBlock = convertLongArrayToByteArray(new long[]{additionalAuthenticatedDataLengthInBytes * 8L, lengthOfEncryptedDataInBytes * 8L});
        iterationOfComputationOfImitationInsert(lastBlock, getNextH(gammaForH), currentImitationInsert);
        bufferedOutputStream.write(Arrays.copyOf(encryptionAlgorithm.encryptOneBlock(currentImitationInsert), gammaLengthInBytes));
    }

    /**
     * @see EncryptionAlgorithmAbstract
     */
    @Override
    protected void decryptDataInFile(BufferedInputStream bufferedInputStream, BufferedOutputStream bufferedOutputStream) throws IOException {
        byte[] gammaForH = getGammaForH();
        byte[] currentImitationInsert = new byte[blockSizeInBytes];
        int lengthOfEncryptedDataInBytes = bufferedInputStream.available() - additionalAuthenticatedDataLengthInBytes - gammaLengthInBytes;
        int remainderLengthOfEncryptedDataInBytes = lengthOfEncryptedDataInBytes;//bufferedInputStream.available() - additionalAuthenticatedDataLengthInBytes - gammaLengthInBytes;
        getImitationInsertFromAADInFile(bufferedInputStream, bufferedOutputStream, gammaForH, currentImitationInsert);
        byte[] gammaForEncryptedData = encryptionAlgorithm.encryptOneBlock(initializationVector);
        while (remainderLengthOfEncryptedDataInBytes != 0) {
            byte[] encryptedData = bufferedInputStream.readNBytes(Math.min(bufferSize, remainderLengthOfEncryptedDataInBytes));
            computeCurrentImitationInsertFromData(encryptedData, gammaForH, currentImitationInsert);
            byte[] decryptedData = encryptPlainData(encryptedData, gammaForEncryptedData);
            bufferedOutputStream.write(decryptedData);
            remainderLengthOfEncryptedDataInBytes -= encryptedData.length;
        }
        byte[] realImitationInsert = bufferedInputStream.readNBytes(gammaLengthInBytes);
        byte[] lastBlock = convertLongArrayToByteArray(new long[]{additionalAuthenticatedDataLengthInBytes * 8L, lengthOfEncryptedDataInBytes * 8L});
        iterationOfComputationOfImitationInsert(lastBlock, getNextH(gammaForH), currentImitationInsert);
        currentImitationInsert = Arrays.copyOf(encryptionAlgorithm.encryptOneBlock(currentImitationInsert), gammaLengthInBytes);
        if (!Arrays.equals(currentImitationInsert, realImitationInsert)) {
            throw new IOException("Зашифрованный файл был поврежден");
        }
    }

    private void getImitationInsertFromAADInFile(BufferedInputStream inputStream, BufferedOutputStream outputStream, byte[] gammaForH, byte[] currentInsert) throws IOException {
        int remainderAdditionalAuthenticatedData = additionalAuthenticatedDataLengthInBytes;
        while (remainderAdditionalAuthenticatedData != 0) {
            byte[] additionalAuthenticatedData = inputStream.readNBytes(Math.min(bufferSize, remainderAdditionalAuthenticatedData));
            computeCurrentImitationInsertFromData(additionalAuthenticatedData, gammaForH, currentInsert);
            outputStream.write(additionalAuthenticatedData);
            remainderAdditionalAuthenticatedData -= additionalAuthenticatedData.length;
        }
    }

    private byte[] computeImitationInsert(byte[] additionalAuthenticatedData, byte[] encryptedData) {
        byte[] gammaForH = getGammaForH();
        byte[] currentImitationInsert = new byte[blockSizeInBytes];
        computeCurrentImitationInsertFromData(additionalAuthenticatedData, gammaForH, currentImitationInsert);
        computeCurrentImitationInsertFromData(encryptedData, gammaForH, currentImitationInsert);
        byte[] lastBlock = convertLongArrayToByteArray(new long[]{additionalAuthenticatedData.length * 8L, encryptedData.length * 8L});
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
        xorByteArrays(currentImitationInsert, productOfDataAndH, currentImitationInsert.length);
    }

    private byte[] encryptPlainData(byte[] plainData, byte[] firstGamma) {
        byte[] plainBlock;
        byte[] encryptedBlock;
        byte[] encryptedData = new byte[plainData.length];
        for (int i = 0; i < plainData.length; i += blockSizeInBytes) {
            plainBlock = Arrays.copyOfRange(plainData, i, Math.min(i + blockSizeInBytes, plainData.length));
            encryptedBlock = encryptionAlgorithm.encryptOneBlock(firstGamma);
            xorByteArrays(encryptedBlock, plainBlock, plainBlock.length);
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

    private byte[] getGammaForH() {
        byte[] gammaForH = Arrays.copyOf(initializationVector, initializationVector.length);
        gammaForH[0] ^= 0x80;
        gammaForH = encryptionAlgorithm.encryptOneBlock(gammaForH);
        return gammaForH;
    }

    /**
     * @see EncryptionModeWithInitializationVector
     */
    @Override
    public void setInitializationVector(byte[] initializationVector) {
        this.initializationVector = initializationVector;
        if (initializationVector[0] < 0)
            this.initializationVector[0] ^= 0x80;
    }

    /**
     * @see EncryptionModeWithInitializationVector
     */
    @Override
    public byte[] getInitializationVector() {
        return initializationVector;
    }

    /**
     * @see EncryptionAlgorithmAbstract
     */
    @Override
    protected void setBufferSize(int bufferSize) {
        this.bufferSize = Math.max(bufferSize - bufferSize % blockSizeInBytes, blockSizeInBytes);
    }
}
