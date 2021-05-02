package Lab4EncryptionModes;

import Lab1EncryptionAlgorithm.EncryptionAlgorithm;

import java.io.*;
import java.util.Arrays;

import static Utils.CommonUtils.*;
import static Utils.EncryptionModesUtils.*;

class EncryptionAlgorithmWithCTRACPKM extends EncryptionAlgorithmAbstract implements EncryptionModeWithInitializationVector {
    private byte[] initializationVector;
    private final int gammaLengthInBytes;
    private final byte[] dSubstitution;
    private final int numberOfBlocksWithLengthOfGammaInSection;
    private final int lengthOfSectionInBytes;

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

    /**
     * @param encryptionAlgorithm     класс, реализующий интерфейс EncryptionAlgorithm
     * @param numberOfBlocksInSection количество блоков базового алгоритма шифрования в секции
     * @param gammaLengthInBytes      длина гаммы в байтах
     * @author ILya Ryzhov
     */
    public EncryptionAlgorithmWithCTRACPKM(EncryptionAlgorithm encryptionAlgorithm, int numberOfBlocksInSection, int gammaLengthInBytes) {
        super(encryptionAlgorithm);
        if (blockSizeInBytes % gammaLengthInBytes != 0)
            throw new IllegalArgumentException("Длина гаммы должна делить длину блока");
        initializationVector = new byte[blockSizeInBytes / 2];
        generateInitializationVector(initializationVector);
        this.gammaLengthInBytes = gammaLengthInBytes;
        this.lengthOfSectionInBytes = numberOfBlocksInSection * blockSizeInBytes;
        this.numberOfBlocksWithLengthOfGammaInSection = lengthOfSectionInBytes / gammaLengthInBytes;
        setBufferSize(DEFAULT_BUFFER_SIZE);
    }

    /**
     * @see EncryptionAlgorithmWithMode
     */
    @Override
    public byte[] encryptMessage(byte[] plainMessage) {
        byte[] encryptedMessage = new byte[plainMessage.length];
        byte[] counter = Arrays.copyOf(initializationVector, blockSizeInBytes);
        EncryptionAlgorithm encryptionAlgorithm = this.encryptionAlgorithm.getInstance();
        encryptDataInMessage(encryptionAlgorithm, plainMessage, encryptedMessage, counter, 0);
        return encryptedMessage;
    }

    private int encryptDataInMessage(EncryptionAlgorithm encryptionAlgorithm, byte[] plainMessage, byte[] encryptedMessage, byte[] counter, int numberOfProcessedBlocks) {
        int numberOfBlocksWithLengthOfGamma = (int) Math.ceil((double) plainMessage.length / gammaLengthInBytes);
        byte[] blockOfPlainText;
        for (int i = 0; i < numberOfBlocksWithLengthOfGamma; i++) {
            if (numberOfProcessedBlocks % numberOfBlocksWithLengthOfGammaInSection == 0 && numberOfProcessedBlocks != 0)
                encryptionAlgorithm.setKey(convertByteArrayToLongArray(getNextSectionKey(encryptionAlgorithm)));
            blockOfPlainText = Arrays.copyOfRange(plainMessage, i * gammaLengthInBytes, Math.min((i + 1) * gammaLengthInBytes, plainMessage.length));
            byte[] encryptedCounter = Arrays.copyOf(encryptionAlgorithm.encryptOneBlock(counter), blockOfPlainText.length);
            xorByteArrays(encryptedCounter, blockOfPlainText, blockOfPlainText.length);
            System.arraycopy(encryptedCounter, 0, encryptedMessage, i * gammaLengthInBytes, encryptedCounter.length);
            incrementCounter(counter);
            numberOfProcessedBlocks++;
        }
        return numberOfProcessedBlocks;
    }

    /**
     * @see EncryptionAlgorithmWithMode
     */
    @Override
    public byte[] decryptMessage(byte[] encryptedMessage) {
        return encryptMessage(encryptedMessage);
    }

    /**
     * @see EncryptionAlgorithmAbstract
     */
    @Override
    protected void setBufferSize(int bufferSize) {
        this.bufferSize = Math.max(bufferSize - bufferSize % lengthOfSectionInBytes, lengthOfSectionInBytes);
    }

    /**
     * @see EncryptionAlgorithmAbstract
     */
    @Override
    protected void encryptDataInFile(BufferedInputStream bufferedInputStream, BufferedOutputStream bufferedOutputStream) throws IOException {
        byte[] counter = Arrays.copyOf(initializationVector, blockSizeInBytes);
        EncryptionAlgorithm encryptionAlgorithm = this.encryptionAlgorithm.getInstance();
        int numberOfProcessedBlocksWithLengthOfGamma = 0;
        while (bufferedInputStream.available() > 0) {
            byte[] plainData = bufferedInputStream.readNBytes(bufferSize);
            byte[] encryptedData = new byte[plainData.length];
            numberOfProcessedBlocksWithLengthOfGamma += encryptDataInMessage(encryptionAlgorithm, plainData, encryptedData, counter, numberOfProcessedBlocksWithLengthOfGamma);
            bufferedOutputStream.write(encryptedData);
        }
    }

    /**
     * @see EncryptionAlgorithmAbstract
     */
    @Override
    protected void decryptDataInFile(BufferedInputStream bufferedInputStream, BufferedOutputStream bufferedOutputStream) throws IOException {
        encryptDataInFile(bufferedInputStream, bufferedOutputStream);
    }

    /**
     * @see EncryptionModeWithInitializationVector
     */
    @Override
    public void setInitializationVector(byte[] initializationVector) {
        this.initializationVector = initializationVector;
    }

    /**
     * @see EncryptionModeWithInitializationVector
     */
    @Override
    public byte[] getInitializationVector() {
        return new byte[0];
    }

    private byte[] getNextSectionKey(EncryptionAlgorithm currentEncryptionAlgorithm) {
        int keySizeInBytes = currentEncryptionAlgorithm.getKeySizeInBytes();
        int numberOfKeyParts = (int) Math.ceil((double) keySizeInBytes / blockSizeInBytes);
        byte[] nextKey = new byte[blockSizeInBytes * numberOfKeyParts];
        for (int i = 0; i < numberOfKeyParts; i++) {
            byte[] partOfNextKey = currentEncryptionAlgorithm.encryptOneBlock(Arrays.copyOfRange(dSubstitution, i * blockSizeInBytes, (i + 1) * blockSizeInBytes));
            System.arraycopy(partOfNextKey, 0, nextKey, i * blockSizeInBytes, blockSizeInBytes);
        }
        return Arrays.copyOf(nextKey, keySizeInBytes);
    }
}
