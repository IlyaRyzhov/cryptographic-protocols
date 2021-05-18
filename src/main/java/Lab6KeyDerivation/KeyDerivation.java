package Lab6KeyDerivation;

import Lab2HashAlgorithm.BlueMidnightWish;
import Lab2HashAlgorithm.BlueMidnightWishDigestSize;
import Lab2HashAlgorithm.HMAC;
import Lab2HashAlgorithm.HashFunction;
import Lab4EncryptionModes.EncryptionModeWithInitializationVector;
import Utils.CommonUtils;

import java.util.Arrays;

import static Utils.EncryptionModesUtils.generateInitializationVector;
import static Utils.EncryptionModesUtils.incrementCounter;

//TODO дописать тесты, поискать ошибки, верятно их много
public class KeyDerivation implements EncryptionModeWithInitializationVector {
    private final HashFunction hashFunction;
    private byte[] initializationVector;
    private boolean[] formattingProcedureFlags;//f0..f7

    public KeyDerivation(HashFunction hashFunction, boolean[] formattingProcedureFlags) {
        this.hashFunction = hashFunction;
        initializationVector = new byte[64];
        generateInitializationVector(initializationVector);
        this.formattingProcedureFlags = formattingProcedureFlags;
    }

    private byte[] generateIntermediateKey(byte[] salt, byte[] originalKey) {
        HMAC hmac = new HMAC(hashFunction, salt);
        return Arrays.copyOf(hmac.computeMAC(originalKey), 32);

    }

    public byte[] generateDerivedKey(byte[] originalKey, byte[] salt, int keyLength,
                                     byte[] usageLabel, byte[] informationAboutParticipants, byte[] additionalInformation) {//keyLength-длина ключа в битах, должна быть кратна 8, max=2147483640
        byte[] iterativeKey = Arrays.copyOf(initializationVector, initializationVector.length);
        int numberOfIterations = (int) Math.ceil((double) (keyLength / 8) / hashFunction.getOutputLength());
        byte[] counter = new byte[32];
        HMAC hmac = new HMAC(hashFunction, generateIntermediateKey(salt, originalKey));
        byte[] iterativeKeys = new byte[numberOfIterations * iterativeKey.length];
        for (int i = 1; i <= numberOfIterations; i++) {
            incrementCounter(counter);
            iterativeKey = hmac.computeMAC(format(iterativeKey, counter, usageLabel, informationAboutParticipants, additionalInformation, keyLength));
            System.arraycopy(iterativeKey, 0, iterativeKeys, (i - 1) * iterativeKey.length, iterativeKey.length);
        }
        int numberOfIterativeKeysAndUsageLabels = (int) Math.ceil((double) (keyLength / 8) / (usageLabel.length + iterativeKey.length));
        byte[] resultKey = new byte[numberOfIterativeKeysAndUsageLabels * ((usageLabel.length + iterativeKey.length))];
        int numberOfIterativeKey = 0;
        for (int i = 0; i < numberOfIterativeKeysAndUsageLabels; i++) {
            System.arraycopy(iterativeKeys, numberOfIterativeKey * iterativeKey.length, resultKey, i * (usageLabel.length + iterativeKey.length), iterativeKey.length);
            System.arraycopy(usageLabel, 0, resultKey, i * (usageLabel.length + iterativeKey.length) + iterativeKey.length, usageLabel.length);
            numberOfIterativeKey++;
        }
        return Arrays.copyOf(resultKey, keyLength / 8);
    }

    private byte[] format(byte[] iterativeKey/*z*/, byte[] counter/*C*/, byte[] usageLabel,/*P*/
                          byte[] informationAboutParticipants/*U*/, byte[] additionalInformation/*A*/, int keyLength/*L*/) {
        byte[] formattedMessage = new byte[5 + 7 * usageLabel.length + counter.length + iterativeKey.length
                + informationAboutParticipants.length + additionalInformation.length];
        byte f = 0;
        for (int i = 7; i >= 0; i--) {
            f <<= 1;
            if (formattingProcedureFlags[i])
                f ^= 1;
        }
        System.arraycopy(new byte[]{f}, 0, formattedMessage, 0, 1);

        if (formattingProcedureFlags[7]) {//C
            System.arraycopy(counter, 0, formattedMessage, 1 + usageLabel.length, counter.length);
        }
        if (formattingProcedureFlags[6]) {//z
            System.arraycopy(iterativeKey, 0, formattedMessage, 1 + 2 * usageLabel.length + counter.length, iterativeKey.length);
        }
        if (formattingProcedureFlags[5]) {//L
            System.arraycopy(CommonUtils.convertIntArrayToByteArray(new int[]{keyLength}), 0, formattedMessage, 1 + 3 * usageLabel.length + counter.length + iterativeKey.length, 4);
        }
        int destinationIndex = 1;
        if (formattingProcedureFlags[4]) {//P
            System.arraycopy(usageLabel, 0, formattedMessage, destinationIndex, usageLabel.length);
            destinationIndex += usageLabel.length + counter.length;
            System.arraycopy(usageLabel, 0, formattedMessage, destinationIndex, usageLabel.length);
            destinationIndex += usageLabel.length + iterativeKey.length;
            System.arraycopy(usageLabel, 0, formattedMessage, destinationIndex, usageLabel.length);
            destinationIndex += usageLabel.length + 4;
            for (int i = 0; i < 3; i++) {
                System.arraycopy(usageLabel, 0, formattedMessage, destinationIndex, usageLabel.length);
                destinationIndex += usageLabel.length;
            }
            destinationIndex += informationAboutParticipants.length;
            System.arraycopy(usageLabel, 0, formattedMessage, destinationIndex, usageLabel.length);
        }
        destinationIndex = 5 + counter.length + iterativeKey.length + 6 * usageLabel.length;
        if (formattingProcedureFlags[3]) {//U
            System.arraycopy(informationAboutParticipants, 0, formattedMessage, destinationIndex - informationAboutParticipants.length, informationAboutParticipants.length);
        }
        if (formattingProcedureFlags[2]) {//A
            System.arraycopy(additionalInformation, 0, formattedMessage, destinationIndex + usageLabel.length, additionalInformation.length);
        }
        return formattedMessage;
    }

    @Override
    public void setInitializationVector(byte[] initializationVector) {
        this.initializationVector = initializationVector;
    }

    @Override
    public byte[] getInitializationVector() {
        return initializationVector;
    }

    public boolean[] getFormattingProcedureFlags() {
        return formattingProcedureFlags;
    }

    public void setFormattingProcedureFlags(boolean[] formattingProcedureFlags) {
        this.formattingProcedureFlags = formattingProcedureFlags;
    }

    public static void main(String[] args) {
        KeyDerivation keyDerivation = new KeyDerivation(new BlueMidnightWish(BlueMidnightWishDigestSize.BLUE_MIDNIGHT_WISH_512),
                new boolean[]{false, false, true, true, false, false, true, true});
        keyDerivation.setInitializationVector(new byte[64]);
        System.out.println(keyDerivation.generateDerivedKey(CommonUtils.convertLongArrayToByteArray(new long[4]), CommonUtils.convertLongArrayToByteArray(new long[2]), 2147483640, new byte[4], new byte[4], new byte[4]));
    }
}
