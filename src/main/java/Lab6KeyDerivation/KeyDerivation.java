package Lab6KeyDerivation;

import Lab2HashAlgorithm.HMAC;
import Lab2HashAlgorithm.HashFunction;
import Lab4EncryptionModes.AlgorithmWithInitializationVector;
import Utils.CommonUtils;

import java.util.Arrays;

import static Utils.EncryptionModesUtils.generateInitializationVector;
import static Utils.EncryptionModesUtils.incrementCounter;

public class KeyDerivation implements AlgorithmWithInitializationVector {
    private final HashFunction hashFunction;
    private byte[] initializationVector;
    private boolean[] formattingProcedureFlags;//f0..f7

    public KeyDerivation(HashFunction hashFunction, boolean[] formattingProcedureFlags) {
        this.hashFunction = hashFunction;
        initializationVector = new byte[64];
        generateInitializationVector(initializationVector);
        this.formattingProcedureFlags = formattingProcedureFlags;
    }

    /**
     * Генерирует производный ключ из исходного ключевого материала
     *
     * @param originalKey                  исходный ключ (S)
     * @param salt                         соль (T)
     * @param keyLength                    длина производного ключа в битах (L), должна быть кратна 8 (не больше 2147483640)
     * @param usageLabel                   метка использования (P)
     * @param informationAboutParticipants информация об участниках информационного обмена (U)
     * @param additionalInformation        некоторая дополнительная информация (A), используемая при выработке производной
     *                                     ключевой информации
     * @return производный ключевой материал
     * @author ILya Ryzhov
     */
    public byte[] generateDerivedKey(byte[] originalKey, byte[] salt, int keyLength,
                                     byte[] usageLabel, byte[] informationAboutParticipants, byte[] additionalInformation) {
        byte[] iterativeKey = Arrays.copyOf(initializationVector, initializationVector.length);//z
        int numberOfIterations = (int) Math.ceil((double) (keyLength / 8) / hashFunction.getOutputLength());
        byte[] counter = new byte[32];//C
        HMAC hmac = new HMAC(hashFunction, generateIntermediateKey(salt, originalKey));
        byte[] resultKey = new byte[numberOfIterations * hashFunction.getOutputLength()];
        for (int i = 1; i <= numberOfIterations; i++) {
            incrementCounter(counter);
            iterativeKey = hmac.computeMAC(format(iterativeKey, counter, usageLabel, informationAboutParticipants, additionalInformation, keyLength));
            System.arraycopy(iterativeKey, 0, resultKey, (i - 1) * iterativeKey.length, iterativeKey.length);
        }
        return Arrays.copyOf(resultKey, keyLength / 8);
    }

    private byte[] generateIntermediateKey(byte[] salt, byte[] originalKey) {
        HMAC hmac = new HMAC(hashFunction, salt);
        return Arrays.copyOf(hmac.computeMAC(originalKey), 32);
    }

    private byte[] format(byte[] iterativeKey, byte[] counter, byte[] usageLabel, byte[] informationAboutParticipants, byte[] additionalInformation, int keyLength) {
        byte[] formattedMessage = new byte[69 + counter.length + usageLabel.length + informationAboutParticipants.length + additionalInformation.length];
        byte f = 0;
        for (int i = 7; i >= 0; i--) {
            f <<= 1;
            if (formattingProcedureFlags[i])
                f ^= 1;
        }
        System.arraycopy(new byte[]{f}, 0, formattedMessage, 0, 1);
        int destinationIndex = 1;
        if (formattingProcedureFlags[7]) {//C
            System.arraycopy(counter, 0, formattedMessage, 1, counter.length);
        }
        destinationIndex += counter.length;
        if (formattingProcedureFlags[6]) {//z
            if (iterativeKey.length != 64) {
                byte[] paddedIterativeKey = new byte[64];
                System.arraycopy(iterativeKey, 0, paddedIterativeKey, paddedIterativeKey.length - iterativeKey.length, iterativeKey.length);
                System.arraycopy(paddedIterativeKey, 0, formattedMessage, destinationIndex, paddedIterativeKey.length);
            } else System.arraycopy(iterativeKey, 0, formattedMessage, destinationIndex, iterativeKey.length);
        }
        destinationIndex += 64;
        if (formattingProcedureFlags[5]) {//L
            System.arraycopy(CommonUtils.convertIntArrayToByteArray(new int[]{keyLength}), 0, formattedMessage, destinationIndex, 4);
        }
        destinationIndex += 4;
        if (formattingProcedureFlags[4]) {//P
            System.arraycopy(usageLabel, 0, formattedMessage, destinationIndex, usageLabel.length);
        }
        destinationIndex += usageLabel.length;
        if (formattingProcedureFlags[3]) {//U
            System.arraycopy(informationAboutParticipants, 0, formattedMessage, destinationIndex, informationAboutParticipants.length);
        }
        destinationIndex += informationAboutParticipants.length;
        if (formattingProcedureFlags[2]) {//A
            System.arraycopy(additionalInformation, 0, formattedMessage, destinationIndex, additionalInformation.length);
        }
        return formattedMessage;
    }

    /**
     * @see AlgorithmWithInitializationVector
     */
    @Override
    public void setInitializationVector(byte[] initializationVector) {
        this.initializationVector = initializationVector;
    }

    /**
     * @see AlgorithmWithInitializationVector
     */
    @Override
    public byte[] getInitializationVector() {
        return initializationVector;
    }

    /**
     * Возвращает флаги процедуры форматирования
     *
     * @return флаги процедуры форматирования
     * @author ILya Ryzhov
     */
    public boolean[] getFormattingProcedureFlags() {
        return formattingProcedureFlags;
    }

    /**
     * Устанавливает флаги процедуры форматирования
     *
     * @param formattingProcedureFlags новый массив флагов, сигнализирующих о существенной зависимости
     *                                 выхода процедуры форматирования от всех бит одного из входов
     * @author ILya Ryzhov
     */
    public void setFormattingProcedureFlags(boolean[] formattingProcedureFlags) {
        this.formattingProcedureFlags = formattingProcedureFlags;
    }
}
