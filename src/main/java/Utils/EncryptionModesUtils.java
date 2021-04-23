package Utils;

public class EncryptionModesUtils {
    public static void incrementCounter(byte[] counter) {
        for (int i = counter.length - 1; i >= 0; i--) {
            counter[i]++;
            if (counter[i] != 0)
                break;
        }
    }

    public static void rightIncrementGamma(byte[] gamma) {
        for (int i = gamma.length - 1; i >= gamma.length / 2; i--) {
            gamma[i]++;
            if (gamma[i] != 0)
                break;
        }
    }

    public static void leftIncrementGamma(byte[] gamma) {
        for (int i = gamma.length / 2 - 1; i >= 0; i--) {
            gamma[i]++;
            if (gamma[i] != 0)
                break;
        }
    }

    public static void xorByteArrays(byte[] firstArray, byte[] secondArray) {
        for (int i = 0; i < secondArray.length; i++) {
            firstArray[i] ^= secondArray[i];
        }
    }
}
