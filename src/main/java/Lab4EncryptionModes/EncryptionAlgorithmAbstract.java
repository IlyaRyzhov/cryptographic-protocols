package Lab4EncryptionModes;

import Lab1EncryptionAlgorithm.EncryptionAlgorithm;

import java.security.SecureRandom;
import java.util.Arrays;

abstract class EncryptionAlgorithmAbstract implements EncryptionAlgorithmWithMode {
    protected final EncryptionAlgorithm encryptionAlgorithm;

    protected EncryptionAlgorithmAbstract(EncryptionAlgorithm encryptionAlgorithm) {
        this.encryptionAlgorithm = encryptionAlgorithm;
    }


    private int findLastOne(byte[] message) {
        int indexOfLastOne = 0;
        for (int i = message.length - 1; i >= 0; i--) {
            if (message[i] == 0x1) {
                indexOfLastOne = i;
                break;
            }
        }
        return indexOfLastOne;
    }

    protected final byte[] removePadding(byte[] message) {
        int indexOfLastOne = findLastOne(message);
        return Arrays.copyOfRange(message, 0, indexOfLastOne);
    }

    protected final byte[] padMessage(byte[] message) {
        byte[] paddedMessage = new byte[(message.length / encryptionAlgorithm.getBlockSizeInBytes() + 1) * encryptionAlgorithm.getBlockSizeInBytes()];
        System.arraycopy(message, 0, paddedMessage, 0, message.length);
        paddedMessage[message.length] = 1;
        return paddedMessage;
    }
}
