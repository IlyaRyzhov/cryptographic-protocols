package Lab4EncryptionModes;

import java.security.SecureRandom;
import java.util.Arrays;

public interface EncryptionModeWithInitializationVector {
    void setInitializationVector(byte[] initializationVector);

    byte[] getInitializationVector();

    default void generateInitializationVector(byte[] initializationVector) {
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(initializationVector);
    }

    default void shiftRegisterWithFillingLSB(byte[] register, byte[] fillingValue) {
        byte[] rightPartOfRegister = Arrays.copyOfRange(register, fillingValue.length, register.length);
        System.arraycopy(rightPartOfRegister, 0, register, 0, rightPartOfRegister.length);
        System.arraycopy(fillingValue, 0, register, rightPartOfRegister.length, fillingValue.length);
    }
}
