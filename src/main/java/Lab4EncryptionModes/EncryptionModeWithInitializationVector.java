package Lab4EncryptionModes;

import java.security.SecureRandom;

public interface EncryptionModeWithInitializationVector {
    void setInitializationVector(byte[] initializationVector);

    byte[] getInitializationVector();

    default void generateInitializationVector(byte[] initializationVector) {
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(initializationVector);
    }
}
