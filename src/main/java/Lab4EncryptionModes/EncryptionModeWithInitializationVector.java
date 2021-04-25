package Lab4EncryptionModes;

public interface EncryptionModeWithInitializationVector {
    void setInitializationVector(byte[] initializationVector);

    byte[] getInitializationVector();
}
