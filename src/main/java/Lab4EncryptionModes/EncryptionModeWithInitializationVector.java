package Lab4EncryptionModes;

public interface EncryptionModeWithInitializationVector {
    void setInitializationVector(byte[] initializationVector);

    //TODO убрать этот метод, мб вектор инициализации секретный, если не будет использоваться
    byte[] getInitializationVector();
}
