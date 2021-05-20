package Lab4EncryptionModes;

public interface AlgorithmWithInitializationVector {
    /**
     * Устанавливает вектор инициализации
     *
     * @param initializationVector желаемый вектор инициализации
     * @author Ilya Ryzhov
     */
    void setInitializationVector(byte[] initializationVector);

    /**
     * Возвращает вектор инициализации
     *
     * @return вектор инициализации
     * @author Ilya Ryzhov
     */
    byte[] getInitializationVector();
}
