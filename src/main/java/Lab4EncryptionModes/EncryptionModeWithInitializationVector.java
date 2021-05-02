package Lab4EncryptionModes;

public interface EncryptionModeWithInitializationVector {
    /**
     * Устанавливает вектор инициализации
     *
     * @param initializationVector желаемый вектор инициализации
     * @author ILya Ryzhov
     */
    void setInitializationVector(byte[] initializationVector);

    /**
     * Возвращает вектор инициализации
     *
     * @return вектор инициализации
     * @author ILya Ryzhov
     */
    byte[] getInitializationVector();
}
