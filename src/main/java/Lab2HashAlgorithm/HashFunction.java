package Lab2HashAlgorithm;

import java.io.File;

public interface HashFunction {
    /**
     * Вычисляет хеш сообщения
     *
     * @param message хешируемое сообщение
     * @return хеш сообщения
     * @author ILya Ryzhov
     */
    byte[] computeHash(byte[] message);

    /**
     * Вычисляет хеш от файла
     *
     * @param file хешируемый файл
     * @return хеш файла
     * @author ILya Ryzhov
     */
    byte[] computeHashOfFile(File file);

    /**
     * Возвращает длину блока в байтах, которая используется в хеш-функции
     *
     * @return длину блока в байтах
     * @author ILya Ryzhov
     */
    int getBlockSize();

    /**
     * Возвращает длину выхода хеш-функции в байтах
     *
     * @return длина выхода хеш-функции в байтах
     * @author ILya Ryzhov
     */
    int getOutputLength();
}
