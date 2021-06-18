package hashAlgorithm;

import java.io.File;

public interface HashFunction {
    /**
     * Вычисляет хеш сообщения
     *
     * @param message хешируемое сообщение
     * @return хеш сообщения
     * @author Ilya Ryzhov
     */
    byte[] computeHash(byte[] message);

    /**
     * Вычисляет хеш от файла
     *
     * @param file хешируемый файл
     * @return хеш файла
     * @author Ilya Ryzhov
     */
    byte[] computeHash(File file);

    /**
     * Возвращает длину блока в байтах, которая используется в хеш-функции
     *
     * @return длину блока в байтах
     * @author Ilya Ryzhov
     */
    int getBlockSize();

    /**
     * Возвращает длину выхода хеш-функции в байтах
     *
     * @return длина выхода хеш-функции в байтах
     * @author Ilya Ryzhov
     */
    int getOutputLength();
}
