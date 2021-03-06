package Utils;

import java.security.SecureRandom;
import java.util.Arrays;

public class EncryptionModesUtils {
    /**
     * Увеличивает счетчик на 1
     *
     * @param counter счетчик
     * @author Ilya Ryzhov
     */
    public static void incrementCounter(byte[] counter) {
        for (int i = counter.length - 1; i >= 0; i--) {
            counter[i]++;
            if (counter[i] != 0)
                break;
        }
    }

    /**
     * Увеличивает правую половину гаммы на 1
     *
     * @param gamma гамма
     * @author Ilya Ryzhov
     */
    public static void rightIncrementGamma(byte[] gamma) {
        for (int i = gamma.length - 1; i >= gamma.length / 2; i--) {
            gamma[i]++;
            if (gamma[i] != 0)
                break;
        }
    }

    /**
     * Увеличивает левую половину гаммы на 1
     *
     * @param gamma гамма
     * @author Ilya Ryzhov
     */
    public static void leftIncrementGamma(byte[] gamma) {
        for (int i = gamma.length / 2 - 1; i >= 0; i--) {
            gamma[i]++;
            if (gamma[i] != 0)
                break;
        }
    }

    /**
     * Применяет исключающее или к numberOfElementsToXor элементам массива firstArray,
     * начиная с позиции offsetInSecondArray массива secondArray
     *
     * @param firstArray            массив, к элементам которого будет применена операция исключающее или
     *                              и в котором будет находиться результат
     * @param secondArray           массив, с элементами которого будет применяться операция исключающее или для первого массива
     * @param offsetInSecondArray   смещение во втором массиве
     * @param numberOfElementsToXor количество оперируемых элементов
     * @author Ilya Ryzhov
     */
    public static void xorByteArrays(byte[] firstArray, byte[] secondArray, int offsetInSecondArray, int numberOfElementsToXor) {
        for (int i = 0; i < numberOfElementsToXor; i++) {
            firstArray[i] ^= secondArray[i + offsetInSecondArray];
        }
    }

    /**
     * Применяет исключающее или к numberOfElementsToXor элементам массива firstArray
     * и элементам массива secondArray
     *
     * @param firstArray            массив, к элементам которого будет применена операция исключающее или
     *                              и в котором будет находиться результат
     * @param secondArray           массив, с элементами которого будет применяться операция исключающее или для первого массива
     * @param numberOfElementsToXor количество оперируемых элементов
     * @author Ilya Ryzhov
     */
    public static void xorByteArrays(byte[] firstArray, byte[] secondArray, int numberOfElementsToXor) {
        for (int i = 0; i < numberOfElementsToXor; i++) {
            firstArray[i] ^= secondArray[i];
        }
    }

    /**
     * Умножает многочлены по модулю примитивного многочлена 128-й степени
     *
     * @param firstPolynomial     первый полином
     * @param secondPolynomial    второй полином
     * @param primitivePolynomial примитивный полином 128-й степени
     * @return результат умножения двух многочленов по модулю примитивного полинома
     * @author Ilya Ryzhov
     */
    public static byte[] multiplyPolynomialsModPrimitivePolynomial(byte[] firstPolynomial, byte[] secondPolynomial, byte[] primitivePolynomial) {
        int degreeOfMonomial = 0;
        byte[] product = new byte[firstPolynomial.length];
        for (int i = secondPolynomial.length - 1; i >= 0; i--) {
            byte currentByte = secondPolynomial[i];
            for (int j = 0; j < 8; j++) {
                int lastBitOfByte = currentByte & 1;
                if (lastBitOfByte == 1) {
                    byte[] addendum = Arrays.copyOf(firstPolynomial, firstPolynomial.length);
                    for (int k = 0; k < degreeOfMonomial; k++) {
                        addendum = multiplyPolynomialByX(addendum, primitivePolynomial);
                    }
                    addPolynomials(product, addendum);
                }
                currentByte >>>= 1;
                degreeOfMonomial++;
            }
        }
        return product;
    }

    private static void polynomialModPrimitive(byte[] polynomial, byte[] primitivePolynomial) {
        polynomial[polynomial.length - 1] ^= primitivePolynomial[primitivePolynomial.length - 1];
    }

    private static void addPolynomials(byte[] firstPolynomial, byte[] secondPolynomial) {
        for (int i = 0; i < firstPolynomial.length; i++) {
            firstPolynomial[i] ^= secondPolynomial[i];
        }
    }

    private static byte[] multiplyPolynomialByX(byte[] polynomial, byte[] primitivePolynomial) {
        byte[] polynomialCopy = Arrays.copyOf(polynomial, polynomial.length);
        int mostSignificantBit = (polynomial[0] & 0xff) >>> 7;
        shiftLeftByteArray(polynomialCopy);
        if (mostSignificantBit == 1)
            polynomialModPrimitive(polynomialCopy, primitivePolynomial);
        return polynomialCopy;
    }

    private static void shiftLeftByteArray(byte[] array) {
        int previousByteFirstBit = 0;
        int currentByteFirstBit;
        for (int i = array.length - 1; i >= 0; i--) {
            if (array[i] < 0) {
                currentByteFirstBit = 1;
            } else currentByteFirstBit = 0;
            array[i] <<= 1;
            array[i] ^= previousByteFirstBit;
            previousByteFirstBit = currentByteFirstBit;
        }
    }

    /**
     * Генерирует вектор инициализации
     *
     * @param initializationVector массив, в который будет помещен вектор инициализации
     * @author Ilya Ryzhov
     */
    public static void generateInitializationVector(byte[] initializationVector) {
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(initializationVector);
    }

    /**
     * Сдвигает регистр влево с заполнением младших байт
     *
     * @param register     регистр сдвига
     * @param fillingValue значение, которым нужно заполнить младшие байты
     * @author Ilya Ryzhov
     */
    public static void shiftLeftRegisterWithFillingLSB(byte[] register, byte[] fillingValue) {
        byte[] rightPartOfRegister = Arrays.copyOfRange(register, fillingValue.length, register.length);
        System.arraycopy(rightPartOfRegister, 0, register, 0, rightPartOfRegister.length);
        System.arraycopy(fillingValue, 0, register, rightPartOfRegister.length, fillingValue.length);
    }
}
