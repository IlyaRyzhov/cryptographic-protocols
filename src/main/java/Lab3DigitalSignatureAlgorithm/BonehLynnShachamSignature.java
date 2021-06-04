package Lab3DigitalSignatureAlgorithm;

import Lab2HashAlgorithm.HashFunction;
import Lab3DigitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.Element;
import Lab3DigitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.Pairing;
import Lab3DigitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.File;

public class BonehLynnShachamSignature {
    private final HashFunction hashFunction;
    private Element publicKey;
    private Element secretKey;
    public static final Pairing pairing;
    public static Element generatingElement;

    public BonehLynnShachamSignature(byte[] secretKey, HashFunction hashFunction) {
        this.secretKey = pairing.getZr().newElementFromBytes(secretKey);
        this.publicKey = generatingElement.duplicate().powZn(this.secretKey);
        this.hashFunction = hashFunction;
    }

    static {
        pairing = PairingFactory.getPairing("pairing/parameters/a/a_181_603.properties");
        generatingElement = pairing.getG2().newElementFromBytes(
                new byte[]{21, 112, 31, 97, 41, -23, 47, 110, 99, -52, 96, -93, -99, 93, -96, 120, -120, 46, 32, 14,
                        71, -45, 3, 21, 6, -104, 67, 15, 47, -79, 38, 115, 30, -35, -117, 75, -109, 86, -116, -128,
                        -27, 48, -17, 52, 73, 31, -50, 122, -24, 73, -110, -65, -36, -74, -6, 27, 69, -96, -114, -86,
                        -91, -113, -74, -99, 25, 91, -71, -42, -60, -126, 81, 93, 47, 93, -110, -101, 17, 88, -111, 22,
                        37, -97, 32, 26, -82, 3, 43, 98, 96, 127, 74, -106, 80, -115, 13, 12, -32, 110, 52, -94,
                        -74, -44, 31, -5, -115, 34, 6, -69, 50, -87, -85, -19, -23, 117, -44, -105, 77, 105, -8, -81,
                        79, 57, 127, -98, 61, 116, -36, 81, 40, 88, -6, -98, -36, 73, 20, 12, 13, 28, -112, -13,
                        29, -88, -48, 126, -60, 4, 19, 13, 35, 51, -94, 34});
    }

    /**
     * Подписывает сообщение
     *
     * @param message сообщение, от которого вычисляется подпись
     * @return электронная подпись сообщения
     * @author Ilya Ryzhov
     */
    public byte[] getSignature(byte[] message) {
        byte[] messageHash = hashFunction.computeHash(message);
        Element messageHashInCurve = pairing.getG1().newElementFromHash(messageHash, 0, messageHash.length);
        return messageHashInCurve.powZn(secretKey).toBytes();
    }

    /**
     * Проверяет подпись сообщения
     *
     * @param message   сообщение, подпись которого проверяется
     * @param signature подпись сообщения
     * @param publicKey открытый ключ подписи
     * @return true если подпись верна, false в противном случае
     * @author Ilya Ryzhov
     */
    public boolean verifySignature(byte[] message, byte[] signature, byte[] publicKey) {
        byte[] messageHash = hashFunction.computeHash(message);
        return signatureVerification(messageHash, signature, publicKey);
    }

    /**
     * Подписывает файл
     *
     * @param file файл, от которого вычисляется подпись
     * @return электронная подпись файла
     * @author Ilya Ryzhov
     */
    public byte[] getSignature(File file) {
        byte[] fileHash = hashFunction.computeHash(file);
        Element messageHashInCurve = pairing.getG1().newElementFromHash(fileHash, 0, fileHash.length);
        return messageHashInCurve.powZn(secretKey).toBytes();
    }

    /**
     * Проверяет подпись файла
     *
     * @param file      файл, подпись которого проверяется
     * @param signature подпись файла
     * @param publicKey открытый ключ подписи
     * @return true если подпись верна, false в противном случае
     * @author Ilya Ryzhov
     */
    public boolean verifySignature(File file, byte[] signature, byte[] publicKey) {
        byte[] fileHash = hashFunction.computeHash(file);
        return signatureVerification(fileHash, signature, publicKey);
    }

    private boolean signatureVerification(byte[] hash, byte[] signature, byte[] publicKey) {
        Element messageHashInCurve = pairing.getG1().newElementFromHash(hash, 0, hash.length);
        Element signatureOnCurve = pairing.getG1().newElementFromBytes(signature);
        Element d1 = pairing.pairing(pairing.getG1().newElementFromBytes(publicKey), messageHashInCurve);
        Element d2 = pairing.pairing(generatingElement, signatureOnCurve);
        return d1.isEqual(d2);
    }

    /**
     * Возвращает открытый ключ подписи
     *
     * @return открытый ключ подписи в байтовом представлении
     * @author Ilya Ryzhov
     */
    public byte[] getPublicKey() {
        return publicKey.toBytes();
    }

    /**
     * Изменяет секретный ключ подписи
     *
     * @param secretKey новый секретный ключ в байтах. При ключе более 23 байтов происходит усечение
     * @author Ilya Ryzhov
     */
    public void setSecretKey(byte[] secretKey) {
        this.secretKey = pairing.getZr().newElementFromBytes(secretKey);
        this.publicKey = generatingElement.duplicate().powZn(this.secretKey);
    }

    /**
     * Изменяет порождающий элемент группы
     *
     * @param generatingElement новый порождающий элемент группы
     * @author Ilya Ryzhov
     */
    public static void setGeneratingElement(Element generatingElement) {
        BonehLynnShachamSignature.generatingElement = generatingElement.duplicate();
    }

    /**
     * Возвращает длину подписи в байтах
     *
     * @author Ilya Ryzhov
     */
    public int getSignatureLengthInBytes() {
        return pairing.getG1().getLengthInBytes();
    }
}
