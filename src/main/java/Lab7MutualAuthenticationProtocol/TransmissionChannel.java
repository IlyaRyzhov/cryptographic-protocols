package Lab7MutualAuthenticationProtocol;

import java.io.*;

public class TransmissionChannel {
    private static final File channel = new File("src/main/java/Lab7MutualAuthenticationProtocol/transmissionChannel.txt");

    /**
     * Записывает сообщение в канал передачи
     *
     * @param message отправленное в канал передачи сообщение
     * @author Ilya Ryzhov
     */
    public static void writeMessageToTransmissionChannel(byte[] message) {
        try (BufferedOutputStream outputStream = new BufferedOutputStream(new FileOutputStream(channel), 1048576)) {
            outputStream.write(message);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Читает сообщение из канала передачи, затем освобождает его для дальнейшего использования
     *
     * @return прочитанное из канала передачи сообщение
     * @author Ilya Ryzhov
     */
    public static byte[] readMessageFromTransmissionChannel() {
        byte[] message = new byte[0];
        try (BufferedInputStream inputStream = new BufferedInputStream(new FileInputStream(channel), 1048576)) {
            message = inputStream.readAllBytes();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            freeTransmissionChannel();
        }
        return message;
    }

    private static void freeTransmissionChannel() {
        try (BufferedOutputStream outputStream = new BufferedOutputStream(new FileOutputStream(channel), 1048576)) {
            outputStream.write(new byte[0]);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
