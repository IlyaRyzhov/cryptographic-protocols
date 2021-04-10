package Utils;

public class BlueMidnightWishUtils {
    public static byte[][] parseMessageIntoBlocks(byte[] message, int numberOfBytesInBlock) {
        int numberOfBlocks = message.length / numberOfBytesInBlock;
        byte[][] parsedMessage = new byte[numberOfBlocks][numberOfBytesInBlock];
        for (int i = 0; i < numberOfBlocks; i++) {
            System.arraycopy(message, i * numberOfBytesInBlock, parsedMessage[i], 0, numberOfBytesInBlock);
        }
        return parsedMessage;
    }
}
