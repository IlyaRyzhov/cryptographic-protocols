package Utils;

import static Utils.CommonUtils.convertLongArrayToByteArray;

public class BlueMidnightWishUtils {
    public static byte[][] parseMessageIntoBlocks(byte[] message, int numberOfBytesInBlock) {
        int numberOfBlocks = message.length / numberOfBytesInBlock;
        byte[][] parsedMessage = new byte[numberOfBlocks][numberOfBytesInBlock];
        byte[] littleEndianMessage = new byte[message.length];
      /*  for (int i = 0; i < message.length; i += 4) {
            littleEndianMessage[i] = message[i + 3];
            littleEndianMessage[i + 1] = message[i + 2];
            littleEndianMessage[i + 2] = message[i + 1];
            littleEndianMessage[i + 3] = message[i];
        }*/
        for (int i = 0; i < numberOfBlocks; i++) {
            System.arraycopy(message, i * numberOfBytesInBlock, parsedMessage[i], 0, numberOfBytesInBlock);
     //       System.arraycopy(littleEndianMessage, i * numberOfBytesInBlock, parsedMessage[i], 0, numberOfBytesInBlock);
        }
        return parsedMessage;
    }
}
