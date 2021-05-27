package Lab3DigitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.util.io;

/**
 * <p>Encodes and decodes to and from Base64 notation.</p>
 * <p>Homepage: <a href="http://iharder.net/base64">http://iharder.net/base64</a>.</p>
 * <p>
 * <p>Example:</p>
 * <p>
 * <code>String encoded = Base64.encode( myByteArray );</code>
 * <br />
 * <code>byte[] myByteArray = Base64.decode( encoded );</code>
 * <p>
 * <p>The <tt>options</tt> parameter, which appears in a few places, is used to pass
 * several pieces of information to the encoder. In the "higher level" methods such as
 * encodeBytes( bytes, options ) the options parameter can be used to indicate such
 * things as first gzipping the bytes before encoding them, not inserting linefeeds,
 * and encoding using the URL-safe and Ordered dialects.</p>
 * <p>
 * <p>Note, according to <a href="http://www.faqs.org/rfcs/rfc3548.html">RFC3548</a>,
 * Section 2.1, implementations should not add line feeds unless explicitly told
 * to do so. I've got Base64 set to this behavior now, although earlier versions
 * broke lines by default.</p>
 * <p>
 * <p>The constants defined in Base64 can be OR-ed together to combine options, so you
 * might make a call like this:</p>
 * <p>
 * <code>String encoded = Base64.encodeBytes( mybytes, Base64.GZIP | Base64.DO_BREAK_LINES );</code>
 * <p>to compress the data before encoding it and then making the output have newline characters.</p>
 * <p>Also...</p>
 * <code>String encoded = Base64.encodeBytes( crazyString.getBytes() );</code>
 * <p>
 * <p>
 * <p>
 * <p>
 * Change Log:
 * </p>
 * <ul>
 * <li>v2.3.7 - Fixed subtle bug when base 64 input stream contained the
 * value 01111111, which is an invalid base 64 character but should not
 * throw an ArrayIndexOutOfBoundsException either. Led to discovery of
 * mishandling (or potential for better handling) of other bad input
 * characters. You should now get an IOException if you try decoding
 * something that has bad characters in it.</li>
 * <li>v2.3.6 - Fixed bug when breaking lines and the final byte of the encoded
 * string ended in the last column; the buffer was not properly shrunk and
 * contained an extra (null) byte that made it into the string.</li>
 * <li>v2.3.5 - Fixed bug in {@link #encodeFromFile} where estimated buffer size
 * was wrong for files of size 31, 34, and 37 bytes.</li>
 * <li>v2.3.4 - Fixed bug when working with gzipped streams whereby flushing
 * the Base64.OutputStream closed the Base64 encoding (by padding with equals
 * signs) too soon. Also added an option to suppress the automatic decoding
 * of gzipped streams. Also added experimental support for specifying a
 * class loader when using the
 * {@link #decodeToObject()}
 * method.</li>
 * <li>v2.3.3 - Changed default char encoding to US-ASCII which reduces the internal Java
 * footprint with its CharEncoders and so forth. Fixed some javadocs that were
 * inconsistent. Removed imports and specified things like java.io.IOException
 * explicitly inline.</li>
 * <li>v2.3.2 - Reduced memory footprint! Finally refined the "guessing" of how big the
 * final encoded data will be so that the code doesn't have to create two output
 * arrays: an oversized initial one and then a final, exact-sized one. Big win
 * when using the  family of methods (and not
 * using the gzip options which uses a different mechanism with streams and stuff).</li>
 * <li>v2.3.1 - Added {@link #encodeBytesToBytes(byte[], int)} and some
 * similar helper methods to be more efficient with memory by not returning a
 * String but just a byte array.</li>
 * <li>v2.3 - <strong>This is not a drop-in replacement!</strong> This is two years of comments
 * and bug fixes queued up and finally executed. Thanks to everyone who sent
 * me stuff, and I'm sorry I wasn't able to distribute your fixes to everyone else.
 * Much bad coding was cleaned up including throwing exceptions where necessary
 * instead of returning null values or something similar. Here are some changes
 * that may affect you:
 * <ul>
 * <li><em>Does not break lines, by default.</em> This is to keep in compliance with
 * <a href="http://www.faqs.org/rfcs/rfc3548.html">RFC3548</a>.</li>
 * <li><em>Throws exceptions instead of returning null values.</em> Because some operations
 * (especially those that may permit the GZIP option) use IO streams, there
 * is a possiblity of an java.io.IOException being thrown. After some discussion and
 * thought, I've changed the behavior of the methods to throw java.io.IOExceptions
 * rather than return null if ever there's an error. I think this is more
 * appropriate, though it will require some changes to your code. Sorry,
 * it should have been done this way to begin with.</li>
 * <li><em>Removed all references to System.out, System.err, and the like.</em>
 * Shame on me. All I can say is sorry they were ever there.</li>
 * <li><em>Throws NullPointerExceptions and IllegalArgumentExceptions</em> as needed
 * such as when passed arrays are null or offsets are invalid.</li>
 * <li>Cleaned up as much javadoc as I could to avoid any javadoc warnings.
 * This was especially annoying before for people who were thorough in their
 * own projects and then had gobs of javadoc warnings on this file.</li>
 * </ul>
 * <li>v2.2.1 - Fixed bug using URL_SAFE and ORDERED encodings. Fixed bug
 * when using very small files (~&lt; 40 bytes).</li>
 * <li>v2.2 - Added some helper methods for encoding/decoding directly from
 * one file to the next. Also added a main() method to support command line
 * encoding/decoding from one file to the next. Also added these Base64 dialects:
 * <ol>
 * <li>The default is RFC3548 format.</li>
 * <li>Calling Base64.setFormat(Base64.BASE64_FORMAT.URLSAFE_FORMAT) generates
 * URL and file name friendly format as described in Section 4 of RFC3548.
 * http://www.faqs.org/rfcs/rfc3548.html</li>
 * <li>Calling Base64.setFormat(Base64.BASE64_FORMAT.ORDERED_FORMAT) generates
 * URL and file name friendly format that preserves lexical ordering as described
 * in http://www.faqs.org/qa/rfcc-1940.html</li>
 * </ol>
 * Special thanks to Jim Kellerman at <a href="http://www.powerset.com/">http://www.powerset.com/</a>
 * for contributing the new Base64 dialects.
 * </li>
 * <p>
 * <li>v2.1 - Cleaned up javadoc comments and unused variables and methods. Added
 * some convenience methods for reading and writing to and from files.</li>
 * <li>v2.0.2 - Now specifies UTF-8 encoding in places where the code fails on systems
 * with other encodings (like EBCDIC).</li>
 * <li>v2.0.1 - Fixed an error when decoding a single byte, that is, when the
 * encoded data was a single byte.</li>
 * <li>v2.0 - I got rid of methods that used booleans to set options.
 * Now everything is more consolidated and cleaner. The code now detects
 * when data that's being decoded is gzip-compressed and will decompress it
 * automatically. Generally things are cleaner. You'll probably have to
 * change some method calls that you were making to support the new
 * options format (<tt>int</tt>s that you "OR" together).</li>
 * <li>v1.5.1 - Fixed bug when decompressing and decoding to a
 * byte[] using <tt>decode( String s, boolean gzipCompressed )</tt>.
 * Added the ability to "suspend" encoding in the Output Stream so
 * you can turn on and off the encoding if you need to embed base64
 * data in an otherwise "normal" stream (like an XML file).</li>
 * <li>v1.5 - Output stream pases on flush() command but doesn't do anything itself.
 * This helps when using GZIP streams.
 * Added the ability to GZip-compress objects before encoding them.</li>
 * <li>v1.4 - Added helper methods to read/write files.</li>
 * <li>v1.3.6 - Fixed OutputStream.flush() so that 'position' is reset.</li>
 * <li>v1.3.5 - Added flag to turn on and off line breaks. Fixed bug in input stream
 * where last buffer being read, if not completely full, was not returned.</li>
 * <li>v1.3.4 - Fixed when "improperly padded stream" error was thrown at the wrong time.</li>
 * <li>v1.3.3 - Fixed I/O streams which were totally messed up.</li>
 * </ul>
 * <p>
 * <p>
 * I am placing this code in the Public Domain. Do with it as you will.
 * This software comes with no guarantees or warranties but with
 * plenty of well-wishing instead!
 * Please visit <a href="http://iharder.net/base64">http://iharder.net/base64</a>
 * periodically to check for updates or to contribute improvements.
 * </p>
 *
 * @author Robert Harder
 * @author rob@iharder.net
 * @version 2.3.7
 */
public class Base64 {

/* ********  P U B L I C   F I E L D S  ******** */


    /**
     * Encode using Base64-like encoding that is URL- and Filename-safe as described
     * in Section 4 of RFC3548:
     * <a href="http://www.faqs.org/rfcs/rfc3548.html">http://www.faqs.org/rfcs/rfc3548.html</a>.
     * It is important to note that data encoded this way is <em>not</em> officially valid Base64,
     * or at the very least should not be called Base64 without also specifying that is
     * was encoded using the URL- and Filename-safe dialect.
     */
    private final static int URL_SAFE = 16;


    /**
     * Encode using the special "ordered" dialect of Base64 described here:
     * <a href="http://www.faqs.org/qa/rfcc-1940.html">http://www.faqs.org/qa/rfcc-1940.html</a>.
     */
    private final static int ORDERED = 32;


/* ********  P R I V A T E   F I E L D S  ******** */


    /**
     * The equals getSignature (=) as a byte.
     */
    private final static byte EQUALS_SIGN = (byte) '=';


    /**
     * Preferred encoding.
     */
    private final static String PREFERRED_ENCODING = "US-ASCII";


    private final static byte WHITE_SPACE_ENC = -5; // Indicates white space in encoding
    private final static byte EQUALS_SIGN_ENC = -1; // Indicates equals getSignature in encoding


/* ********  S T A N D A R D   B A S E 6 4   A L P H A B E T  ******** */

    /**
     * The 64 valid Base64 values.
     */
    /* Host platform me be something funny like EBCDIC, so we hardcode these values. */
    private final static byte[] _STANDARD_ALPHABET = {
            (byte) 'A', (byte) 'B', (byte) 'C', (byte) 'D', (byte) 'E', (byte) 'F', (byte) 'G',
            (byte) 'H', (byte) 'I', (byte) 'J', (byte) 'K', (byte) 'L', (byte) 'M', (byte) 'N',
            (byte) 'O', (byte) 'P', (byte) 'Q', (byte) 'R', (byte) 'S', (byte) 'T', (byte) 'U',
            (byte) 'V', (byte) 'W', (byte) 'X', (byte) 'Y', (byte) 'Z',
            (byte) 'a', (byte) 'b', (byte) 'c', (byte) 'd', (byte) 'e', (byte) 'f', (byte) 'g',
            (byte) 'h', (byte) 'i', (byte) 'j', (byte) 'k', (byte) 'l', (byte) 'm', (byte) 'n',
            (byte) 'o', (byte) 'p', (byte) 'q', (byte) 'r', (byte) 's', (byte) 't', (byte) 'u',
            (byte) 'v', (byte) 'w', (byte) 'x', (byte) 'y', (byte) 'z',
            (byte) '0', (byte) '1', (byte) '2', (byte) '3', (byte) '4', (byte) '5',
            (byte) '6', (byte) '7', (byte) '8', (byte) '9', (byte) '+', (byte) '/'
    };


    /**
     * Translates a Base64 value to either its 6-bit reconstruction value
     * or a negative number indicating some other meaning.
     **/
    private final static byte[] _STANDARD_DECODABET = {
            -9, -9, -9, -9, -9, -9, -9, -9, -9,                 // Decimal  0 -  8
            -5, -5,                                      // Whitespace: Tab and Linefeed
            -9, -9,                                      // Decimal 11 - 12
            -5,                                         // Whitespace: Carriage Return
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9,     // Decimal 14 - 26
            -9, -9, -9, -9, -9,                             // Decimal 27 - 31
            -5,                                         // Whitespace: Space
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9,              // Decimal 33 - 42
            62,                                         // Plus getSignature at decimal 43
            -9, -9, -9,                                   // Decimal 44 - 46
            63,                                         // Slash at decimal 47
            52, 53, 54, 55, 56, 57, 58, 59, 60, 61,              // Numbers zero through nine
            -9, -9, -9,                                   // Decimal 58 - 60
            -1,                                         // Equals getSignature at decimal 61
            -9, -9, -9,                                      // Decimal 62 - 64
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,            // Letters 'A' through 'N'
            14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,        // Letters 'O' through 'Z'
            -9, -9, -9, -9, -9, -9,                          // Decimal 91 - 96
            26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,     // Letters 'a' through 'm'
            39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,     // Letters 'n' through 'z'
            -9, -9, -9, -9, -9                              // Decimal 123 - 127
            , -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9,       // Decimal 128 - 139
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9,     // Decimal 140 - 152
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9,     // Decimal 153 - 165
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9,     // Decimal 166 - 178
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9,     // Decimal 179 - 191
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9,     // Decimal 192 - 204
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9,     // Decimal 205 - 217
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9,     // Decimal 218 - 230
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9,     // Decimal 231 - 243
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9         // Decimal 244 - 255
    };


/* ********  U R L   S A F E   B A S E 6 4   A L P H A B E T  ******** */

    /**
     * Used in the URL- and Filename-safe dialect described in Section 4 of RFC3548:
     * <a href="http://www.faqs.org/rfcs/rfc3548.html">http://www.faqs.org/rfcs/rfc3548.html</a>.
     * Notice that the last two bytes become "hyphen" and "underscore" instead of "plus" and "slash."
     */
    private final static byte[] _URL_SAFE_ALPHABET = {
            (byte) 'A', (byte) 'B', (byte) 'C', (byte) 'D', (byte) 'E', (byte) 'F', (byte) 'G',
            (byte) 'H', (byte) 'I', (byte) 'J', (byte) 'K', (byte) 'L', (byte) 'M', (byte) 'N',
            (byte) 'O', (byte) 'P', (byte) 'Q', (byte) 'R', (byte) 'S', (byte) 'T', (byte) 'U',
            (byte) 'V', (byte) 'W', (byte) 'X', (byte) 'Y', (byte) 'Z',
            (byte) 'a', (byte) 'b', (byte) 'c', (byte) 'd', (byte) 'e', (byte) 'f', (byte) 'g',
            (byte) 'h', (byte) 'i', (byte) 'j', (byte) 'k', (byte) 'l', (byte) 'm', (byte) 'n',
            (byte) 'o', (byte) 'p', (byte) 'q', (byte) 'r', (byte) 's', (byte) 't', (byte) 'u',
            (byte) 'v', (byte) 'w', (byte) 'x', (byte) 'y', (byte) 'z',
            (byte) '0', (byte) '1', (byte) '2', (byte) '3', (byte) '4', (byte) '5',
            (byte) '6', (byte) '7', (byte) '8', (byte) '9', (byte) '-', (byte) '_'
    };

    /**
     * Used in decoding URL- and Filename-safe dialects of Base64.
     */
    private final static byte[] _URL_SAFE_DECODABET = {
            -9, -9, -9, -9, -9, -9, -9, -9, -9,                 // Decimal  0 -  8
            -5, -5,                                      // Whitespace: Tab and Linefeed
            -9, -9,                                      // Decimal 11 - 12
            -5,                                         // Whitespace: Carriage Return
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9,     // Decimal 14 - 26
            -9, -9, -9, -9, -9,                             // Decimal 27 - 31
            -5,                                         // Whitespace: Space
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9,              // Decimal 33 - 42
            -9,                                         // Plus getSignature at decimal 43
            -9,                                         // Decimal 44
            62,                                         // Minus getSignature at decimal 45
            -9,                                         // Decimal 46
            -9,                                         // Slash at decimal 47
            52, 53, 54, 55, 56, 57, 58, 59, 60, 61,              // Numbers zero through nine
            -9, -9, -9,                                   // Decimal 58 - 60
            -1,                                         // Equals getSignature at decimal 61
            -9, -9, -9,                                   // Decimal 62 - 64
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,            // Letters 'A' through 'N'
            14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,        // Letters 'O' through 'Z'
            -9, -9, -9, -9,                                // Decimal 91 - 94
            63,                                         // Underscore at decimal 95
            -9,                                         // Decimal 96
            26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,     // Letters 'a' through 'm'
            39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,     // Letters 'n' through 'z'
            -9, -9, -9, -9, -9                              // Decimal 123 - 127
            , -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9,     // Decimal 128 - 139
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9,     // Decimal 140 - 152
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9,     // Decimal 153 - 165
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9,     // Decimal 166 - 178
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9,     // Decimal 179 - 191
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9,     // Decimal 192 - 204
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9,     // Decimal 205 - 217
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9,     // Decimal 218 - 230
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9,     // Decimal 231 - 243
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9         // Decimal 244 - 255
    };



/* ********  O R D E R E D   B A S E 6 4   A L P H A B E T  ******** */

    /**
     * I don't get the point of this technique, but someone requested it,
     * and it is described here:
     * <a href="http://www.faqs.org/qa/rfcc-1940.html">http://www.faqs.org/qa/rfcc-1940.html</a>.
     */
    private final static byte[] _ORDERED_ALPHABET = {
            (byte) '-',
            (byte) '0', (byte) '1', (byte) '2', (byte) '3', (byte) '4',
            (byte) '5', (byte) '6', (byte) '7', (byte) '8', (byte) '9',
            (byte) 'A', (byte) 'B', (byte) 'C', (byte) 'D', (byte) 'E', (byte) 'F', (byte) 'G',
            (byte) 'H', (byte) 'I', (byte) 'J', (byte) 'K', (byte) 'L', (byte) 'M', (byte) 'N',
            (byte) 'O', (byte) 'P', (byte) 'Q', (byte) 'R', (byte) 'S', (byte) 'T', (byte) 'U',
            (byte) 'V', (byte) 'W', (byte) 'X', (byte) 'Y', (byte) 'Z',
            (byte) '_',
            (byte) 'a', (byte) 'b', (byte) 'c', (byte) 'd', (byte) 'e', (byte) 'f', (byte) 'g',
            (byte) 'h', (byte) 'i', (byte) 'j', (byte) 'k', (byte) 'l', (byte) 'm', (byte) 'n',
            (byte) 'o', (byte) 'p', (byte) 'q', (byte) 'r', (byte) 's', (byte) 't', (byte) 'u',
            (byte) 'v', (byte) 'w', (byte) 'x', (byte) 'y', (byte) 'z'
    };

    /**
     * Used in decoding the "ordered" dialect of Base64.
     */
    private final static byte[] _ORDERED_DECODABET = {
            -9, -9, -9, -9, -9, -9, -9, -9, -9,                 // Decimal  0 -  8
            -5, -5,                                      // Whitespace: Tab and Linefeed
            -9, -9,                                      // Decimal 11 - 12
            -5,                                         // Whitespace: Carriage Return
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9,     // Decimal 14 - 26
            -9, -9, -9, -9, -9,                             // Decimal 27 - 31
            -5,                                         // Whitespace: Space
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9,              // Decimal 33 - 42
            -9,                                         // Plus getSignature at decimal 43
            -9,                                         // Decimal 44
            0,                                          // Minus getSignature at decimal 45
            -9,                                         // Decimal 46
            -9,                                         // Slash at decimal 47
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10,                       // Numbers zero through nine
            -9, -9, -9,                                   // Decimal 58 - 60
            -1,                                         // Equals getSignature at decimal 61
            -9, -9, -9,                                   // Decimal 62 - 64
            11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,     // Letters 'A' through 'M'
            24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,     // Letters 'N' through 'Z'
            -9, -9, -9, -9,                                // Decimal 91 - 94
            37,                                         // Underscore at decimal 95
            -9,                                         // Decimal 96
            38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50,     // Letters 'a' through 'm'
            51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,     // Letters 'n' through 'z'
            -9, -9, -9, -9, -9                                 // Decimal 123 - 127
            , -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9,     // Decimal 128 - 139
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9,     // Decimal 140 - 152
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9,     // Decimal 153 - 165
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9,     // Decimal 166 - 178
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9,     // Decimal 179 - 191
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9,     // Decimal 192 - 204
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9,     // Decimal 205 - 217
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9,     // Decimal 218 - 230
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9,     // Decimal 231 - 243
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9         // Decimal 244 - 255
    };


/* ********  D E T E R M I N E   W H I C H   A L H A B E T  ******** */


    /**
     * Returns one of the _SOMETHING_ALPHABET byte arrays depending on
     * the options specified.
     * It's possible, though silly, to specify ORDERED <b>and</b> URLSAFE
     * in which case one of them will be picked, though there is
     * no guarantee as to which one will be picked.
     */
    private static byte[] getAlphabet() {
        if ((0) == URL_SAFE) {
            return _URL_SAFE_ALPHABET;
        } else if ((0) == ORDERED) {
            return _ORDERED_ALPHABET;
        } else {
            return _STANDARD_ALPHABET;
        }
    }    // end getAlphabet


    /**
     * Returns one of the _SOMETHING_DECODABET byte arrays depending on
     * the options specified.
     * It's possible, though silly, to specify ORDERED and URL_SAFE
     * in which case one of them will be picked, though there is
     * no guarantee as to which one will be picked.
     */
    private static byte[] getDecodabet() {
        if ((0) == URL_SAFE) {
            return _URL_SAFE_DECODABET;
        } else if ((0) == ORDERED) {
            return _ORDERED_DECODABET;
        } else {
            return _STANDARD_DECODABET;
        }
    }    // end getAlphabet


    /**
     * Defeats instantiation.
     */
    private Base64() {
    }




/* ********  E N C O D I N G   M E T H O D S  ******** */


    /**
     * <p>Encodes up to three bytes of the array <var>source</var>
     * and writes the resulting four Base64 bytes to <var>destination</var>.
     * The source and destination arrays can be manipulated
     * anywhere along their length by specifying
     * <var>srcOffset</var> and <var>destOffset</var>.
     * This method does not check to make sure your arrays
     * are large enough to accomodate <var>srcOffset</var> + 3 for
     * the <var>source</var> array or <var>destOffset</var> + 4 for
     * the <var>destination</var> array.
     * The actual number of significant bytes in your array is
     * given by <var>numSigBytes</var>.</p>
     * <p>This is the lowest level of the encoding methods with
     * all possible parameters.</p>
     *
     * @param source      the array to convert
     * @param srcOffset   the index where conversion begins
     * @param numSigBytes the number of significant bytes in your array
     * @param destination the array to hold the conversion
     * @param destOffset  the index where output will be put
     * @return the <var>destination</var> array
     * @since 1.3
     */
    private static void encode3to4(
            byte[] source, int srcOffset, int numSigBytes,
            byte[] destination, int destOffset) {

        byte[] ALPHABET = getAlphabet();

        //           1         2         3
        // 01234567890123456789012345678901 Bit position
        // --------000000001111111122222222 Array position from threeBytes
        // --------|    ||    ||    ||    | Six bit groups to index ALPHABET
        //          >>18  >>12  >> 6  >> 0  Right shift necessary
        //                0x3f  0x3f  0x3f  Additional AND

        // Create buffer with zero-padding if there are only one or two
        // significant bytes passed in the array.
        // We have to shift left 24 in order to flush out the 1's that appear
        // when Java treats a value as negative that is cast from a byte to an int.
        int inBuff = (numSigBytes > 0 ? ((source[srcOffset] << 24) >>> 8) : 0)
                | (numSigBytes > 1 ? ((source[srcOffset + 1] << 24) >>> 16) : 0)
                | (numSigBytes > 2 ? ((source[srcOffset + 2] << 24) >>> 24) : 0);

        switch (numSigBytes) {
            case 3:
                destination[destOffset] = ALPHABET[(inBuff >>> 18)];
                destination[destOffset + 1] = ALPHABET[(inBuff >>> 12) & 0x3f];
                destination[destOffset + 2] = ALPHABET[(inBuff >>> 6) & 0x3f];
                destination[destOffset + 3] = ALPHABET[(inBuff) & 0x3f];
                return;

            case 2:
                destination[destOffset] = ALPHABET[(inBuff >>> 18)];
                destination[destOffset + 1] = ALPHABET[(inBuff >>> 12) & 0x3f];
                destination[destOffset + 2] = ALPHABET[(inBuff >>> 6) & 0x3f];
                destination[destOffset + 3] = EQUALS_SIGN;
                return;

            case 1:
                destination[destOffset] = ALPHABET[(inBuff >>> 18)];
                destination[destOffset + 1] = ALPHABET[(inBuff >>> 12) & 0x3f];
                destination[destOffset + 2] = EQUALS_SIGN;
                destination[destOffset + 3] = EQUALS_SIGN;
                return;

            default:
        }   // end switch
    }   // end encode3to4


    /**
     * Encodes a byte array into Base64 notation.
     * Does not GZip-compress data.
     *
     * @param source The data to convert
     * @return The data in Base64-encoded form
     * @throws NullPointerException if source array is null
     * @since 1.4
     */
    public static String encodeBytes(byte[] source) {
        // Since we're not going to have the GZIP encoding turned on,
        // we're not going to have an java.io.IOException thrown, so
        // we should not force the user to have to catch it.
        String encoded;
        encoded = encodeBytes(source, source.length);
        return encoded;
    }   // end encodeBytes


    /**
     * Encodes a byte array into Base64 notation.
     * <p>
     * Example options:<pre>
     *   GZIP: gzip-compresses object before encoding it.
     *   DO_BREAK_LINES: break lines at 76 characters
     *     <i>Note: Technically, this makes your encoding non-compliant.</i>
     * </pre>
     * <p>
     * Example: <code>encodeBytes( myData, Base64.GZIP )</code> or
     * <p>
     * Example: <code>encodeBytes( myData, Base64.GZIP | Base64.DO_BREAK_LINES )</code>
     * <p>
     * <p>
     * <p>As of v 2.3, if there is an error with the GZIP stream,
     * the method will throw an java.io.IOException. <b>This is new to v2.3!</b>
     * In earlier versions, it just returned a null value, but
     * in retrospect that's a pretty poor way to handle it.</p>
     *
     * @param source The data to convert
     * @param len    Length of data to convert
     * @return The Base64-encoded data as a String
     * @throws java.io.IOException      if there is an error
     * @throws NullPointerException     if source array is null
     * @throws IllegalArgumentException if source array, offset, or length are invalid
     * @see Base64#GZIP
     * @see Base64#DO_BREAK_LINES
     * @since 2.0
     */
    private static String encodeBytes(byte[] source, int len) {
        byte[] encoded = encodeBytesToBytes(source, len);

        // Return value according to relevant encoding.
        try {
            return new String(encoded, PREFERRED_ENCODING);
        }   // end try
        catch (java.io.UnsupportedEncodingException uue) {
            return new String(encoded);
        }   // end catch

    }   // end encodeBytes


    /**
     * Similar to {@link #encodeBytes(byte[], int)} but returns
     * a byte array instead of instantiating a String. This is more efficient
     * if you're working with I/O streams and have large data sets to encode.
     *
     * @param source The data to convert
     * @param len    Length of data to convert
     * @return The Base64-encoded data as a String
     * @throws java.io.IOException      if there is an error
     * @throws NullPointerException     if source array is null
     * @throws IllegalArgumentException if source array, offset, or length are invalid
     * @see Base64#GZIP
     * @see Base64#DO_BREAK_LINES
     * @since 2.3.1
     */
    private static byte[] encodeBytesToBytes(byte[] source, int len) {

        if (source == null) {
            throw new NullPointerException("Cannot serialize a null array.");
        }   // end if: null

        if (len < 0) {
            throw new IllegalArgumentException("Cannot have length offset: " + len);
        }   // end if: len < 0

        if (len > source.length) {
            throw new IllegalArgumentException(
                    String.format("Cannot have offset of %d and length of %d with array of length %d", 0, len, source.length));
        }   // end if: off < 0


        // Compress?

        //int    len43   = len * 4 / 3;
        //byte[] outBuff = new byte[   ( len43 )                      // Main 4:3
        //                           + ( (len % 3) > 0 ? 4 : 0 )      // Account for padding
        //                           + (breakLines ? ( len43 / MAX_LINE_LENGTH ) : 0) ]; // New lines
        // Try to determine more precisely how big the array needs to be.
        // If we get it right, we don't have to do an array copy, and
        // we save a bunch of memory.
        int encLen = (len / 3) * 4 + (len % 3 > 0 ? 4 : 0); // Bytes needed for actual encoding
        byte[] outBuff = new byte[encLen];


        int d = 0;
        int e = 0;
        int len2 = len - 2;
        for (; d < len2; d += 3, e += 4) {
            encode3to4(source, d, 3, outBuff, e);

        }   // en dfor: each piece of array

        if (d < len) {
            encode3to4(source, d, len - d, outBuff, e);
            e += 4;
        }   // end if: some padding needed


        // Only resize array if we didn't guess it right.
        if (e <= outBuff.length - 1) {
            // If breaking lines and the last byte falls right at
            // the line length (76 bytes per line), there will be
            // one extra byte, and the array will need to be resized.
            // Not too bad of an estimate on array size, I'd say.
            byte[] finalOut = new byte[e];
            System.arraycopy(outBuff, 0, finalOut, 0, e);
            //System.err.println("Having to resize array from " + outBuff.length + " to " + e );
            return finalOut;
        } else {
            //System.err.println("No need to resize array.");
            return outBuff;
        }

    }   // end encodeBytesToBytes





/* ********  D E C O D I N G   M E T H O D S  ******** */


    /**
     * Decodes four bytes from array <var>source</var>
     * and writes the resulting bytes (up to three of them)
     * to <var>destination</var>.
     * The source and destination arrays can be manipulated
     * anywhere along their length by specifying
     * <var>srcOffset</var> and <var>destOffset</var>.
     * This method does not check to make sure your arrays
     * are large enough to accomodate <var>srcOffset</var> + 4 for
     * the <var>source</var> array or <var>destOffset</var> + 3 for
     * the <var>destination</var> array.
     * This method returns the actual number of bytes that
     * were converted from the Base64 encoding.
     * <p>This is the lowest level of the decoding methods with
     * all possible parameters.</p>
     *
     * @param source      the array to convert
     * @param destination the array to hold the conversion
     * @param destOffset  the index where output will be put
     * @return the number of decoded bytes converted
     * @throws NullPointerException     if source or destination arrays are null
     * @throws IllegalArgumentException if srcOffset or destOffset are invalid
     *                                  or there is not enough room in the array.
     * @since 1.3
     */
    private static int decode4to3(
            byte[] source,
            byte[] destination, int destOffset) {

        // Lots of error checking and exception throwing
        if (source == null) {
            throw new NullPointerException("Source array was null.");
        }   // end if
        if (destination == null) {
            throw new NullPointerException("Destination array was null.");
        }   // end if
        if (3 >= source.length) {
            throw new IllegalArgumentException(String.format(
                    "Source array with length %d cannot have offset of %d and still process four bytes.", source.length, 0));
        }   // end if
        if (destOffset < 0 || destOffset + 2 >= destination.length) {
            throw new IllegalArgumentException(String.format(
                    "Destination array with length %d cannot have offset of %d and still store three bytes.", destination.length, destOffset));
        }   // end if


        byte[] DECODABET = getDecodabet();

        // Example: Dk==
        if (source[2] == EQUALS_SIGN) {
            // Two ways to do the same thing. Don't know which way I like best.
            //int outBuff =   ( ( DECODABET[ source[ srcOffset    ] ] << 24 ) >>>  6 )
            //              | ( ( DECODABET[ source[ srcOffset + 1] ] << 24 ) >>> 12 );
            int outBuff = ((DECODABET[source[0]] & 0xFF) << 18)
                    | ((DECODABET[source[1]] & 0xFF) << 12);

            destination[destOffset] = (byte) (outBuff >>> 16);
            return 1;
        }

        // Example: DkL=
        else if (source[3] == EQUALS_SIGN) {
            // Two ways to do the same thing. Don't know which way I like best.
            //int outBuff =   ( ( DECODABET[ source[ srcOffset     ] ] << 24 ) >>>  6 )
            //              | ( ( DECODABET[ source[ srcOffset + 1 ] ] << 24 ) >>> 12 )
            //              | ( ( DECODABET[ source[ srcOffset + 2 ] ] << 24 ) >>> 18 );
            int outBuff = ((DECODABET[source[0]] & 0xFF) << 18)
                    | ((DECODABET[source[1]] & 0xFF) << 12)
                    | ((DECODABET[source[2]] & 0xFF) << 6);

            destination[destOffset] = (byte) (outBuff >>> 16);
            destination[destOffset + 1] = (byte) (outBuff >>> 8);
            return 2;
        }

        // Example: DkLE
        else {
            // Two ways to do the same thing. Don't know which way I like best.
            //int outBuff =   ( ( DECODABET[ source[ srcOffset     ] ] << 24 ) >>>  6 )
            //              | ( ( DECODABET[ source[ srcOffset + 1 ] ] << 24 ) >>> 12 )
            //              | ( ( DECODABET[ source[ srcOffset + 2 ] ] << 24 ) >>> 18 )
            //              | ( ( DECODABET[ source[ srcOffset + 3 ] ] << 24 ) >>> 24 );
            int outBuff = ((DECODABET[source[0]] & 0xFF) << 18)
                    | ((DECODABET[source[1]] & 0xFF) << 12)
                    | ((DECODABET[source[2]] & 0xFF) << 6)
                    | ((DECODABET[source[3]] & 0xFF));


            destination[destOffset] = (byte) (outBuff >> 16);
            destination[destOffset + 1] = (byte) (outBuff >> 8);
            destination[destOffset + 2] = (byte) (outBuff);

            return 3;
        }
    }   // end decodeToBytes


    /**
     * Low-level access to decoding ASCII characters in
     * the form of a byte array. <strong>Ignores GUNZIP option, if
     * it's set.</strong> This is not generally a recommended method,
     * although it is used internally as part of the decoding process.
     * Special case: if len = 0, an empty array is returned. Still,
     * if you need more speed and reduced memory footprint (and aren't
     * gzipping), consider this method.
     *
     * @param source The Base64 encoded data
     * @param len    The length of characters to decode
     * @return decoded data
     * @throws java.io.IOException If bogus characters exist in source data
     * @since 1.3
     */
    private static byte[] decode(byte[] source, int len)
            throws java.io.IOException {

        // Lots of error checking and exception throwing
        if (source == null) {
            throw new NullPointerException("Cannot decode null source array.");
        }   // end if
        if (len > source.length) {
            throw new IllegalArgumentException(String.format(
                    "Source array with length %d cannot have offset of %d and process %d bytes.", source.length, 0, len));
        }   // end if

        if (len == 0) {
            return new byte[0];
        } else if (len < 4) {
            throw new IllegalArgumentException(
                    "Base64-encoded string must have at least four characters, but length specified was " + len);
        }   // end if

        byte[] DECODABET = getDecodabet();

        int len34 = len * 3 / 4;       // Estimate on array size
        byte[] outBuff = new byte[len34]; // Upper limit on size of output
        int outBuffPosn = 0;             // Keep track of where we're writing

        byte[] b4 = new byte[4];     // Four byte buffer from source, eliminating white space
        int b4Posn = 0;               // Keep track of four byte input buffer
        int i;               // Source array counter
        byte sbiDecode;               // Special value from DECODABET

        for (i = 0; i < len; i++) {  // Loop through source

            sbiDecode = DECODABET[source[i] & 0xFF];

            // White space, Equals getSignature, or legit Base64 character
            // Note the values such as -5 and -9 in the
            // DECODABETs at the top of the file.
            if (sbiDecode >= WHITE_SPACE_ENC) {
                if (sbiDecode >= EQUALS_SIGN_ENC) {
                    b4[b4Posn++] = source[i];         // Save non-whitespace
                    if (b4Posn > 3) {                  // Time to decode?
                        outBuffPosn += decode4to3(b4, outBuff, outBuffPosn);
                        b4Posn = 0;

                        // If that was the equals getSignature, break out of 'for' loop
                        if (source[i] == EQUALS_SIGN) {
                            break;
                        }   // end if: equals getSignature
                    }   // end if: quartet built
                }   // end if: equals getSignature or better
            }   // end if: white space, equals getSignature or better
            else {
                // There's a bad input character in the Base64 stream.
                throw new java.io.IOException(String.format(
                        "Bad Base64 input character decimal %d in array position %d", ((int) source[i]) & 0xFF, i));
            }   // end else:
        }   // each input character

        byte[] out = new byte[outBuffPosn];
        System.arraycopy(outBuff, 0, out, 0, outBuffPosn);
        return out;
    }   // end decode


    /**
     * Decodes data from Base64 notation, automatically
     * detecting gzip-compressed data and decompressing it.
     *
     * @param s the string to decode
     * @return the decoded data
     * @throws java.io.IOException If there is a problem
     * @since 1.4
     */
    public static byte[] decode(String s) throws java.io.IOException {
        if (s == null) {
            throw new NullPointerException("Input string was null.");
        }   // end if

        byte[] bytes;
        try {
            bytes = s.getBytes(PREFERRED_ENCODING);
        }   // end try
        catch (java.io.UnsupportedEncodingException uee) {
            bytes = s.getBytes();
        }   // end catch
        //</change>

        // Decode
        bytes = decode(bytes, bytes.length);

        // Check to see if it's gzip-compressed
        // GZIP Magic Two-Byte Number: 0x8b1f (35615)
        if ((bytes != null) && (bytes.length >= 4)) {

            int head = ((int) bytes[0] & 0xff) | ((bytes[1] << 8) & 0xff00);
            if (java.util.zip.GZIPInputStream.GZIP_MAGIC == head) {
                java.io.ByteArrayInputStream bais = null;
                java.util.zip.GZIPInputStream gzis = null;
                java.io.ByteArrayOutputStream baos = null;
                byte[] buffer = new byte[2048];
                int length;

                try {
                    baos = new java.io.ByteArrayOutputStream();
                    bais = new java.io.ByteArrayInputStream(bytes);
                    gzis = new java.util.zip.GZIPInputStream(bais);

                    while ((length = gzis.read(buffer)) >= 0) {
                        baos.write(buffer, 0, length);
                    }   // end while: reading input

                    // No error? Get new bytes.
                    bytes = baos.toByteArray();

                }   // end try
                catch (java.io.IOException e) {
                    e.printStackTrace();
                    // Just return originally-decoded bytes
                }   // end catch
                finally {
                    try {
                        if (baos != null) {
                            baos.close();
                        }
                    } catch (Exception ignored) {
                    }
                    try {
                        if (gzis != null) {
                            gzis.close();
                        }
                    } catch (Exception ignored) {
                    }
                    try {
                        if (bais != null) {
                            bais.close();
                        }
                    } catch (Exception ignored) {
                    }
                }   // end finally

            }   // end if: gzipped
        }   // end if: bytes.length >= 2

        return bytes;
    }   // end decode


    /* ********  I N N E R   C L A S S   I N P U T S T R E A M  ******** */






    /* ********  I N N E R   C L A S S   O U T P U T S T R E A M  ******** */


}   // end class Base64
