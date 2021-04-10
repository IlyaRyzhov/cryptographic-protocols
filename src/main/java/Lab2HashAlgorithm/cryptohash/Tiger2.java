// $Id: Tiger2.java 214 2010-06-03 17:25:08Z tp $

package Lab2HashAlgorithm.cryptohash;

/**
 * <p>This class implements the Tiger2 hash algorithm under the
 * {@link Digest} API. Tiger2 differs from Tiger by the padding,
 * which is identical to that of MD4/MD5 in Tiger2, but not in Tiger.</p>
 *
 * <pre>
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 * </pre>
 *
 * @version   $Revision: 214 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

public class Tiger2 extends TigerCore {

	/**
	 * Create the engine.
	 */
	public Tiger2()
	{
		super((byte)0x80);
	}

	/** @see Digest */
	public Digest copy()
	{
		return copyState(new Tiger2());
	}

	/** @see Digest */
	public String toString()
	{
		return "Tiger2";
	}
}
