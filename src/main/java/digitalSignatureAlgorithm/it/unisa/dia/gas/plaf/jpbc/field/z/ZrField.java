package digitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.field.z;

import digitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.field.base.AbstractField;
import digitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.util.math.BigIntegerUtils;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * @author Angelo De Caro (jpbclib@gmail.com)
 */
public class ZrField extends AbstractField<ZrElement> {
    private final BigInteger order;
    private ZrElement nqr;
    private final int fixedLengthInBytes;
    final BigInteger twoInverse;


    public ZrField(BigInteger order) {
        this(new SecureRandom(), order, null);
    }

    public ZrField(SecureRandom random, BigInteger order) {
        this(random, order, null);
    }

    public ZrField(BigInteger order, BigInteger nqr) {
        this(new SecureRandom(), order, nqr);
    }

    private ZrField(SecureRandom random, BigInteger order, BigInteger nqr) {
        this.order = order;
        this.orderIsOdd = BigIntegerUtils.isOdd(order);

        this.fixedLengthInBytes = (order.bitLength() + 7) / 8;

        this.twoInverse = BigIntegerUtils.TWO.modInverse(order);

        if (nqr != null)
            this.nqr = newElement().set(nqr);
    }


    public ZrElement<ZrField> newElement() {
        return new ZrElement<>(this);
    }

    public BigInteger getOrder() {
        return order;
    }

    public ZrElement getNqr() {
        if (nqr == null) {
            nqr = newElement();
            do {
                nqr.setToRandom();
            } while (nqr.isSqr());
        }

        return nqr.duplicate();
    }

    public int getLengthInBytes() {
        return fixedLengthInBytes;
    }

}