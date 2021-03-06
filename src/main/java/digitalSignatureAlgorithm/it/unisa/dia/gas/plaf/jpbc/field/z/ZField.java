package digitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.field.z;

import digitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.field.base.AbstractField;

import java.math.BigInteger;

/**
 * @author Angelo De Caro (jpbclib@gmail.com)
 */
public class ZField extends AbstractField<ZElement> {

    public ZElement newElement() {
        return new ZElement(this);
    }

    public BigInteger getOrder() {
        return BigInteger.ZERO;
    }

    public ZElement getNqr() {
        throw new IllegalStateException("Not implemented yet!!!");
    }

    public int getLengthInBytes() {
        return -1;
    }

}
