package digitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.field.gt;

import digitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.Element;
import digitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.field.base.AbstractElement;
import digitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.pairing.map.PairingMap;

import java.math.BigInteger;

/**
 * @author Angelo De Caro (jpbclib@gmail.com)
 */
public class GTFiniteElement extends AbstractElement {
    private final PairingMap pairing;
    Element value;


    public GTFiniteElement(PairingMap pairing, GTFiniteField field) {
        super(field);

        this.pairing = pairing;
        this.value = field.getTargetField().newElement().setToOne();
    }

    public GTFiniteElement(PairingMap pairing, GTFiniteField field, Element value) {
        super(field);

        this.pairing = pairing;
        this.value = value;
    }

    GTFiniteElement(GTFiniteElement element) {
        super(element.field);

        this.pairing = element.pairing;
        this.value = element.value;
    }


    public GTFiniteElement getImmutable() {
        if (isImmutable())
            return this;

        return new ImmutableGTFiniteElement(this);
    }

    public GTFiniteElement duplicate() {
        return new GTFiniteElement(pairing, (GTFiniteField) field, value.duplicate());
    }

    public GTFiniteElement set(Element value) {
        this.value.set(((GTFiniteElement) value).value);

        return this;
    }

    public GTFiniteElement set(int value) {
        this.value.set(value);

        return this;
    }

    public GTFiniteElement set(BigInteger value) {
        this.value.set(value);

        return this;
    }

    public boolean isZero() {
        return isOne();
    }

    public boolean isOne() {
        return value.isOne();
    }

    public GTFiniteField getField() {
        return (GTFiniteField) field;
    }

    public GTFiniteElement setToZero() {
        value.setToOne();

        return this;
    }

    public GTFiniteElement setToOne() {
        value.setToOne();

        return this;
    }

    public GTFiniteElement setToRandom() {
        value.setToRandom();
        pairing.finalPow(value);

        return this;
    }

    public GTFiniteElement setFromHash(byte[] source, int offset, int length) {
        value.setFromHash(source, offset, length);
        pairing.finalPow(value);

        return this;
    }

    public int setFromBytes(byte[] source) {
        return value.setFromBytes(source);
    }

    public int setFromBytes(byte[] source, int offset) {
        return value.setFromBytes(source, offset);
    }

    public GTFiniteElement invert() {
        value.invert();

        return this;
    }

    public GTFiniteElement negate() {
        return invert();
    }

    public GTFiniteElement add(Element element) {
        return mul(element);
    }

    public GTFiniteElement sub(Element element) {
        return div(element);
    }

    public GTFiniteElement div(Element element) {
        value.div(((GTFiniteElement) element).value);

        return this;
    }

    public GTFiniteElement mul(Element element) {
        value.mul(((GTFiniteElement) element).value);

        return this;
    }

    public GTFiniteElement mul(BigInteger n) {
        return pow(n);
    }

    public boolean isSqr() {
        throw new IllegalStateException("Not Implemented yet!");
    }

    public GTFiniteElement pow(BigInteger n) {
        this.value.pow(n);

        return this;
    }

    @Override
    public Element powZn(Element n) {
        return null;
    }

    public boolean isEqual(Element element) {
        return this == element || (element instanceof GTFiniteElement && value.isEqual(((GTFiniteElement) element).value));

    }

    public BigInteger toBigInteger() {
        return value.toBigInteger();
    }

    @Override
    public byte[] toBytes() {
        return value.toBytes();
    }

    public int sign() {
        throw new IllegalStateException("Not implemented yet!!!");
    }

    public String toString() {
        return value.toString();
    }

}
