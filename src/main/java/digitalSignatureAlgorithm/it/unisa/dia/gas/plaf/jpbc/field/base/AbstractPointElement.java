package digitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.field.base;

import digitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.Element;
import digitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.Point;
import digitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.Vector;

/**
 * @author Angelo De Caro (jpbclib@gmail.com)
 */
public abstract class AbstractPointElement<E extends Element, F extends AbstractFieldOver> extends AbstractElement<F> implements Point<E>, Vector<E> {

    protected E x, y;


    protected AbstractPointElement(F field) {
        super(field);
    }


    public E getX() {
        return x;
    }

    public E getY() {
        return y;
    }


}
