package digitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.field.base;

import digitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.Element;
import digitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.Vector;

import java.util.ArrayList;
import java.util.List;

/**
 * @author Angelo De Caro (jpbclib@gmail.com)
 */
public abstract class AbstractVectorElement<E extends Element, F extends AbstractFieldOver> extends AbstractElement<F> implements Vector<E> {

    protected List<E> coeff;

    protected AbstractVectorElement(F field) {
        super(field);

        this.coeff = new ArrayList<>();
    }


    public E getAt(int index) {
        return coeff.get(index);
    }

    public int getSize() {
        return coeff.size();
    }

}