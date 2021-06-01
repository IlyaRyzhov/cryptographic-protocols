package Lab7MutualAuthenticationProtocol;

public abstract class AuthenticationProtocolAbstract {
    protected int numberOfUnsuccessfulAttempts;

    abstract boolean authenticateTwoUsers(UserOfTransmissionProtocol initiator, UserOfTransmissionProtocol pretender);
}
