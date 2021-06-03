package Lab7MutualAuthenticationProtocol;

public abstract class AuthenticationProtocolAbstract {
    protected int numberOfUnsuccessfulAttempts;

    public abstract boolean authenticateTwoUsers(UserOfTransmissionProtocol initiator, UserOfTransmissionProtocol pretender);
}
