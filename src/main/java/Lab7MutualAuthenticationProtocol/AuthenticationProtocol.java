package Lab7MutualAuthenticationProtocol;

public interface AuthenticationProtocol {
    boolean authenticateTwoUsers(UserOfTransmissionProtocol initiator, UserOfTransmissionProtocol pretender);
}
