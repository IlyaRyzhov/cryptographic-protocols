package mutualAuthenticationProtocol;

public abstract class AuthenticationProtocolAbstract {
    protected int numberOfUnsuccessfulAttempts;

    /**
     * Проводит процесс аутентификации двух пользователей
     *
     * @param initiator инициатор процесса аутентификации
     * @param pretender аутентифицируемый пользователь
     * @return true если процесс аутентификации завершился успешно, false в противном случае
     * @author Ilya Ryzhov
     */
    public abstract boolean authenticateTwoUsers(UserOfTransmissionProtocol initiator, UserOfTransmissionProtocol pretender);
}
