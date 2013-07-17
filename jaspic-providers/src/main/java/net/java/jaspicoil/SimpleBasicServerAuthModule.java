package net.java.jaspicoil;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.callback.CallerPrincipalCallback;
import javax.security.auth.message.callback.PasswordValidationCallback;
import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;

/**
 * This JASPIC Module implements a HTTP Basic Authentication.
 * 
 * @author bugeaud at gmail dot com
 * @see http://tools.ietf.org/html/draft-ietf-httpauth-basicauth-enc-01
 * @license CDDL1 http://www.opensource.org/licenses/cddl1.txt
 * @license LGPL http://www.gnu.org/copyleft/lesser.html
 * 
 */
public class SimpleBasicServerAuthModule implements ServerAuthModule {

	private String jaasContextName;
	private static Logger LOG = Logger.getLogger("net.java.jaspicoil");
	private CallbackHandler handler;
	private boolean mandatory;

	public SimpleBasicServerAuthModule() {
	}

	public SimpleBasicServerAuthModule(String contextName) {
		this.jaasContextName = contextName;
	}

	/**
	 * Initialize this module with request and response message policies to
	 * enforce, a CallbackHandler, and any module-specific configuration
	 * properties. The request policy and the response policy must not both be
	 * null.
	 * 
	 * @param requestPolicy
	 *            The request policy this module must enforce, or null.
	 * @param responsePolicy
	 *            The response policy this module must enforce, or null.
	 * @param handler
	 *            CallbackHandler used to request information.
	 * @param options
	 *            A Map of module-specific configuration properties.
	 * @throws AuthException
	 *             If module initialization fails, including for the case where
	 *             the options argument contains elements that are not supported
	 *             by the module.
	 */
	public void initialize(MessagePolicy requestPolicy,
			MessagePolicy responsePolicy, CallbackHandler handler, Map options)
			throws AuthException {
		this.handler = handler;
		// If none policy was provided, we assume this provider is mandatory.
		// This is unfortunately required as some container workaround
		this.mandatory = requestPolicy != null ? requestPolicy.isMandatory()
				: true;

		this.jaasContextName = (String) options.get(JAAS_LOGIN_CONTEXT);

	}

	private static Class<?>[] supportedMessageTypes = new Class<?>[] {
			javax.servlet.http.HttpServletRequest.class,
			javax.servlet.http.HttpServletResponse.class };

	/**
	 * Get the one or more Class objects representing the message types
	 * supported by the module.
	 * 
	 * @return An array of Class objects, with at least one element defining a
	 *         message type supported by the module.
	 */
	@SuppressWarnings("rawtypes")
	public Class[] getSupportedMessageTypes() {
		return supportedMessageTypes;
	}

	protected static final String JAAS_LOGIN_CONTEXT = "javax.security.auth.login.LoginContext";
	protected static final String AUTHORIZATION_HEADER = "Authorization";
	protected static final String AUTHENTICATE_HEADER = "WWW-Authenticate";
	protected static final String BASIC_PREFIX = "basic ";
	protected static final int BASIC_PREFIX_LENGTH = BASIC_PREFIX.length();
	protected static final String CHARSET_SUFFIX = ", charset=\"UTF-8\"";
	protected static final Charset UTF_8 = Charset.forName("UTF-8");

	/**
	 * Authenticate a received service request.
	 * <p/>
	 * This method is called to transform the mechanism-specific request message
	 * acquired by calling getRequestMessage (on messageInfo) into the validated
	 * application message to be returned to the message processing runtime. If
	 * the received message is a (mechanism-specific) meta-message, the method
	 * implementation must attempt to transform the meta-message into a
	 * corresponding mechanism-specific response message, or to the validated
	 * application request message. The runtime will bind a validated
	 * application message into the the corresponding service invocation.
	 * <p>
	 * This method conveys the outcome of its message processing either by
	 * returning an AuthStatus value or by throwing an AuthException.
	 * <p/>
	 * From a performance point of view this method will be called twice for
	 * each resource with a security constraint on it. Resources with no
	 * security constraint do not result in a call to this method.
	 * 
	 * @param messageInfo
	 *            A contextual object that encapsulates the client request and
	 *            server response objects, and that may be used to save state
	 *            across a sequence of calls made to the methods of this
	 *            interface for the purpose of completing a secure message
	 *            exchange.
	 * @param clientSubject
	 *            A Subject that represents the source of the service request.
	 *            It is used by the method implementation to store Principals
	 *            and credentials validated in the request.
	 * @param serviceSubject
	 *            A Subject that represents the recipient of the service
	 *            request, or null. It may be used by the method implementation
	 *            as the source of Principals or credentials to be used to
	 *            validate the request. If the Subject is not null, the method
	 *            implementation may add additional Principals or credentials
	 *            (pertaining to the recipient of the service request) to the
	 *            Subject.
	 * @return An AuthStatus object representing the completion status of the
	 *         processing performed by the method. The AuthStatus values that
	 *         may be returned by this method are defined as follows:
	 *         <p/>
	 *         <ul>
	 *         <li>AuthStatus.SUCCESS when the application request message was
	 *         successfully validated. The validated request message is
	 *         available by calling getRequestMessage on messageInfo.
	 *         <p/>
	 *         <li>AuthStatus.SEND_SUCCESS to indicate that
	 *         validation/processing of the request message successfully
	 *         produced the secured application response message (in
	 *         messageInfo). The secured response message is available by
	 *         calling getResponseMessage on messageInfo.
	 *         <p/>
	 *         <li>AuthStatus.SEND_CONTINUE to indicate that message validation
	 *         is incomplete, and that a preliminary response was returned as
	 *         the response message in messageInfo.
	 *         <p/>
	 *         When this status value is returned to challenge an application
	 *         request message, the challenged request must be saved by the
	 *         authentication module such that it can be recovered when the
	 *         module's validateRequest message is called to process the request
	 *         returned for the challenge.
	 *         <p/>
	 *         <li>AuthStatus.SEND_FAILURE to indicate that message validation
	 *         failed and that an appropriate failure response message is
	 *         available by calling getResponseMessage on messageInfo.
	 *         </ul>
	 * @throws AuthException When the message processing failed without
	 *         establishing a failure response message (in messageInfo).
	 */
	public AuthStatus validateRequest(MessageInfo messageInfo,
			Subject clientSubject, Subject serviceSubject) throws AuthException {
		// Get the servlet context
		final HttpServletRequest request = (HttpServletRequest) messageInfo
				.getRequestMessage();
		final HttpServletResponse response = (HttpServletResponse) messageInfo
				.getResponseMessage();
		final String auth = request.getHeader(AUTHORIZATION_HEADER);
		// Test prefix for HTTP BASIC Auth
		if (auth != null && StringUtils.startsWithIgnoreCase(auth, "basic ")) {
			// We might have a valid header, so try to decode it
			final String data = new String(Base64.decodeBase64(auth
					.substring(BASIC_PREFIX_LENGTH)), UTF_8);
			final int splitIndex = data.indexOf(':');
			if (splitIndex < 0) {
				return sendErrorAndAuthenticateRequest(request, response,
						"Wrong WWW-Authenticate header format");
			}
			final String username = data.substring(splitIndex);
			final char[] password = data.substring(splitIndex + 1,
					data.length()).toCharArray();

			// Prepare the JAAS callback to feed any LoginModule with user and password
			final NameCallback nameCallback = new NameCallback("username");
			nameCallback.setName(username);

			final PasswordCallback passwordCallback = new PasswordCallback(
					getRealm(request), false);
			passwordCallback.setPassword(password);

			final CallbackHandler delegatedHandler = new CallbackHandler() {
				public void handle(Callback[] callbacks) throws IOException,
						UnsupportedCallbackException {
					for (int i = 0; i < callbacks.length; i++) {
						final Callback c = callbacks[i];
						if (c instanceof NameCallback) {
							((NameCallback) c).setName(username);
						} else if (c instanceof PasswordCallback) {
							((PasswordCallback) c).setPassword(password);
						} else {
							throw new UnsupportedOperationException(
									String.format("Callback type %s (%s) is not supported yet.",c.getClass(),c));
						}
					}
				}
			};

			if (this.jaasContextName == null) {
			    throw new UnsupportedOperationException("No delegate JAAS context found. As per JASPIC JAAS Bridge profile, this parameter is requiered.");
			}

			try {
				// Create a new JAAS context with the delegated data & try to login
				final LoginContext context = new LoginContext(this.jaasContextName, delegatedHandler);
				context.login();
				
				// Get the authenticated subject from the JAAS context
				Subject authenticatedSubject = context.getSubject();

				final PasswordValidationCallback passwordValidationCallback = new PasswordValidationCallback(authenticatedSubject, username,password);
				
				// notify JASPIC containerr for the name, password and subject
				this.handler.handle(new Callback[] { passwordValidationCallback });

			} catch (final LoginException ex) {
			    // If there was any issue during the JAAS login, fail the process
			    final AuthException aex = new AuthException(String.format("Fail to login user %s with the delegated JAAS context %s",username,this.jaasContextName));
			    aex.initCause(ex);
			} catch (final IOException e) {
				LOG.log(Level.WARNING, "Unable to call the handlers for name="
						+ nameCallback, e);
			} catch (final UnsupportedCallbackException e) {
				LOG.log(Level.WARNING, "Unable to call the handlers for name="
						+ nameCallback, e);
			}

		} else if (this.mandatory) {
			return sendErrorAndAuthenticateRequest(request, response,
					"AuthModule was mandatory but no valid credential was provided");
		} else {
			LOG.info("No authentication was provided bu Basic AuthModule is not mandatory so return SUCCESS.");
		}

		return AuthStatus.SUCCESS;
	}

	private String getRealm(HttpServletRequest request) {
		// TODO should implement this dynamically
		return "FakeRealm";
	}

	private AuthStatus sendErrorAndAuthenticateRequest(
			HttpServletRequest request, HttpServletResponse response,
			String message) {
		response.setHeader(AUTHENTICATE_HEADER,
				createAuthenticateValue(getRealm(request)));
		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		LOG.fine(message);
		return AuthStatus.SEND_CONTINUE;
	}

	private AuthStatus sendErrorAndFail(HttpServletRequest request,
			HttpServletResponse response, String message) {
		response.setHeader(AUTHENTICATE_HEADER,
				createAuthenticateValue(getRealm(request)));
		response.setStatus(HttpServletResponse.SC_FORBIDDEN);
		LOG.fine(message);
		return AuthStatus.FAILURE;
	}

	private String createAuthenticateValue(String realm) {
		final StringBuilder builder = new StringBuilder();
		builder.append("Basic realm=\"").append(realm)
				.append("\", charset=\"UTF-8\"");
		return builder.toString();
	}

	/**
	 * Secure a service response before sending it to the client.
	 * <p/>
	 * This method is called to transform the response message acquired by
	 * calling getResponseMessage (on messageInfo) into the mechanism-specific
	 * form to be sent by the runtime.
	 * <p>
	 * This method conveys the outcome of its message processing either by
	 * returning an AuthStatus value or by throwing an AuthException.
	 * 
	 * @param messageInfo
	 *            A contextual object that encapsulates the client request and
	 *            server response objects, and that may be used to save state
	 *            across a sequence of calls made to the methods of this
	 *            interface for the purpose of completing a secure message
	 *            exchange.
	 * @param serviceSubject
	 *            A Subject that represents the source of the service response,
	 *            or null. It may be used by the method implementation to
	 *            retrieve Principals and credentials necessary to secure the
	 *            response. If the Subject is not null, the method
	 *            implementation may add additional Principals or credentials
	 *            (pertaining to the source of the service response) to the
	 *            Subject.
	 * @return An AuthStatus object representing the completion status of the
	 *         processing performed by the method. The AuthStatus values that
	 *         may be returned by this method are defined as follows:
	 *         <p/>
	 *         <ul>
	 *         <li>AuthStatus.SEND_SUCCESS when the application response message
	 *         was successfully secured. The secured response message may be
	 *         obtained by calling getResponseMessage on messageInfo.
	 *         <p/>
	 *         <li>AuthStatus.SEND_CONTINUE to indicate that the application
	 *         response message (within messageInfo) was replaced with a
	 *         security message that should elicit a security-specific response
	 *         (in the form of a request) from the peer.
	 *         <p/>
	 *         This status value serves to inform the calling runtime that (to
	 *         successfully complete the message exchange) it will need to be
	 *         capable of continuing the message dialog by processing at least
	 *         one additional request/response exchange (after having sent the
	 *         response message returned in messageInfo).
	 *         <p/>
	 *         When this status value is returned, the application response must
	 *         be saved by the authentication module such that it can be
	 *         recovered when the module's validateRequest message is called to
	 *         process the elicited response.
	 *         <p/>
	 *         <li>AuthStatus.SEND_FAILURE to indicate that a failure occurred
	 *         while securing the response message and that an appropriate
	 *         failure response message is available by calling
	 *         getResponseMeessage on messageInfo.
	 *         </ul>
	 * @throws AuthException When the message processing failed without
	 *         establishing a failure response message (in messageInfo).
	 */
	public AuthStatus secureResponse(MessageInfo messageInfo,
			Subject serviceSubject) throws AuthException {
		// nothing to do but go thru
		return AuthStatus.SUCCESS;
	}

	/**
	 * Remove method specific principals and credentials from the subject.
	 * 
	 * @param messageInfo
	 *            a contextual object that encapsulates the client request and
	 *            server response objects, and that may be used to save state
	 *            across a sequence of calls made to the methods of this
	 *            interface for the purpose of completing a secure message
	 *            exchange.
	 * @param subject
	 *            the Subject instance from which the Principals and credentials
	 *            are to be removed.
	 * @throws AuthException If an error occur during the Subject processing.
	 */
	public void cleanSubject(MessageInfo messageInfo, Subject clientSubject)
			throws AuthException {
		// Nothing to do yet
	}
}
