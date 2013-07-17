package net.java.jaspicoil;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.callback.CallerPrincipalCallback;
import javax.security.auth.message.callback.GroupPrincipalCallback;
import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import net.java.jaspicoil.util.ADUtil;

import org.apache.commons.codec.binary.Base64;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import org.jaaslounge.decoding.kerberos.KerberosAuthData;
import org.jaaslounge.decoding.kerberos.KerberosPacAuthData;
import org.jaaslounge.decoding.kerberos.KerberosToken;
import org.jaaslounge.decoding.pac.Pac;
import org.jaaslounge.decoding.pac.PacLogonInfo;
import org.jaaslounge.decoding.pac.PacSid;
import org.jaaslounge.decoding.spnego.SpnegoConstants;
import org.jaaslounge.decoding.spnego.SpnegoToken;

/**
 * <p>
 * This JASPIC Module supports the Kerberos SPNEGO mechanism and leverages
 * MS-PAC to provide advanced features:
 * <ul>
 * <li>Secured SSO between client session (Windows) and server webapp</li>
 * <li>REST compatible SSO that enables facade integration strategies between
 * webapps</li>
 * <li>Support Qualified SSO to segregate between Smarcard authenticated users
 * and regular ones</li>
 * <li>Compatible with JSR-196 containers : Glassfish, JBoss ...</li>
 * <li>Multi-OS Server Support (Windows, Linux ...)</li>
 * <li>Limit usage of LDAP to increase performance and stability</li>
 * <li>Supports Sun and IBM branches of JVM</li>
 * <li>...</li>
 * </ul>
 * </p>
 * <p>
 * Authentication is base on the Kerberos protocol using the underlying
 * </p>
 * The users will be added groups as contained in the MS-PAC plus if Smartcard
 * Logon authenticated the syntetic group SMARTCARD_AUTHENTICATED.
 * 
 * Various parameters can be set : <dd>
 * <dt>principalName</dt>
 * <dl>
 * REQUIRED: The Service Principal Name to be used to fetch.
 * </dl>
 * </dd> <dd>
 * <dt>keyTabLocation</dt>
 * <dl>
 * REQUIRED: The location of the keytab containing the keys for the SPN
 * indicated in the "principalName" parameter
 * </dl>
 * </dd> <dd>
 * <dt>debug</dt>
 * <dl>
 * OPTIONAL : If true, it will print to the default logger some debug
 * information. By default debug is set to false.
 * </dl>
 * </dd> <dd>
 * <dt>jaasContext</dt>
 * <dl>
 * OPTIONAL : The name of the JAAS LoginModule configuration to use for the
 * internal usage. If none is provided, it will use defaults on the related
 * calls.
 * </dl>
 * </dd> <dd>
 * <dt>secureGroupSids</dt>
 * <dl>
 * OPTIONAL: A comma separated list of canonical string representation of AD
 * SIDs. When found on a user, any of these SIDS will be granted the synthetic
 * SMARTCARD_AUTHENTICATED group.
 * </dl>
 * </dd> <dd>
 * <dt>mandatoryGroups</dt>
 * <dl>
 * OPTIONAL: A comma separated list of group string (SID, CN ...) that will be
 * checked before granting access to the application.
 * </dl>
 * </dd> <dd>
 * <dt>smartcardSecuredUsersOnly</dt>
 * <dl>
 * OPTIONAL: When set to true, this boolean flag indicates that users not
 * authenticated thru smartcard logon will be denied access to the protected
 * context. When not set or set to another value, the default value is false.
 * </dl>
 * </dd> <dd>
 * <dt>delegatedSecuredUsersOnly</dt>
 * <dl>
 * OPTIONAL: When set to true, this boolean flag indicates that users not
 * authenticated thru KCD will be denied access to the protected context. When
 * not set or set to another value, the default value is false
 * </dl>
 * </dd> <dd>
 * <dt>groupMapping</dt>
 * <dl>
 * OPTIONAL: An URL to an accessible & valid Java properties file container
 * extra group mapping. It might be used to map SID for logical group names or
 * to provide an alternative solution to container managed mapping.
 * </dl>
 * </dd> <dd>
 * <dt>sessionAttributes</dt>
 * <dl>
 * OPTIONAL: A list of comma separated values representing a pair (key, value)
 * to store in the user session one authenticated.
 * </dl>
 * </dd> <dd>
 * <dt>userHeader</dt>
 * <dl>
 * OPTIONAL: Name of HTTP Header where to store the user name that was
 * authenticated. This feature is only supported thru the Tomcat Valve.
 * </dl>
 * </dd> <dd>
 * <dt>administratorGroups</dt>
 * <dl>
 * FUTURE / OPTIONAL: A list of groups that indicate the user is an
 * administrator. By default, no administrator group is set
 * </dl>
 * </dd> <dd>
 * <dt>administratorOnlyURIs</dt>
 * <dl>
 * FUTURE / OPTIONAL: A list of comma separated URI patterns that are blocked
 * unless member of administrator group. Warning : this feature is working on
 * container that invoke the SAM on all resources including the non-protected
 * ones.
 * </dl>
 * </dd> <dd>
 * <dt>javax.security.jacc.PolicyContext</dt>
 * <dl>
 * INTERNAL : send by the container to indicate the PolicyContext to use.
 * </dl>
 * </dd> <dd>
 * <dt>javax.security.auth.message.MessagePolicy.isMandatory</dt>
 * <dl>
 * INTERNAL : sent by the container according to JSR-196 to indicate if the
 * policy is mandatory (value true) or not (value false).
 * </dl>
 * </dd>
 * <p>
 * The parameters principalName and keyTabLocation are <b>only required</b> if
 * there was no JAAS delegated context found (from jaasContext associated
 * parameter value or thru JASPIC/JAAS internal context).
 * </p>
 * <p>
 * When sartcardSecuredUsersOnly and delegatedSecuredUsersOnly flags are both
 * set to true, users not authenticated thru smartcard logon or KCD will be
 * denied access to the protected context.
 * </p>
 * <p>
 * A tag FUTURE on a parameter indicates that this feature is not yet supported
 * and/or available in this version.
 * 
 * @author bugeaud at gmail dot com
 * @license CDDL1 http://www.opensource.org/licenses/cddl1.txt
 * @license LGPL http://www.gnu.org/copyleft/lesser.html
 */
public class MSPacSpnegoServerAuthModule implements ServerAuthModule {

	public static final String AUTH_TYPE_INFO_KEY = "javax.servlet.http.authType";
	public static final String MAGIC_SESSION_STATE_KEY = "net.java.spnego.jaspic.MagicSessionState";
	public static final String USERNAME_SESSION_KEY = "net.java.jaspic.user.name";
	public static final String REALM_SESSION_KEY = "net.java.jaspic.user.realm";
	public static final String DEBUG_OPTIONS_KEY = "debug";
	public static final String POLICY_CONTEXT_OPTIONS_KEY = "javax.security.jacc.PolicyContext";
	public static final String IS_MANDATORY_INFO_KEY = "javax.security.auth.message.MessagePolicy.isMandatory";
	public static final String SERVICE_PRINCIPAL_NAME_KEY = "principalName";
	public static final String KEYTAB_LOCATION_KEY = "keyTabLocation";
	public static final String JAAS_CONTEXT_KEY = "jaasContext";
	public static final String SECURE_GROUP_SIDS_KEY = "secureGroupSids";
	public static final String MANDATORY_GROUPS_KEY = "mandatoryGroups";
	public static final String GROUP_MAPPING_KEY = "groupMapping";
	public static final String SESSION_ATTRIBUTES_KEY = "sessionAttributes";
	public static final String USER_HEADER_KEY = "userHeader";
	public static final String ADMINISTRATOR_GROUPS_KEY = "administratorGroups";
	public static final String ADMINISTRATOR_ONLY_URIS_KEY = "administratorOnlyURIs";
	public static final String SMARTCARD_SECURED_USERS_ONLY = "smartcardSecuredUsersOnly";
	public static final String DELEGATED_SECURED_USERS_ONLY = "delegatedSecuredUsersOnly";
	private static final String AUTHORIZATION_HEADER = "authorization";
	private static final String AUTHENTICATION_HEADER = "WWW-Authenticate";
	private static final String NEGOTIATE = "Negotiate";
	private static final String NTLM_INITIAL_TOKEN = "NTLMSSP";
	/**
	 * Role indicating the user has authenticated thru smarcard
	 */
	public static final String GROUP_SMARTCARD_AUTHENTICATED = "SMARTCARD_AUTHENTICATED";
	/**
	 * Role indicating the user has authenticated thru KCD authentication
	 */
	public static final String GROUP_DELEGATED_AUTHENTICATED = "DELEGATED_AUTHENTICATED";
	/**
	 * Role indicating the user was accessing thru a secured channel
	 */
	public static final String GROUP_SECURED_CHANNEL = "SECURED_CHANNEL";
	/**
	 * Role indicating the user was accessing thru an unsecured secured channel
	 */
	public static final String GROUP_UNSECURED_CHANNEL = "UNSECURED_CHANNEL";
	private static final Logger LOG = Logger
			.getLogger(MSPacSpnegoServerAuthModule.class.getName());
	private static Class<?>[] supportedMessageTypes = new Class<?>[] {
			javax.servlet.http.HttpServletRequest.class,
			javax.servlet.http.HttpServletResponse.class };
	/**
	 * The Kerberos OID
	 */
	private static Oid GSS_KRB5_MECH_OID = null;

	static {
		try {
			GSS_KRB5_MECH_OID = new Oid("1.2.840.113554.1.2.2");
		} catch (final GSSException e) {
			LOG.log(Level.SEVERE, "Unkown GSS_KRB5_MECH_OID", e);
		}
	}

	/**
	 * State of the AuthModule is kept using this status
	 */
	public enum SessionState {
		// The SPNEGO was started

		STARTED,
		// The SPNEGO was accepted a first time but more data is needed
		IN_PROGRESS,
		// The SPNEGO was fully ESTABLISHED
		ESTABLISHED
	}

	private MessagePolicy requestPolicy;
	private MessagePolicy responsePolicy;
	private CallbackHandler handler;
	private Map<String, ?> options;
	private boolean debug;
	private String servicePrincipal;
	private URL keyTabLocation;
	private String jaasContextName;
	private Subject serviceSubject;
	private Set<String> secureGroups;
	private Set<String> mandatoryGroups;
	private Set<String> administratorGroups;
	private Set<String> administratorOnlyUris;
	private Properties groupMapping;
	private Map<String, String> sessionAttributes;
	private String userHeader;
	private Level debugLevel;
	private String policyContextID;
	private boolean mandatory;
	private boolean smartcardSecuredUsersOnly = false;
	private boolean delegatedSecuredUsersOnly = false;
	/**
	 * This stores the login module name
	 */
	private String loginModuleName;

	public MSPacSpnegoServerAuthModule() {
	}

	/**
	 * Create a Kerberos MS-PAC JASPIC module indicating the login module
	 * context
	 * 
	 * @param loginModuleName
	 */
	public MSPacSpnegoServerAuthModule(String loginModuleName) {
		this.loginModuleName = loginModuleName;
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
	@SuppressWarnings({ "rawtypes", "unchecked" })
	public void initialize(MessagePolicy requestPolicy,
			MessagePolicy responsePolicy, CallbackHandler handler, Map options)
			throws AuthException {

		boolean useDelegatedLoginModule = false;
		// If no options or empty options was provided get away and display some
		// usage log
		// Please note that some AS such as JBoss 7 call this method twice.
		if (options == null || options.isEmpty()) {
			LOG.warning(String
					.format("Options is either empty or null this time. Please make sure that "
							+ "at least the parameter %s and %s are set in the JASPIC provider configuration.",
							SERVICE_PRINCIPAL_NAME_KEY, KEYTAB_LOCATION_KEY));
			return;
		}

		this.requestPolicy = requestPolicy;
		this.responsePolicy = responsePolicy;

		// If none policy was provided, we assume this provider is mandatory.
		// This is unfortunately required as some container issue workaround
		this.mandatory = requestPolicy != null ? requestPolicy.isMandatory()
				: true;

		this.handler = handler;
		this.options = options;

		this.debug = options.containsKey(DEBUG_OPTIONS_KEY);

		// Set the debug level according to the logger config and the JASPIC
		// config
		this.debugLevel = LOG.isLoggable(Level.FINE) && !this.debug ? Level.FINE
				: Level.INFO;
		debug("Debug was set ({0},{1})", this.debug, this.debugLevel);

		this.jaasContextName = (String) options.get(JAAS_CONTEXT_KEY);
		debug("Jaas context name was set {0}", this.jaasContextName);

		if (this.jaasContextName == null && this.loginModuleName != null) {
			debug("There was no JAAS context parameter set on the JASPIC so using the default passed from the application server");
			this.jaasContextName = this.loginModuleName;
			useDelegatedLoginModule = true;
		}

		this.policyContextID = (String) options.get(POLICY_CONTEXT_OPTIONS_KEY);
		debug("Policy context set to {0}", this.policyContextID);

		this.servicePrincipal = (String) options
				.get(SERVICE_PRINCIPAL_NAME_KEY);
		debug("Principal set to {0}", this.servicePrincipal);

		// If there was no delegated LoginModule found we must set a SPN
		if (!useDelegatedLoginModule && this.servicePrincipal == null) {
			LOG.severe("A valid SPN must be configured for JASPIC connector with the property "
					+ SERVICE_PRINCIPAL_NAME_KEY);
			return;
		}

		// Get the secure groups
		final String groupList = (String) options.get(SECURE_GROUP_SIDS_KEY);
		if (groupList != null && !"".equals(groupList.trim())) {
			this.secureGroups = Collections
					.unmodifiableSet(new HashSet<String>(Arrays
							.asList(groupList.trim().split(","))));
			debug("Secure groups set as: {0}", this.secureGroups);
		}

		// Get the mandatory groups
		final String mandatoryGroupList = (String) options
				.get(MANDATORY_GROUPS_KEY);
		if (mandatoryGroupList != null && !"".equals(mandatoryGroupList.trim())) {
			this.mandatoryGroups = Collections
					.unmodifiableSet(new HashSet<String>(Arrays
							.asList(mandatoryGroupList.trim().split(","))));
			debug("Mandatory groups set as: {0}", this.mandatoryGroups);
		}

		final String administratorGroupList = (String) options
				.get(ADMINISTRATOR_GROUPS_KEY);
		if (administratorGroupList != null
				&& !"".equals(administratorGroupList.trim())) {
			this.administratorGroups = Collections
					.unmodifiableSet(new HashSet<String>(Arrays
							.asList(administratorGroupList.trim().split(","))));
			debug("Administrator groups set as: {0}", this.mandatoryGroups);
		}

		final String administratorOnlyUriList = (String) options
				.get(ADMINISTRATOR_ONLY_URIS_KEY);
		if (administratorOnlyUriList != null
				&& !"".equals(administratorOnlyUriList.trim())) {
			this.administratorOnlyUris = Collections
					.unmodifiableSet(new HashSet<String>(Arrays
							.asList(administratorOnlyUriList.trim().split(","))));
			debug("Administrator restricted URIs set as: {0}",
					this.mandatoryGroups);
		}

		final String sessionAttributeList = (String) options
				.get(SESSION_ATTRIBUTES_KEY);
		if (sessionAttributeList != null
				&& !"".equals(sessionAttributeList.trim())) {
			final String[] pairs = sessionAttributeList.trim().split(",");
			final Map<String, String> attributes = new HashMap<String, String>();
			for (final String pair : pairs) {
				final String[] vals = pair.split("=");
				attributes.put(vals[0], vals[1]);
			}
			this.sessionAttributes = Collections.unmodifiableMap(attributes);
			debug("Session attributes was set to {0}", this.sessionAttributes);
		}

		final String keyTabLocationString = (String) options
				.get(KEYTAB_LOCATION_KEY);
		if (!useDelegatedLoginModule && keyTabLocationString == null) {
			LOG.severe("A valid key tab location must be configured for JASPIC connector with the property "
					+ KEYTAB_LOCATION_KEY);
			return;
		}

		if (keyTabLocationString != null) {
			// Try to reference the indicated keytab
			try {
				this.keyTabLocation = new URL(keyTabLocationString);
				debug("Keytab location was set to {0}", this.keyTabLocation);
			} catch (final MalformedURLException e) {
				LOG.log(Level.WARNING,
						"Unable to build " + KEYTAB_LOCATION_KEY
								+ " from the parameter value "
								+ options.get(KEYTAB_LOCATION_KEY), e);
			}
		}

		URL groupMappingSource = null;
		try {
			final String groupParam = (String) options.get(GROUP_MAPPING_KEY);
			if (groupParam != null && !"".equals(groupParam.trim())) {
				groupMappingSource = new URL(groupParam);
			}

		} catch (final MalformedURLException e) {
			LOG.log(Level.WARNING,
					"Unable to build " + GROUP_MAPPING_KEY
							+ " from the parameter value "
							+ options.get(GROUP_MAPPING_KEY), e);
		}
		if (groupMappingSource != null) {
			final Properties groupMapping = new Properties();

			try {
				InputStream groupMappingInputstream = null;
				try {
					groupMappingInputstream = groupMappingSource.openStream();
					groupMapping.load(groupMappingInputstream);
				} finally {
					if (groupMappingInputstream != null) {
						groupMappingInputstream.close();
					}
				}
				this.groupMapping = groupMapping;
				debug("Group mapping was set to {0}", this.groupMapping);
			} catch (final IOException ioex) {
				LOG.log(Level.WARNING,
						"Unable to load " + GROUP_MAPPING_KEY
								+ " from the indicated ressource "
								+ options.get(GROUP_MAPPING_KEY), ioex);
			}
		}

		try {
			// Load the serviceSubject from a LoginModule, this is required to
			// get the Kerberos Key
			this.serviceSubject = initializeKerberosServerContext(
					this.jaasContextName, this.servicePrincipal,
					this.keyTabLocation, this.debug);
			debug("Service subject was set to {0}", this.serviceSubject);
		} catch (final LoginException e) {
			final AuthException aex = new AuthException(
					"Kerberos service context initialization failed");
			aex.initCause(e);
			throw aex;
		}

		this.smartcardSecuredUsersOnly = Boolean.parseBoolean((String) options
				.get(SMARTCARD_SECURED_USERS_ONLY));
		debug("Only accept smartcard secured users ? {0}",
				this.smartcardSecuredUsersOnly);

		this.delegatedSecuredUsersOnly = Boolean.parseBoolean((String) options
				.get(DELEGATED_SECURED_USERS_ONLY));
		debug("Only accept delegated (KCD) users ? {0}",
				this.delegatedSecuredUsersOnly);

		this.userHeader = (String) options.get(USER_HEADER_KEY);
		debug("User header set to {0}", this.userHeader);

		// TODO Add some fetchExtraGroupsScript handling that will use
		// javax.script to execute
		// an idea is to use the first line as //#!!mime/type the mimetype will
		// be extracted out to known which engine to call
	}

	private Subject initializeKerberosServerContext(String jaasContextName,
			String servicePrincipal, URL keyTabLocation, boolean debug)
			throws LoginException {
		if (jaasContextName == null) {
			// Get the subject from a new LoginContext
			// WARNING: Here we assumes that the URL will be file: based, hence
			// local only.
			final Krb5LoginConfig loginConfig = new Krb5LoginConfig(
					keyTabLocation.getFile(), servicePrincipal, debug);
			return fetchSubjectFromLoginModuleWithPrincipal("",
					servicePrincipal, loginConfig);
		} else if (servicePrincipal == null) {
			// If there was no default service principal name specify then
			// default to the JAAS configuration setup
			return fetchSubjectFromLoginModule(jaasContextName, null, null);
		} else {
			// Get the subject from the indicated JAAS configuration selecting
			// with the indicated principal
			return fetchSubjectFromLoginModuleWithPrincipal(jaasContextName,
					servicePrincipal, null);
		}
	}

	private Subject fetchSubjectFromLoginModuleWithPrincipal(
			String jaasContextName, String servicePrincipal,
			Krb5LoginConfig loginConfig) throws LoginException {
		final Set<Principal> princ = new HashSet<Principal>(1);
		princ.add(new KerberosPrincipal(servicePrincipal));
		// Create a new editable Subject
		final Subject sub = new Subject(false, princ, new HashSet<Object>(),
				new HashSet<Object>());
		return fetchSubjectFromLoginModule(jaasContextName, sub, loginConfig);
	}

	private Subject fetchSubjectFromLoginModule(String jaasContextName,
			Subject subject, Krb5LoginConfig loginConfig) throws LoginException {
		debug("Try to create a context LM for jassname={0}, subject={1}, config={2}",
				jaasContextName, subject, loginConfig);
		final LoginContext lc = new LoginContext(jaasContextName, subject,
				null, loginConfig);
		lc.login();
		return lc.getSubject();
	}

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
	@SuppressWarnings("unchecked")
	public AuthStatus validateRequest(MessageInfo messageInfo,
			Subject clientSubject, Subject serviceSubject) throws AuthException {

		// Extra check (disabled withour -ea) if mandatory value is consistent
		// with initialize phase
		assert messageInfo.getMap().containsKey(IS_MANDATORY_INFO_KEY) == this.mandatory;

		// Get the servlet context
		final HttpServletRequest request = (HttpServletRequest) messageInfo
				.getRequestMessage();
		final HttpServletResponse response = (HttpServletResponse) messageInfo
				.getResponseMessage();

		// Invalidate any existing session to prevent session fixture attempt
		HttpSession session = request.getSession(false);
		if (session != null) {
			final SessionState state = (SessionState) session
					.getAttribute(MAGIC_SESSION_STATE_KEY);
			if (state == null) {
				// Session was not created by us, we will invalidate an existing
				// session that was not created by us
				session.invalidate();
				LOG.warning("An existing session was invalidated. This might be a session fixture attempt, so failing the authentication.");
				return AuthStatus.SEND_FAILURE;
			} else if (SessionState.ESTABLISHED.equals(state)) {
				// The context was already fully established once within this
				// session.
				return AuthStatus.SUCCESS;
			}
		}

		debugRequest(request);

		// should specify encoder
		final String authorization = request.getHeader(AUTHORIZATION_HEADER);

		if (authorization != null && authorization.startsWith(NEGOTIATE)) {

			final String negotiateString = authorization.substring(NEGOTIATE
					.length() + 1);

			final byte[] requestToken = Base64.decodeBase64(negotiateString);

			if (serviceSubject == null) {
				// If no service subject was provided by the container then set
				// a service subject
				// from the global context.
				serviceSubject = this.serviceSubject;
			}

			try {
				// Create a validation action
				byte[] gssToken = null;
				final KerberosValidateAction kva = new KerberosValidateAction(
						this.servicePrincipal, requestToken, serviceSubject);
				try {
					// Validate using the service (server) Subject
					gssToken = Subject.doAs(this.serviceSubject, kva);
				} catch (final PrivilegedActionException e) {
					final GSSException gex = new GSSException(
							GSSException.DEFECTIVE_TOKEN);
					gex.initCause(e);
					gex.setMinor(GSSException.UNAVAILABLE,
							"Unable to perform Kerberos validation");
					throw gex;
				}

				if (kva.getContext() != null) {
					final String responseToken = Base64
							.encodeBase64String(gssToken);
					response.setHeader(AUTHENTICATION_HEADER, "Negotiate "
							+ responseToken);
					debugToken("GSS Response token set to {0}", gssToken);
				}

				if (!kva.isEstablished()) {
					debug("GSS Dialog must continue to succeed");

					session.setAttribute(MAGIC_SESSION_STATE_KEY,
							SessionState.IN_PROGRESS);

					response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
					return AuthStatus.SEND_CONTINUE;

				} else {

					final Oid mechId = kva.getMech();
					final GSSName name = kva.getSrcName();

					if (!authorizeCaller(request, requestToken, name,
							clientSubject)) {
						return sendFailureMessage(response,
								"Failed to authorize the caller/client");
					}

					// As no valid session should exist anymore, simply create a
					// new one
					session = request.getSession(true);

					final Principal clientPrincipal = new KerberosPrincipal(
							name.canonicalize(GSS_KRB5_MECH_OID).toString());

					updateSessionAndHeader(request, session, clientPrincipal);

					session.setAttribute(MAGIC_SESSION_STATE_KEY,
							SessionState.ESTABLISHED);
					/*
					 * Store the mechId in the MessageInfo to indicate which
					 * authentication mechanism was used successfully (JASPIC
					 * Requirement)
					 */
					messageInfo.getMap().put(
							AUTH_TYPE_INFO_KEY,
							mechId != null ? mechId.toString()
									: "Undefined GSS Mechanism");

					debug("GSS Dialog is complete");

				}

			} catch (final GSSException gsse) {
				debug("GSS Dialog has failed : {0}", gsse);

				if (requestToken != null) {
					debug("Bad token detected {0}", gsse);
					debugToken("Bad token was {0}", requestToken);

					if (isNTLMToken(requestToken)) {
						// There is a high probability it was a NTLM SPNEGO
						// token
						return sendFailureMessage(response,
								"No support for NTLM");
					}
				}

				// for other errors throw an AuthException
				final AuthException ae = new AuthException();
				ae.initCause(gsse);
				throw ae;
			}

		} else if (this.mandatory) {

			response.setHeader(AUTHENTICATION_HEADER, NEGOTIATE);
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

			debug("Negotiate was added to the HTTP header : {0}", NEGOTIATE);

			return AuthStatus.SEND_CONTINUE;

		} else if (authorization != null) {
			LOG.warning("An authorization header was ignored.");
		}

		return AuthStatus.SUCCESS;
	}

	private void updateSessionAndHeader(HttpServletRequest request,
			HttpSession session, Principal principal) {

		if (principal != null) {
			final String[] principalParts = principal.getName().split("@");
			session.setAttribute(USERNAME_SESSION_KEY, principalParts[0]);
			session.setAttribute(REALM_SESSION_KEY, principalParts[1]);
			debug("Setting extra session users info name={0} realm={1}",
					principalParts[0], principalParts[1]);

			// TODO Implement userHeader on a generic way
			/*
			 * if(this.userHeader!=null && !"".equals(userHeader.trim())){
			 * request.adHeader(...) ? }
			 */
		}

		if (this.sessionAttributes != null) {
			for (final Map.Entry<String, String> entry : this.sessionAttributes
					.entrySet()) {
				session.setAttribute(entry.getKey(), entry.getValue());
			}
			debug("Setting extra session pairs : {0}", this.sessionAttributes);
		}

		debug("Session was update sessionId {0} for user {1}", session.getId(),
				principal);
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

		final HttpServletRequest request = (HttpServletRequest) messageInfo
				.getRequestMessage();
		final Principal clientPrincipal = request.getUserPrincipal();
		// There should be a session as validate request created one at the end
		final HttpSession session = request.getSession(false);

		// As the session might have changed in the middle (for security
		// reason),
		// we make sure the settings are saved. Plus if coming from
		// SessionState.ESTABLISHED
		// on an existing session, we might have still something to set for the
		// next Filters
		updateSessionAndHeader(request, session, clientPrincipal);

		debug("secureResponse was called and session was updated");

		return AuthStatus.SEND_SUCCESS;
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
	 *            are to be removed. throws AuthException If an error occurs
	 *            during the Subject processing.
	 */
	public void cleanSubject(MessageInfo messageInfo, Subject subject)
			throws AuthException {
		LOG.fine("cleanSubject called");
	}

	/**
	 * Sends a failure message in the response
	 * 
	 * @param response
	 * @param message
	 * @return
	 */
	protected AuthStatus sendFailureMessage(HttpServletResponse response,
			String message) {

		try {
			response.setStatus(HttpServletResponse.SC_FORBIDDEN);
			response.sendError(HttpServletResponse.SC_FORBIDDEN, message);
		} catch (final Throwable t) {
			// status code has been set, and proper AuthStatus will be returned
			LOG.log(Level.WARNING, "Fail to set FORBIDDEN status {0}", t);
		}
		return AuthStatus.SEND_FAILURE;
	}

	/**
	 * Create a Kerberos Subject for the Principal whose name is passed
	 * 
	 * @param name
	 *            the name to use
	 * @return a valid Subject
	 */
	private Subject createSubject(GSSName name) {
		// return com.sun.security.jgss.GSSUtil.createSubject(name, null); //
		// this was Sun JVM only ;-)

		final Set<KerberosPrincipal> krb5Principals = new HashSet<KerberosPrincipal>();

		try {
			// First create a canonical string representation of KRB5
			final String krb5name = name.canonicalize(GSS_KRB5_MECH_OID)
					.toString();

			// Then, create a Kerberos Principal from the canonical name
			final KerberosPrincipal krbPrinc = new KerberosPrincipal(krb5name);

			krb5Principals.add(krbPrinc);
		} catch (final GSSException e) {
			LOG.log(Level.SEVERE, "Unable to create the Kerberos context", e);
		}

		return new Subject(false, krb5Principals, new HashSet<Object>(),
				new HashSet<Object>());

	}

	private void debug(String message, Object... parameters) {
		if (this.debug || LOG.isLoggable(Level.FINE)) {
			LOG.log(this.debugLevel, message, parameters);
		}
	}

	private boolean authorizeCaller(HttpServletRequest request,
			byte[] serviceToken, GSSName name, final Subject clientSubject) {

		// create Subject with principals from name
		final Subject kerberosServiceSubject = createSubject(name);

		final Set<Principal> kerberosServicePrincipals = kerberosServiceSubject
				.getPrincipals();

		if (kerberosServicePrincipals.size() > 0) {
			final Set<Principal> clientPrincipals = clientSubject
					.getPrincipals();

			clientPrincipals.addAll(kerberosServicePrincipals);

			// Pickup the first Principal as the caller
			final Principal caller = kerberosServicePrincipals.iterator()
					.next();

			if (caller != null) {
				// Fetch the list of extra groups
				final Set<String> extraGroups = fetchExtraGroups(request,
						this.serviceSubject, this.options);

				// Let's add all the groups as valid Principal as part of the
				// clientSubject
				final String[] groups = buildGroupsFromPAC(serviceToken,
						this.serviceSubject, extraGroups);

				final List<String> groupList = Arrays.asList(groups);

				if (this.mandatoryGroups != null
						&& this.mandatoryGroups.size() > 0) {
					// There was some mandatory group to check
					if (!groupList.containsAll(this.mandatoryGroups)) {
						// None of the global constraint was found, so exiting
						debug("Not all the mandatory groups required ({1}) where found in the user groups {0} so failing the authentication.",
								groupList, this.mandatoryGroups);
						return false;
					}
				}

				// Check global constraints
				if (this.smartcardSecuredUsersOnly
						|| this.delegatedSecuredUsersOnly) {

					final List<String> contraintGroupList = new ArrayList<String>();
					if (this.smartcardSecuredUsersOnly) {
						contraintGroupList.add(GROUP_SMARTCARD_AUTHENTICATED);
					}
					if (this.delegatedSecuredUsersOnly) {
						contraintGroupList.add(GROUP_DELEGATED_AUTHENTICATED);
					}

					// Test if at least one of the constraints are matched
					if (Collections.disjoint(groupList, contraintGroupList)) {
						// None of the global constraint was found, so exiting
						debug("The global contrainted group {1} where not found in the user groups {0} so failing the authentication.",
								groupList, contraintGroupList);
						return false;
					}

				}

				final GroupPrincipalCallback groupPrincipalCallback = new GroupPrincipalCallback(
						clientSubject, groups);
				try {
					// notify caller for the groups
					this.handler
							.handle(new Callback[] { groupPrincipalCallback });
					debug("Groups found {0}", groupList);
				} catch (final IOException e) {
					LOG.log(Level.WARNING, "Unable to set the groups "
							+ groupList, e);
				} catch (final UnsupportedCallbackException e) {
					LOG.log(Level.WARNING, "Unable to set the groups "
							+ groupList, e);
				}
			}

			// Create the caller principal to pass to caller
			final CallerPrincipalCallback callerPrincipalCallback = new CallerPrincipalCallback(
					clientSubject, caller);

			try {
				// notify caller for the Principal
				this.handler.handle(new Callback[] { callerPrincipalCallback });
				debug("Caller principal is {0}", (Object) caller);
				return true;
			} catch (final IOException e) {
				LOG.log(Level.WARNING, "Unable to set caller principal {0}", e);
			} catch (final UnsupportedCallbackException e) {
				LOG.log(Level.WARNING, "Unable to set caller principal {0}", e);
			}
		}
		return false;
	}

	/**
	 * This method can easily be overridden to provide extra groups
	 * 
	 * @param request
	 *            the request
	 * @param serverSubject
	 *            the subject of the server containing the KerberosKey
	 * @param options
	 *            the options passed from the JASPIC context
	 * @return the mutable set of extra roles to add or null if an error happens
	 */
	public Set<String> fetchExtraGroups(HttpServletRequest request,
			Subject serverSubject, Map<String, ?> options) {
		final Set<String> groups = new HashSet<String>();
		// Check for request context groups
		// Test channel security
		if (request.isSecure()) {
			groups.add(GROUP_SECURED_CHANNEL);
			debug("The request context is secured so the {0} group was added to the user",
					GROUP_SECURED_CHANNEL);
		} else {
			groups.add(GROUP_UNSECURED_CHANNEL);
			debug("The request context is not secured so the {0} group was added to the user",
					GROUP_UNSECURED_CHANNEL);
		}
		return groups;
	}

	/*
	 * interface GroupFetcher { String[] fetchExtraGroups() }
	 */

	/**
	 * Test if the token is a NTLM Initial
	 * 
	 * @param bytes
	 * @return true if the token is an NTLM token
	 */
	private boolean isNTLMToken(byte[] bytes) {
		return new String(bytes).startsWith(NTLM_INITIAL_TOKEN);
	}

	/**
	 * Log some debug data about a token
	 * 
	 * @param message
	 *            the message to display
	 * @param token
	 *            the token to log
	 */
	private void debugToken(String message, byte[] token) {

		if (this.debug || LOG.isLoggable(Level.FINE)) {
			final StringBuffer sb = new StringBuffer();
			sb.append("\n");
			sb.append("Token ");
			sb.append(Base64.isBase64(token) ? "is" : "is Not");
			sb.append(" Base64 encoded\n");
			sb.append("bytes: ");
			boolean first = true;
			for (final byte b : token) {
				final int i = b;
				if (first) {
					sb.append(i);
					first = false;
				} else {
					sb.append(", ").append(i);
				}
			}
			LOG.log(this.debugLevel, message, sb);
		}
	}

	/**
	 * Log the request for debug purpose
	 * 
	 * @param request
	 *            the HTTP Servlet Request
	 */
	private void debugRequest(HttpServletRequest request) {

		if (this.debug || LOG.isLoggable(Level.FINE)) {
			final StringBuffer sb = new StringBuffer();
			sb.append("\n");
			try {
				sb.append("Request: ").append(request.getRequestURL())
						.append("\n");
				sb.append("UserPrincipal: ").append(request.getUserPrincipal())
						.append("\n");
				sb.append("AuthType: ").append(request.getAuthType())
						.append("\n");
				sb.append("Headers:\n");
				@SuppressWarnings("rawtypes")
				final Enumeration names = request.getHeaderNames();
				while (names.hasMoreElements()) {
					final String name = (String) names.nextElement();
					sb.append("\t").append(name).append("\t")
							.append(request.getHeader(name)).append("\n");
				}
				LOG.log(this.debugLevel, "HTTP Request is : {0}", sb);

			} catch (final Throwable t) {
				LOG.log(Level.WARNING,
						"An unexpected problem has occured during log : {0}", t);
			}
		}
	}

	private KerberosKey[] getSubjectKeys(Subject subject) {
		final List<KerberosKey> serverKeys = new ArrayList<KerberosKey>();

		final Set<Object> serverPrivateCredentials = subject
				.getPrivateCredentials();
		for (final Object credential : serverPrivateCredentials) {
			if (credential instanceof KerberosKey) {
				serverKeys.add((KerberosKey) credential);
			}
		}

		return serverKeys.toArray(new KerberosKey[0]);
	}

	/**
	 * Fetch the list of SID group from the PAC for a given Kerberos service
	 * token
	 * 
	 * @param serviceToken
	 *            the service token
	 * @param serverSubject
	 *            the subject of the server containing the KerberosKey
	 * @param groups
	 *            a set of extra groups, if null a new empty set will be created
	 *            as a basis
	 * @return the array of matching roles or null if an error happens
	 */
	private String[] buildGroupsFromPAC(byte[] serviceToken,
			Subject serverSubject, Set<String> groups) {
		final KerberosKey[] keys = getSubjectKeys(serverSubject);

		try {
			final SpnegoToken spnegoToken = SpnegoToken.parse(serviceToken);
			final String mechanism = spnegoToken.getMechanism();

			debug("Mechanism found {0}", mechanism);

			// Fetch all the SIDs and put it in a set
			final Set<String> sids = groups == null ? new HashSet<String>()
					: groups;

			if (SpnegoConstants.KERBEROS_MECHANISM.equals(mechanism)
					|| SpnegoConstants.LEGACY_KERBEROS_MECHANISM
							.equals(mechanism)) {

				final byte[] mechanismToken = spnegoToken.getMechanismToken();

				// Decoding Kerberos token
				final KerberosToken kerberosToken = new KerberosToken(
						mechanismToken, keys);
				final List<KerberosAuthData> userAuthorizations = kerberosToken
						.getTicket().getEncData().getUserAuthorizations();
				for (final KerberosAuthData kerberosAuthData : userAuthorizations) {
					if (kerberosAuthData instanceof KerberosPacAuthData) {
						final Pac pac = ((KerberosPacAuthData) kerberosAuthData)
								.getPac();
						final PacLogonInfo logonInfo = pac.getLogonInfo();

						if (logonInfo.getGroupSid() != null) {
							final PacSid sid = logonInfo.getGroupSid();
							sids.add(ADUtil.convertSID(sid.getBytes()));
							// sids.add( "SID_"+sid.toString());
						}

						for (final PacSid pacSid : logonInfo.getGroupSids()) {
							sids.add(ADUtil.convertSID(pacSid.getBytes()));
							// sids.add("SID_" + pacSid.toString());

						}

						for (final PacSid pacSid : logonInfo.getExtraSids()) {
							sids.add(ADUtil.convertSID(pacSid.getBytes()));
							// sids.add("SID_" + pacSid.toString());
						}

						for (final PacSid pacSid : logonInfo
								.getResourceGroupSids()) {
							sids.add(ADUtil.convertSID(pacSid.getBytes()));
							// sids.add("SID_" + pacSid.toString());
						}

						// Remove fake Smarcard Logon Role if existing
						if (sids.contains(GROUP_SMARTCARD_AUTHENTICATED)) {
							// Right, there is a role matching the
							sids.remove(GROUP_SMARTCARD_AUTHENTICATED);
							LOG.warning("Smartcard role was already assigned to a user, this could be a security issue. Meanwhile, the fake role was removed.");
						}

						// Let's check for smartcard logon
						debug("Testing MS-PAC for Smartcard Logon");
						if (pac.getCredentialType() != null) {
							// Add the synthetic group to indicate a smartcard
							// logon was secured
							sids.add(GROUP_SMARTCARD_AUTHENTICATED);
							debug("Smartcard logon was detected from the MS-PAC");
						}

						debug("Checking secure SIDs indicating MS-KILE Authentication Mechanism Assurance");
						if (this.secureGroups != null
								&& !Collections.disjoint(sids,
										this.secureGroups)) {
							// Add the synthetic group to indicate a smartcard
							// logon was secured
							sids.add(GROUP_SMARTCARD_AUTHENTICATED);
							debug("Smartcard logon was detected because of MS-KILE Authentication Mechanism Assurance");
						}

						debug("Checking KCD call scenario");
						if (pac.getDelegationInfos() != null
								&& pac.getDelegationInfos().size() > 0) {
							// There is some delegation info found, so let's add
							// the synthetic group to indicate KCD was detected
							sids.add(GROUP_DELEGATED_AUTHENTICATED);
							debug("Kerberos Constrainted Delegation call scenario was detected");
						}

						if (this.groupMapping != null
								&& this.groupMapping.size() > 0) {
							for (final String groupKey : this.groupMapping
									.stringPropertyNames()) {
								// provide some mapping
								// TODO provide a better mapping with N-N
								// support
								if (sids.contains(groupKey)) {
									final String groupValue = this.groupMapping
											.getProperty(groupKey);
									sids.add(groupValue);
								}
							}
						}

					}
				}
			}
			debug("Groups assigned from PAC : {0}", sids);

			// Return the group sids as an array
			final String[] idsArray = new String[sids.size()];
			return sids.toArray(idsArray);

		} catch (final Exception e) {
			// In any case it will just fail to prevent any groups from beeing
			// fetched
			debugToken(
					"Failed to fetch credential from PAC with service token {0}",
					serviceToken);
			LOG.log(Level.WARNING,
					"Unable to get the groups from the given PAC, will return null to the caller",
					e);
			return null;
		}

	}

	/**
	 * Krb5LoginConfig centralize the Kerberos configuration file.
	 */
	private static class Krb5LoginConfig extends Configuration {

		private static final Logger LOG = Logger
				.getLogger(Krb5LoginConfig.class.getName());
		private final String keyTabLocation;
		private final String servicePrincipalName;
		private final boolean debug;

		public Krb5LoginConfig(String keyTabLocation,
				String servicePrincipalName, boolean debug) {
			this.keyTabLocation = keyTabLocation;
			this.servicePrincipalName = servicePrincipalName;
			this.debug = debug;
		}

		static final String IBM_KRB_MODULE = "com.ibm.security.auth.module.Krb5LoginModule";
		static final String SUN_KRB_MODULE = "com.sun.security.auth.module.Krb5LoginModule";

		/**
		 * Return a valid Kerberos context matching the underlying JVM
		 * capability
		 * 
		 * @param name
		 *            the name of the configuration
		 * @return a valid JAAS configuration
		 */
		@Override
		public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
			if (isSunKerberosAvailable()) {
				LOG.info("Sun Kerberos provider selected");
				return getSunAppConfigurationEntry(name);
			} else if (isIbmKerberosAvailable()) {
				LOG.info("IBM Kerberos provider selected");
				return getIbmAppConfigurationEntry(name);
			} else {
				// should throw a better exception but done for compatibility
				// issues
				throw new UnsupportedOperationException(
						"Unable to find a matching KerberosLoginModule in the Java runtime");
			}
		}

		private AppConfigurationEntry[] getSunAppConfigurationEntry(String name) {
			final HashMap<String, String> options = new HashMap<String, String>();
			options.put("useKeyTab", "true");
			options.put("keyTab", this.keyTabLocation);
			options.put("principal", this.servicePrincipalName);
			options.put("storeKey", "true");
			options.put("doNotPrompt", "true");
			if (this.debug) {
				options.put("debug", "true");
			}
			options.put("isInitiator", "false");

			return new AppConfigurationEntry[] { new AppConfigurationEntry(
					SUN_KRB_MODULE,
					AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
					options), };
		}

		private boolean isSunKerberosAvailable() {
			try {
				Class.forName(SUN_KRB_MODULE);
				return true;
			} catch (final Exception e) {
				return false;
			}
		}

		private AppConfigurationEntry[] getIbmAppConfigurationEntry(String name) {
			final HashMap<String, String> options = new HashMap<String, String>();
			options.put("useKeytab", this.keyTabLocation);
			options.put("principal", this.servicePrincipalName);

			if (this.debug) {
				options.put("debug", "true");
			}
			options.put("credsType", "acceptor");

			return new AppConfigurationEntry[] { new AppConfigurationEntry(
					IBM_KRB_MODULE,
					AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
					options), };
		}

		private boolean isIbmKerberosAvailable() {
			try {
				Class.forName(IBM_KRB_MODULE);
				return true;
			} catch (final Exception e) {
				return false;
			}
		}
	}

	/**
	 * This class is used to validate the kerberos token
	 * 
	 */
	private static class KerberosValidateAction implements
			PrivilegedExceptionAction<byte[]> {

		private final byte[] kerberosTicket;
		private final Subject serviceSubject;
		private GSSContext context;
		private boolean established = false;
		private Oid mech = null;
		private GSSName srcName = null;
		private String servicePrincipal = null;

		public KerberosValidateAction(String servicePrincipal,
				byte[] kerberosTicket, Subject serviceSubject) {
			this.servicePrincipal = servicePrincipal;
			this.kerberosTicket = kerberosTicket;
			this.serviceSubject = serviceSubject;
		}

		// @Override
		public byte[] run() throws Exception {
			// Create the manager
			// Simple default GSSContext creation does not work with an IBM SDK
			// GSSManager.getInstance().createContext((GSSCredential) null)
			// hence, we need to shape the GSS context a bit more by hitting the
			// exact usage scenario : SPNEGO with Kerberos
			final GSSManager manager = GSSManager.getInstance();
			final Oid spnegoMechOid = new Oid("1.3.6.1.5.5.2");
			final Oid krb5MechOid = new Oid("1.2.840.113554.1.2.2");

			// Create the service name
			// BUGFIX :
			// createName("HTTP/host@DOMAIN",GSSName.NT_HOSTBASED_SERVICE,
			// krb5MechOid) might fail on IBM SDK so defaulting to null
			final GSSName serviceName = manager.createName(
					this.servicePrincipal, null, krb5MechOid);

			// Create a credential accepting SPNEGO + Kerberos
			// BUGFIX : DEFAULT_LIFETIME can not be used on IBM SDK see bug
			// http://www-304.ibm.com/support/docview.wss?uid=swg1IZ54545
			final GSSCredential serviceCredential = manager.createCredential(
					serviceName, GSSCredential.INDEFINITE_LIFETIME, new Oid[] {
							spnegoMechOid, krb5MechOid },
					GSSCredential.ACCEPT_ONLY);

			// Now create the GSS context
			this.context = manager.createContext(serviceCredential);

			try {
				// Check if the ticket is acceptable
				final byte[] result = this.context.acceptSecContext(
						this.kerberosTicket, 0, this.kerberosTicket.length);
				this.established = this.context.isEstablished();

				try {
					this.mech = this.context.getMech();
				} catch (final GSSException gsse) {
					this.mech = null; //
					LOG.log(Level.FINE,
							"Unable to get the mech from the GSSContext, defaulting to null",
							gsse);
				}

				this.srcName = this.context.getSrcName();

				/**
				 * @todo Try to use generic GSS instead, an attempt was done to extract here the encoded MS-PAC ticket, this
				 * currently fails, the code hint is : 
				 * <code>
				 * MessageProp prop = new MessageProp(0,false); byte[]
				 * unCipheredPac = context.unwrap(kerberosTicket, 0,
				 * kerberosTicket.length, prop);
				 * </code>
				 */
				return result;
			} finally {
				this.context.dispose();
			}
		}

		public GSSContext getContext() {
			return this.context;
		}

		public byte[] getKerberosTicket() {
			return this.kerberosTicket;
		}

		public boolean isEstablished() {
			return this.established;
		}

		public Oid getMech() {
			return this.mech;
		}

		public GSSName getSrcName() {
			return this.srcName;
		}
	}

}
