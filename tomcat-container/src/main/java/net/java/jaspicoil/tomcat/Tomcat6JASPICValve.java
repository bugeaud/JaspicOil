package net.java.jaspicoil.tomcat;

import java.io.IOException;
import java.io.StringReader;
import java.security.AccessController;
import java.security.Principal;
import java.util.Map;
import java.util.Properties;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.authenticator.AuthenticatorBase;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.deploy.LoginConfig;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

/**
 * Implements JSR-196 Container as a Tomcat Valve.
 * Warning : at this time JASPIC spec is only implemented as a facade of JaspicOil providers
 *
 * @author bugeaud at gmail dot com
 */
public class Tomcat6JASPICValve extends AuthenticatorBase {

    public static final String AUTH_TYPE = "JASPICSPNEGO";
    
    private ServerAuthModule authModule = null;
    private String providerClassName;
    private String providerParameters;
    private String userHeader;
    
    @Override
    protected boolean authenticate(Request request, Response response, LoginConfig lc) throws IOException {
	// Simply exit
	if (authModule == null) {
	    return false;
	}

	try {
	    // Create a messageInfo adapter
	    final AdapterMessageInfo messageInfo = new AdapterMessageInfo(request.getRequest(), response.getResponse(), createConfigFromProviderParameters());
	    
	    // create a new empty Subject
	    final Subject clientSubject = new Subject();

	    // Get the current Subject for the service
	    final Subject serviceSubject = Subject.getSubject(AccessController.getContext());
	    
	    // Call the SAM validate request
	    final AuthStatus requestStatus = authModule.validateRequest(messageInfo, clientSubject, serviceSubject);

	    if (AuthStatus.SUCCESS.equals(requestStatus)) {
		// If it is successfull then propagate to tomcat
		final Principal userPrincipal = TomcatIdentityContext.getCurrentIdentity().getPrincipal();
		TomcatIdentityContext.UserIdentity userIdentity = TomcatIdentityContext.getCurrentIdentity(true);
		
		// Register the tomcat context
		register(request, response, userIdentity.findMainPrincipal(), AUTH_TYPE, userIdentity.getName(), new String(userIdentity.getPassword()));
		
		// Save the identity to the session for later container use
		TomcatIdentityContext.save(request.getSessionInternal(false));
		
		// Then try to encode some extra parameters
		final AuthStatus responseStatus = authModule.secureResponse(messageInfo, serviceSubject);
		if (AuthStatus.SEND_SUCCESS.equals(responseStatus)) {
		    // We try to set some header to represent the user
		    final String userKey = getUserHeader();
		    if (userKey != null && !"".equals(userKey.trim())) {
			// Replace existing or add a new header for the user
			request.getCoyoteRequest().getMimeHeaders().setValue(userKey).setString(getshortUserName(userPrincipal));
		    }
		    return true;
		}
	    } else if (AuthStatus.SEND_CONTINUE.equals(requestStatus)) {
		response.sendError(Response.SC_UNAUTHORIZED);
		return false;
	    }
	    //TODO We should handle CONTINUE to support SPNEGO in a better way.
	} catch (Exception e) {
	    response.sendError(Response.SC_FORBIDDEN);
	    log.warn("Unable to authenticate", e);

	}
	// By default, authenticate will fail
	return false;
    }
    private static Log log = LogFactory.getLog(AuthenticatorBase.class);

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {
	try {
	    TomcatIdentityContext.init(request.getSessionInternal(false));
	    super.invoke(request, response);
	} finally {
	    //
	    //We clear the user identity at the end
	    TomcatIdentityContext.clearCurrentIdentity();
	}

    }

    private Map<String, String> createConfigFromProviderParameters() {
	final String parameters = getProviderParameters();
	final Properties properties = new Properties();
	try {
	    properties.load(new StringReader(parameters));
	} catch (IOException ex) {
	    log.error("Unable to load the provider parameters from the valve attribute", ex);
	}
	return (Map) properties;
    }
    
    private ServerAuthModule createServerAuthModule() throws LifecycleException{
	final String providerName = getProviderClassName();
	try {
	    return ServerAuthModule.class.cast(Class.forName(providerName).newInstance());
	} catch (Exception ex) {
	    // Failing the valve life cycle
	    throw new LifecycleException(String.format("Unable to instantiate the AuthModule %s given as valve attribute",providerName),ex);
	}
    }
    
    private String getshortUserName(Principal user){
	if(user==null) return null;
	final String userName = user.getName();
	final String[] parts = userName.split("@");
	return parts.length >= 0 ? parts[0] : userName;
    }

    public void start() throws LifecycleException {

	// Create a AuthModule according to the parameters given
	authModule = createServerAuthModule();

	// At this time input and output are mandatory but policies are empty array
	MessagePolicy inputPolicy = new MessagePolicy(new MessagePolicy.TargetPolicy[]{}, true);
	MessagePolicy outputPolicy = new MessagePolicy(new MessagePolicy.TargetPolicy[]{}, true);

	final CallbackHandler handlerAdapter = new CallbackHandler() {

	    public void handle(Callback[] callbacks) throws java.io.IOException, UnsupportedCallbackException {
		if (callbacks == null) {
		    return;
		}
		for (Callback callback : callbacks) {
		    TomcatIdentityContext.updateIdentity(callback);
		    /*
		     TODO Improve the callback support

		     // must
		     CallerPrincipalCallback : done
		     GroupPrincipalCallback : done
		     PasswordValidationCallback : done

		     // should
		     CertStoreCallback
		     PrivateKeyCallback
		     SecretKeyCallback
		     TrustStoreCallback
		     */
		}
	    }
	};
	try {
	    // Initialize the auth module
	    authModule.initialize(inputPolicy, outputPolicy, handlerAdapter, createConfigFromProviderParameters());
	} catch (AuthException ex) {
	    log.error(null, ex);
	    throw new LifecycleException("Authentification exception during AuthModule call to initialize()", ex);
	}

    }

    public void stop() throws LifecycleException {
	authModule = null;
    }


    /**
     * @return the authModule
     */
    public ServerAuthModule getAuthModule() {
	return authModule;
    }

    /**
     * @param authModule the authModule to set
     */
    public void setAuthModule(ServerAuthModule authModule) {
	this.authModule = authModule;
    }

    public String getUserHeader() {
	return userHeader;
    }

    public void setUserHeader(String userHeader) {
	this.userHeader = userHeader;
    }

    /**
     * @return the providerClassName
     */
    public String getProviderClassName() {
	return providerClassName;
    }

    /**
     * @param providerClassName the providerClassName to set
     */
    public void setProviderClassName(String providerClassName) {
	this.providerClassName = providerClassName;
    }

    /**
     * @return the providerParameters
     */
    public String getProviderParameters() {
	return providerParameters;
    }

    /**
     * @param providerParameters the providerParameters to set
     */
    public void setProviderParameters(String providerParameters) {
	this.providerParameters = providerParameters;
    }

    /**
     * JASPIC MessageInfo adapter
     */
    @SuppressWarnings("rawtypes")
    public static class AdapterMessageInfo implements MessageInfo {

	private HttpServletRequest request;
	private HttpServletResponse response;
	private Map attributes;

	public AdapterMessageInfo(HttpServletRequest request, HttpServletResponse response, Map attributes) {
	    this.request = request;
	    this.response = response;
	    this.attributes = attributes;
	}

	public Map getMap() {
	    return attributes;
	}

	public Object getRequestMessage() {
	    return request;
	}

	public Object getResponseMessage() {
	    return response;
	}

	public void setRequestMessage(Object arg0) {
	    throw new UnsupportedOperationException("Setting the request message is not supported");

	}

	public void setResponseMessage(Object arg0) {
	    throw new UnsupportedOperationException("Setting the response message is not supported");
	}
    }

}
