package net.java.jaspicoil.tomcat;

import java.io.Serializable;
import java.security.Principal;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.message.callback.CallerPrincipalCallback;
import javax.security.auth.message.callback.GroupPrincipalCallback;
import javax.security.auth.message.callback.PasswordValidationCallback;
import org.apache.catalina.Session;

/**
 * Manage an identity context
 * @author bugeaud at gmail dot com
 */
public class TomcatIdentityContext {

    private static final ThreadLocal<UserIdentity> selfIdentity = new ThreadLocal<UserIdentity>();

    /**
     * Get the current identity from Tomcat JASPIC context
     * @param create if true, when no existing Identity is found, create a blank/new one
     * @return the current identity
     */
    public static UserIdentity getCurrentIdentity(boolean create){
    	synchronized(selfIdentity){
            final UserIdentity self = selfIdentity.get();
            if(self==null && create){
                selfIdentity.set(new UserIdentity());
            }
            return self;    		
    	}
    }
    
    /**
     * Get the current from Tomcat JASPIC context
     * @return null if no identity exists
     */
    public static final UserIdentity getCurrentIdentity(){
        return getCurrentIdentity(false);
    }
    
    /**
     * Clear the current from Tomcat JASPIC context
     */
    public static void clearCurrentIdentity(){
    	synchronized(selfIdentity){
    		selfIdentity.set(null);
    	}
    }

    private static final String USER_IDENTITY_NOTE_KEY = "net.java.spnego.jaspic.cache";
    
    /**
     * Initialise the current identity from the session
     * @param session the HTTP session to use
     * @return the current Identity
     */
    public static UserIdentity init(Session session){
    	// When no session was set no init can be performed
        if(session==null) {
        	// There is no session so simply init the current identity
        	return getCurrentIdentity(true);
        }
    	synchronized(selfIdentity){
	        //If no identity is existing for this thread, then try to load it from the session
	        if(selfIdentity.get()==null){
	            final UserIdentity userIdentity = (UserIdentity)session.getNote(USER_IDENTITY_NOTE_KEY);
	            if(userIdentity!=null){
	            	// The saved identity is the new current
	                selfIdentity.set(userIdentity);
	                return userIdentity;
	            }
	        }
    	}
        // In any other cases simply return a new identity as current one
        return getCurrentIdentity(true);
    }
    
    /**
     * Save the current Identity to the HTTP Session
     * @param session the HTTP session to save
     */
    public static void save(Session session){
        session.setNote(USER_IDENTITY_NOTE_KEY, selfIdentity.get());
    }

    /**
     * Create a self contained UserIdentity that also holds the groups
     */
    public static class UserIdentity implements Serializable{
    	
		private static final long serialVersionUID = 1L;
		
		private Principal principal;
        private Subject subject;
        private String name;
        private List<String> groups;
	private char[] password;

        @Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result
					+ ((groups == null) ? 0 : groups.hashCode());
			result = prime * result + ((name == null) ? 0 : name.hashCode());
			result = prime * result
					+ ((principal == null) ? 0 : principal.hashCode());
			result = prime * result
					+ ((subject == null) ? 0 : subject.hashCode());
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (getClass() != obj.getClass())
				return false;
			UserIdentity other = (UserIdentity) obj;
			if (groups == null) {
				if (other.groups != null)
					return false;
			} else if (!groups.equals(other.groups))
				return false;
			if (name == null) {
				if (other.name != null)
					return false;
			} else if (!name.equals(other.name))
				return false;
			if (principal == null) {
				if (other.principal != null)
					return false;
			} else if (!principal.equals(other.principal))
				return false;
			if (subject == null) {
				if (other.subject != null)
					return false;
			} else if (!subject.equals(other.subject))
				return false;
			return true;
		}

		/**
         * @return the principal
         */
        public Principal getPrincipal() {
            return principal;
        }

        /**
         * @param principal the principal to set
         */
        public void setPrincipal(Principal principal) {
            this.principal = principal;
        }

	/**
	 * Find the main Principal from the UserIdentity.
	 * @return a valid Principal or null
	 */
	public Principal findMainPrincipal(){
	    final Principal p = getPrincipal();
	    if(p !=null) return p;
	    final Subject s = getSubject();
	    if(s==null) return null;
	    final Set<Principal> principals = s.getPrincipals();
	    // At this time only get the first fetched Prinicpal as the Main one
	    // TODO Improve detection based on AS specific heuristics (for instance DistinguishedPrincipal on GF, etc)
	    if(principals == null) return null;
	    return principals.isEmpty() ? null : principals.iterator().next(); 
	}
	
        /**
         * @return the subject
         */
        public Subject getSubject() {
            return subject;
        }

        /**
         * @param subject the subject to set
         */
        public void setSubject(Subject subject) {
            this.subject = subject;
        }

        /**
         * @return the name
         */
        public String getName() {
            return name;
        }

        /**
         * @param name the name to set
         */
        public void setName(String name) {
            this.name = name;
        }

        /**
         * @return the groups
         */
        public List<String> getGroups() {
            return groups;
        }

        /**
         * @param groups the groups to set
         */
        public void setGroups(List<String> groups) {
            this.groups = groups;
        }

	/**
	 * @return the password
	 */
	public char[] getPassword() {
	    return password;
	}

	/**
	 * @param password the password to set
	 */
	public void setPassword(char[] password) {
	    this.password = password;
	}
    }
    
    
    public static void updateIdentity(GroupPrincipalCallback callback){
        final UserIdentity self = getCurrentIdentity();
	self.setGroups(Collections.unmodifiableList(Arrays.asList(callback.getGroups())));
        self.setSubject(callback.getSubject());
    }

    public static void updateIdentity(CallerPrincipalCallback callback){
	final UserIdentity self = getCurrentIdentity();
	self.setName(callback.getName());
	self.setPrincipal(callback.getPrincipal());
	self.setSubject(callback.getSubject());
    }
    public static void updateIdentity(PasswordValidationCallback callback){
	final UserIdentity self = getCurrentIdentity();
	self.setName(callback.getUsername());
	self.setPassword(callback.getPassword());
    }
    
    public static void updateIdentity(Callback callback){
	throw new UnsupportedOperationException(new UnsupportedCallbackException(callback,"Not implemented yet"));
    }
    
}