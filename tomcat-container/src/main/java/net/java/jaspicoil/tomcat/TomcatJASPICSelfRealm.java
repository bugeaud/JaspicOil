package net.java.jaspicoil.tomcat;

import java.security.Principal;
import org.apache.catalina.realm.RealmBase;

/**
 * This is a self contained Realm.
 * All the data are fetched from the UserIdentity context.
 * This Realm only handle value for the current user. Thus, any other request will fail.
 * This should only be used for Tomcat JASPIC Valve
 * @author bugeaud at gmail dot com
 */
public class TomcatJASPICSelfRealm extends RealmBase{

    @Override
    protected String getName() {
        return TomcatIdentityContext.getCurrentIdentity().getPrincipal().getName();
    }

    @Override
    protected String getPassword(String string) {
        return null;
    }

    @Override
    protected Principal getPrincipal(String principalName) {
        final TomcatIdentityContext.UserIdentity identity = TomcatIdentityContext.getCurrentIdentity();
        if(identity.getPrincipal().getName().equals(principalName)){
            return identity.getPrincipal();
        }else{
            throw new UnsupportedOperationException("This is a self contained Realm, user "+principalName+
            		" is not matching the current identity :"+identity);
        }
    }
    
    @Override
    public boolean hasRole(Principal principal, String role) {
        final TomcatIdentityContext.UserIdentity identity = TomcatIdentityContext.getCurrentIdentity();
        if(identity.getPrincipal().equals(principal)){
            return identity.getGroups().contains(role);
        }else{
            throw new UnsupportedOperationException("This is a self contained Realm, request user principal "+principal+
            		" is not matching the current given identity : "+identity);      	
        }
    }
    
}
