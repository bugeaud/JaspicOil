package net.java.jaspicoil.util;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.Principal;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * This utility class contains various usefull code to handle AD specific things
 * 
 * @author bugeaud at gmail dot com
 */
public class ADUtil {

	protected static final Logger LOG = Logger
			.getLogger(ADUtil.class.getName());

	/**
	 * Convert a byte array representing a AD SID to its string representation
	 * as per the specification from MS see
	 * http://msdn.microsoft.com/en-us/library/cc230371(PROT.10).aspx
	 * 
	 * @param SID
	 *            the array of bytes
	 * @return the string representation
	 */
	public static String convertSID(byte[] SID) {
		// Add the 'S' prefix
		final StringBuilder strSID = new StringBuilder("S-");

		// bytes[0] : in the array is the version (must be 1 but might
		// change in the future)
		strSID.append(SID[0]).append('-');

		// bytes[2..7] : the Authority
		final StringBuilder tmpBuff = new StringBuilder();
		for (int t = 2; t <= 7; t++) {
			final String hexString = Integer.toHexString(SID[t] & 0xFF);
			tmpBuff.append(hexString);
		}
		strSID.append(Long.parseLong(tmpBuff.toString(), 16));

		// bytes[1] : the sub authorities count
		final int count = SID[1];

		// bytes[8..end] : the sub authorities (these are Integers - notice
		// the endian)
		for (int i = 0; i < count; i++) {
			final int currSubAuthOffset = i * 4;
			tmpBuff.setLength(0);
			tmpBuff.append(String.format("%02X%02X%02X%02X",
					SID[11 + currSubAuthOffset] & 0xFF,
					SID[10 + currSubAuthOffset] & 0xFF,
					SID[9 + currSubAuthOffset] & 0xFF,
					SID[8 + currSubAuthOffset] & 0xFF));

			strSID.append('-').append(Long.parseLong(tmpBuff.toString(), 16));
		}

		// That's it - we have the SID
		return strSID.toString();
	}

	/**
	 * Parse a AD binary value from the dsquery to a byte array. The format is a
	 * list of byte in base 64 with each octet starting with "0x" and a
	 * separated with spaces
	 * 
	 * @param array
	 *            the representation in string
	 * @return the byte array represented
	 */
	public static byte[] parseHexByteArray(String array) {
		final String[] v = array.split(" ");
		final byte[] arr = new byte[v.length];
		for (int i = 0; i < v.length; i++) {
			arr[i] = Integer.decode(v[i]).byteValue();
		}
		return arr;
	}

	/**
	 * This is a utility method that can be used to create a Principal within
	 * GlassFish. This
	 * 
	 * @param underlyingPrincipal
	 * @return a new Principal
	 */
	public Object createGlassfishDistinguishedPrincipal(
			Principal underlyingPrincipal) {

		Class<?> principalClass;
		try {
			principalClass = Class
					.forName("com.sun.enterprise.security.auth.login.DistinguishedPrincipalCredential");
			final Constructor<?> c = principalClass
					.getConstructor(Principal.class);
			return c.newInstance(underlyingPrincipal);
		} catch (final ClassNotFoundException e) {
			LOG.log(Level.SEVERE,
					"Glassfish DistinguishedPrincipalCredential not found", e);
			return null;
		} catch (final NoSuchMethodException e) {
			LOG.log(Level.SEVERE,
					"Constructor not found on Glassfish DistinguishedPrincipalCredential",
					e);
			return null;
		} catch (final InvocationTargetException e) {
			LOG.log(Level.SEVERE,
					"Unable to construct Glassfish DistinguishedPrincipalCredential",
					e);
			return null;
		} catch (final IllegalAccessException e) {
			LOG.log(Level.SEVERE,
					"Unable to access Glassfish DistinguishedPrincipalCredential",
					e);
			return null;
		} catch (final InstantiationException e) {
			LOG.log(Level.SEVERE,
					"Unable to instanciate Glassfish DistinguishedPrincipalCredential",
					e);
			return null;
		}

	}

}
