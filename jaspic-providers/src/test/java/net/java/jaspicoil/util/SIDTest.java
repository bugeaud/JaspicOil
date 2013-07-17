package net.java.jaspicoil.util;

import static org.junit.Assert.*;

import org.junit.Test;

/**
 * Some set of test around the SID value converting.
 * Test cases are build using :
 * SID extraction : dsquery * -filter "(sAMAccountName=theuser)" -attr objectSid
 * Hexa string extraction : dsquery * -filter "(sAMAccountName=theuser)" -attr objectSid;binary
 * 
 * @author bugeaud at gmail dot com
 * @see http://tools.ietf.org/html/draft-ietf-httpauth-basicauth-enc-01
 * @license CDDL1 http://www.opensource.org/licenses/cddl1.txt
 * @license LGPL http://www.gnu.org/copyleft/lesser.html
 * 
 */
public class SIDTest {

    /**
     * Test if an Administrator SID converts correctly
     */
    @Test
    public void testValidAdministratorValue() {
	assertEquals("S-1-5-32-544",
		ADUtil.convertSID(ADUtil.parseHexByteArray("0x01 0x02 0x00 0x00 0x00 0x00 0x00 0x05 0x20 0x00 0x00 0x00 0x20 0x02 0x00 0x00")));
    }

    /**
     * Test if a user SID converts correctly
     */
    @Test
    public void testValidUserValue() {
	assertEquals("S-1-5-21-1269433063-18164574-2503654879-500",
		ADUtil.convertSID(ADUtil.parseHexByteArray("0x01 0x05 0x00 0x00 0x00 0x00 0x00 0x05 0x15 0x00 0x00 0x00 0xe7 0x02 0xaa 0x4b 0x5e 0x2b 0x15 0x01 0xdf 0xbd 0x3a 0x95 0xf4 0x01 0x00 0x00")));
    }

    /**
     * Test a wrong user sid
     */
    @Test
    public void testInvalidValue() {
	assertNotSame("S-1-5-21-1269433063-18164574-2503654879-501",
		ADUtil.convertSID(ADUtil.parseHexByteArray("0x01 0x05 0x00 0x00 0x00 0x00 0x00 0x05 0x15 0x00 0x00 0x00 0xe7 0x02 0xaa 0x4b 0x5e 0x2b 0x15 0x01 0xdf 0xbd 0x3a 0x95 0xf4 0x01 0x00 0x00")));
    }
}
