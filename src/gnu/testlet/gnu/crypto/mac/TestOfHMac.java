package gnu.testlet.gnu.crypto.mac;

// ----------------------------------------------------------------------------
// $Id: TestOfHMac.java,v 1.3 2005/10/06 04:24:20 rsdio Exp $
//
// Copyright (C) 2003 Free Software Foundation, Inc.
//
// This file is part of GNU Crypto.
//
// GNU Crypto is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2, or (at your option)
// any later version.
//
// GNU Crypto is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; see the file COPYING.  If not, write to the
//
//    Free Software Foundation Inc.,
//    51 Franklin Street, Fifth Floor,
//    Boston, MA 02110-1301
//    USA
//
// Linking this library statically or dynamically with other modules is
// making a combined work based on this library.  Thus, the terms and
// conditions of the GNU General Public License cover the whole
// combination.
//
// As a special exception, the copyright holders of this library give
// you permission to link this library with independent modules to
// produce an executable, regardless of the license terms of these
// independent modules, and to copy and distribute the resulting
// executable under terms of your choice, provided that you also meet,
// for each linked independent module, the terms and conditions of the
// license of that module.  An independent module is a module which is
// not derived from or based on this library.  If you modify this
// library, you may extend this exception to your version of the
// library, but you are not obligated to do so.  If you do not wish to
// do so, delete this exception statement from your version.
// ----------------------------------------------------------------------------

// Tags: GNU-CRYPTO

import gnu.crypto.mac.HMacFactory;
import gnu.crypto.mac.IMac;
import gnu.testlet.TestHarness;
import gnu.testlet.Testlet;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Random;

/**
 * <p>Conformance Tests of common characteristics to all HMAC types in this
 * library; e.g. cloning</p>
 *
 * @version $Revision: 1.3 $
 */
public class TestOfHMac implements Testlet {

   // Constants and variables
   // -------------------------------------------------------------------------

   private static final Random prng = new Random(System.currentTimeMillis());
   private String mac;
   private IMac algorithm, clone;

   // Constructor(s)
   // -------------------------------------------------------------------------

   // default 0-arguments constructor

   // Class methods
   // -------------------------------------------------------------------------

   private static final byte[] makeKey(int length) {
      byte[] result = new byte[length];
      prng.nextBytes(result);
      return result;
   }

   // Instance methods
   // -------------------------------------------------------------------------

   public void test(TestHarness harness) {
      harness.checkPoint("TestOfHMac");
      HashMap attr = new HashMap();
      for (Iterator it = HMacFactory.getNames().iterator(); it.hasNext(); ) {
         algorithm = null;
         mac = (String) it.next();
         try {
            algorithm = HMacFactory.getInstance(mac);
            harness.check(algorithm != null, "getInstance("+String.valueOf(mac)+")");
         } catch (InternalError x) {
            harness.debug(x);
            harness.fail("TestOfHMac.getInstance("+String.valueOf(mac)+") - "+String.valueOf(x));
         }

         // cloneable
         attr.put(IMac.MAC_KEY_MATERIAL, makeKey(algorithm.macSize()));
         try {
            algorithm.init(attr);
            algorithm.update((byte) 'a');
            algorithm.update((byte) 'b');
            algorithm.update((byte) 'c');

            clone = (IMac) algorithm.clone();

            algorithm.update((byte) 'd'); clone.update((byte) 'd');
            algorithm.update((byte) 'e'); clone.update((byte) 'e');
            algorithm.update((byte) 'f'); clone.update((byte) 'f');

            byte[] md1 = algorithm.digest();
            byte[] md2 = clone.digest();

            harness.check(Arrays.equals(md1, md2), "clone("+algorithm.name()+")");
         } catch (Exception x) {
            harness.debug(x);
            harness.fail("TestOfHMac.clone("+algorithm.name()+") - "+String.valueOf(x));
         }

         // reusable
         try {
            algorithm.init(attr);
            algorithm.update((byte) 'a');
            algorithm.update((byte) 'b');
            algorithm.update((byte) 'c');
            byte[] md1 = algorithm.digest();

            algorithm.reset();
            algorithm.update((byte) 'a');
            algorithm.update((byte) 'b');
            algorithm.update((byte) 'c');
            byte[] md2 = algorithm.digest();

            harness.check(Arrays.equals(md1, md2), "reset("+algorithm.name()+")");
         } catch (Exception x) {
            harness.debug(x);
            harness.fail("TestOfHMac.reset("+algorithm.name()+") - "+String.valueOf(x));
         }
      }
   }
}
