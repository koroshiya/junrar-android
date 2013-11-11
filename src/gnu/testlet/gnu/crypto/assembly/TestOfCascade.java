package gnu.testlet.gnu.crypto.assembly;

// ----------------------------------------------------------------------------
// $Id: TestOfCascade.java,v 1.5 2005/10/06 04:24:19 rsdio Exp $
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

import gnu.crypto.Registry;
import gnu.crypto.assembly.Cascade;
import gnu.crypto.assembly.Direction;
import gnu.crypto.assembly.Stage;
import gnu.crypto.cipher.IBlockCipher;
import gnu.crypto.cipher.DES;
import gnu.crypto.cipher.TripleDES;
import gnu.crypto.mode.ModeFactory;
import gnu.crypto.util.Util;
import gnu.testlet.Testlet;
import gnu.testlet.TestHarness;

import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.HashMap;

/**
 * <p>Simple test of {@link Cascade} that simulates a DES-EDE constructed from
 * three separate DES instances.</p>
 *
 * @version $Revision: 1.5 $
 */
public class TestOfCascade implements Testlet {

   // Constants and variables
   // -------------------------------------------------------------------------

   /** The ECB encryption monte-carlo tests. */
   static final String[][] E_TV = {
      // key bytes                                               plain bytes        cipher bytes
      {"0123456789abcdef","0123456789abcdef","0123456789abcdef","4e6f772069732074","6a2a19f41eca854b"},
      {"0123456789abcdef","23456789abcdef01","0123456789abcdef","4e6f772069732074","03e69f5bfa58eb42"},
      {"0123456789abcdef","23456789abcdef01","456789abcdef0123","4e6f772069732074","dd17e8b8b437d232"},
      {"6b085d92976149a4","6b085d92976149a4","6b085d92976149a4","6a2a19f41eca854b","ce5d6c7b63177c18"},
      {"02c4da3d73f226ad","1cbce0f2bacd3b15","02c4da3d73f226ad","03e69f5bfa58eb42","262a60f9743e1fd8"},
      {"dc34addf3d9d1fdc","976d456702cef4fd","ad49c2ba0b2f975b","dd17e8b8b437d232","3145bcfc1c19382f"}
   };

   /** The ECB decryption monte-carlo tests. */
   static final String[][] D_TV = {
      {"0123456789abcdef","0123456789abcdef","0123456789abcdef","4e6f772069732074","cdd64f2f9427c15d"},
      {"0123456789abcdef","23456789abcdef01","0123456789abcdef","4e6f772069732074","6996c8fa47a2abeb"},
      {"0123456789abcdef","23456789abcdef01","456789abcdef0123","4e6f772069732074","8325397644091a0a"},
      {"cdf40b491c8c0db3","cdf40b491c8c0db3","cdf40b491c8c0db3","cdd64f2f9427c15d","5bb675e3db3a7f3b"},
      {"68b58c9dce086704","529dce3719e9e0da","68b58c9dce086704","6996c8fa47a2abeb","6b177e016e6ae12d"},
      {"83077c10cda2d6e5","296240fd8c834fcd","8fdac4fbe5ae978f","8325397644091a0a","c67901abdc008c89"}
   };

   // Constructor(s)
   // -------------------------------------------------------------------------

   // default 0-arguments constructor

   // Class methods
   // -------------------------------------------------------------------------

   // Instance methods
   // -------------------------------------------------------------------------

   public void test(TestHarness harness) {
      harness.checkPoint("TestOfCascade");

      byte[] pt, ct;
      byte[] ct1 = new byte[8];
      byte[] ct2 = new byte[8];

      HashMap map = new HashMap();
      IBlockCipher desEDE = new TripleDES();

      HashMap map1 = new HashMap();
      HashMap map2 = new HashMap();
      HashMap map3 = new HashMap();
      Cascade new3DES = new Cascade();
      Object des1 = new3DES.append(
            Stage.getInstance(
                  ModeFactory.getInstance(Registry.ECB_MODE, new DES(), 8),
                  Direction.FORWARD));
      Object des2 = new3DES.append(
            Stage.getInstance(
                  ModeFactory.getInstance(Registry.ECB_MODE, new DES(), 8),
                  Direction.REVERSED));
      Object des3 = new3DES.append(
            Stage.getInstance(
                  ModeFactory.getInstance(Registry.ECB_MODE, new DES(), 8),
                  Direction.FORWARD));

      map.put(des1, map1);
      map.put(des2, map2);
      map.put(des3, map3);

      for (int i = 0; i < E_TV.length; i++) {
         map1.put(IBlockCipher.KEY_MATERIAL, Util.toBytesFromString(E_TV[i][0]));
         map2.put(IBlockCipher.KEY_MATERIAL, Util.toBytesFromString(E_TV[i][1]));
         map3.put(IBlockCipher.KEY_MATERIAL, Util.toBytesFromString(E_TV[i][2]));
         map.put(IBlockCipher.KEY_MATERIAL,
               Util.toBytesFromString(E_TV[i][0] + E_TV[i][1] + E_TV[i][2]));
         map.put(Cascade.DIRECTION, Direction.FORWARD);
         pt = Util.toBytesFromString(E_TV[i][3]);
         ct = Util.toBytesFromString(E_TV[i][4]);

         try {
            desEDE.reset();
            new3DES.reset();

            desEDE.init(map);
            new3DES.init(map);

            desEDE.encryptBlock(pt, 0, ct1, 0);
            new3DES.update(pt, 0, ct2, 0);
            harness.check(Arrays.equals(ct1, ct2));

            for (int j = 0; j < 9999; j++) {
               desEDE.encryptBlock(ct1, 0, ct1, 0);
               new3DES.update(ct2, 0, ct2, 0);
            }
            harness.check(Arrays.equals(ct, ct1));
            harness.check(Arrays.equals(ct, ct2));
         } catch (InvalidKeyException x) {
            harness.fail("init (encryption)");
            harness.debug(x);
         }
      }

      for (int i = 0; i < D_TV.length; i++) {
         map1.put(IBlockCipher.KEY_MATERIAL, Util.toBytesFromString(D_TV[i][0]));
         map2.put(IBlockCipher.KEY_MATERIAL, Util.toBytesFromString(D_TV[i][1]));
         map3.put(IBlockCipher.KEY_MATERIAL, Util.toBytesFromString(D_TV[i][2]));
         map.put(IBlockCipher.KEY_MATERIAL,
               Util.toBytesFromString(D_TV[i][0] + D_TV[i][1] + D_TV[i][2]));
         map.put(Cascade.DIRECTION, Direction.REVERSED);
         pt = Util.toBytesFromString(D_TV[i][3]);
         ct = Util.toBytesFromString(D_TV[i][4]);

         try {
            desEDE.reset();
            new3DES.reset();

            desEDE.init(map);
            new3DES.init(map);

            desEDE.decryptBlock(pt, 0, ct1, 0);
            new3DES.update(pt, 0, ct2, 0);
            harness.check(Arrays.equals(ct1, ct2));

            for (int j = 0; j < 9999; j++) {
               desEDE.decryptBlock(ct1, 0, ct1, 0);
               new3DES.update(ct2, 0, ct2, 0);
            }
            harness.check(Arrays.equals(ct, ct1));
            harness.check(Arrays.equals(ct, ct2));
         } catch (InvalidKeyException x) {
            harness.fail("init (decryption)");
            harness.debug(x);
         }
      }
   }
}
