package gnu.testlet.gnu.crypto.prng;

// ----------------------------------------------------------------------------
// $Id: TestOfARCFour.java,v 1.3 2005/10/06 04:24:20 rsdio Exp $
//
// Copyright (C) 2002, 2003 Free Software Foundation, Inc.
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
import gnu.crypto.prng.ARCFour;
import gnu.crypto.prng.IRandom;
import gnu.crypto.prng.PRNGFactory;
import gnu.crypto.util.Util;
import gnu.testlet.TestHarness;
import gnu.testlet.Testlet;

import java.util.Arrays;
import java.util.HashMap;

/**
 * <p>Conformance tests for the ARCFOUR keystream generator.</p>
 *
 * @version $Revision: 1.3 $
 */
public class TestOfARCFour implements Testlet {

   // Constants and variables.
   // -----------------------------------------------------------------------

   private byte[] pt, kb, ct;
   private HashMap attrib = new HashMap();
   private IRandom keystream;

   // Constructors.
   // -----------------------------------------------------------------------

   // default 0-arguments constructor

   // Class methods.
   // -----------------------------------------------------------------------

   // Instance methods.
   // -----------------------------------------------------------------------

   // Test vectors are from "draft-kaukonen-cipher-arcfour-03.txt", which is
   // about as official as anything associated with ARCFOUR gets.

   public void test(TestHarness harness) {
      harness.checkPoint("TestOfARCFour.testVectorOne");
      //  PLAIN=0000000000000000
      //    KEY=0123456789ABCDEF
      // CIPHER=7494C2E7104B0879
      try {
         attrib.clear();
         keystream = PRNGFactory.getInstance(Registry.ARCFOUR_PRNG);

         pt = new byte[8];
         kb = Util.toBytesFromString("0123456789ABCDEF");
         ct = Util.toBytesFromString("7494C2E7104B0879");
         attrib.put(ARCFour.ARCFOUR_KEY_MATERIAL, kb);

         keystream.init(attrib);

         byte[] sb = new byte[8];
         keystream.nextBytes(sb, 0, 8);
         harness.check(Arrays.equals(ct, sb));
      } catch (Exception e) {
         harness.debug(e);
         harness.fail("TestOfARCFour.testVectorOne");
      }

      harness.checkPoint("TestOfARCFour.testVectorTwo");
      //  PLAIN=DCEE4CF92C
      //    KEY=618A63D2FB
      // CIPHER=F13829C9DE
      try {
         attrib.clear();
         keystream = PRNGFactory.getInstance(Registry.ARCFOUR_PRNG);

         pt = Util.toBytesFromString("DCEE4CF92C");
         kb = Util.toBytesFromString("618A63D2FB");
         ct = Util.toBytesFromString("F13829C9DE");
         attrib.put(ARCFour.ARCFOUR_KEY_MATERIAL, kb);

         keystream.init(attrib);

         byte[] cct = new byte[pt.length];
         for (int i = 0; i < pt.length; i++) {
            cct[i] = (byte) (pt[i] ^ keystream.nextByte());
         }
         harness.check(Arrays.equals(cct, ct));
      } catch (Exception e) {
         harness.debug(e);
         harness.fail("TestOfARCFour.testVectorTwo");
      }

      harness.checkPoint("TestOfARCFour.testVectorThree");
      //  PLAIN=527569736C696E6E756E206C61756C75206B6F7276697373
      //        73616E692C2074E4686BE470E46964656E2070E4E46C6CE4
      //        2074E47973696B75752E204B6573E479F66E206F6E206F6E
      //        6E69206F6D616E616E692C206B61736B6973617675756E20
      //        6C61616B736F7420766572686F75752E20456E206D612069
      //        6C6F697473652C20737572652068756F6B61612C206D7574
      //        7461206D657473E46E2074756D6D757573206D756C6C6520
      //        74756F6B61612E205075756E746F2070696C76656E2C206D
      //        692068756B6B75752C207369696E746F20766172616E2074
      //        75756C6973656E2C206D69206E756B6B75752E2054756F6B
      //        7375742076616E616D6F6E206A61207661726A6F74207665
      //        656E2C206E69697374E420737964E46D656E69206C61756C
      //        756E207465656E2E202D2045696E6F204C65696E6F
      //    KEY=29041972FB42BA5FC7127712F13829C9
      // CIPHER=358186999001E6B5DAF05ECEEB7EEE21E0689C1F00EEA81F
      //        7DD2CAAEE1D2763E68AF0EAD33D66C268BC946C484FBE94C
      //        5F5E0B86A59279E4F824E7A640BD223210B0A61160B7BCE9
      //        86EA65688003596B630A6B90F8E0CAF6912A98EB872176E8
      //        3C202CAA64166D2CCE57FF1BCA57B213F0ED1AA72FB8EA52
      //        B0BE01CD1E412867720B326EB389D011BD70D8AF035FB0D8
      //        589DBCE3C666F5EA8D4C7954C50C3F340B0467F81B425961
      //        C11843074DF620F208404B394CF9D37FF54B5F1AD8F6EA7D
      //        A3C561DFA7281F964463D2CC35A4D1B03490DEC51B0711FB
      //        D6F55F79234D5B7C766622A66DE92BE996461D5E4DC878EF
      //        9BCA030521E8351E4BAED2FD04F9467368C4AD6AC186D082
      //        45B263A2666D1F6C5420F1599DFD9F438921C2F5A463938C
      //        E0982265EEF70179BC553F339EB1A4C1AF5F6A547F
      try {
         attrib.clear();
         keystream = PRNGFactory.getInstance(Registry.ARCFOUR_PRNG);

         pt = Util.toBytesFromString(
            "527569736C696E6E756E206C61756C75206B6F7276697373"+
            "73616E692C2074E4686BE470E46964656E2070E4E46C6CE4"+
            "2074E47973696B75752E204B6573E479F66E206F6E206F6E"+
            "6E69206F6D616E616E692C206B61736B6973617675756E20"+
            "6C61616B736F7420766572686F75752E20456E206D612069"+
            "6C6F697473652C20737572652068756F6B61612C206D7574"+
            "7461206D657473E46E2074756D6D757573206D756C6C6520"+
            "74756F6B61612E205075756E746F2070696C76656E2C206D"+
            "692068756B6B75752C207369696E746F20766172616E2074"+
            "75756C6973656E2C206D69206E756B6B75752E2054756F6B"+
            "7375742076616E616D6F6E206A61207661726A6F74207665"+
            "656E2C206E69697374E420737964E46D656E69206C61756C"+
            "756E207465656E2E202D2045696E6F204C65696E6F");
         kb = Util.toBytesFromString("29041972FB42BA5FC7127712F13829C9");
         ct = Util.toBytesFromString(
            "358186999001E6B5DAF05ECEEB7EEE21E0689C1F00EEA81F"+
            "7DD2CAAEE1D2763E68AF0EAD33D66C268BC946C484FBE94C"+
            "5F5E0B86A59279E4F824E7A640BD223210B0A61160B7BCE9"+
            "86EA65688003596B630A6B90F8E0CAF6912A98EB872176E8"+
            "3C202CAA64166D2CCE57FF1BCA57B213F0ED1AA72FB8EA52"+
            "B0BE01CD1E412867720B326EB389D011BD70D8AF035FB0D8"+
            "589DBCE3C666F5EA8D4C7954C50C3F340B0467F81B425961"+
            "C11843074DF620F208404B394CF9D37FF54B5F1AD8F6EA7D"+
            "A3C561DFA7281F964463D2CC35A4D1B03490DEC51B0711FB"+
            "D6F55F79234D5B7C766622A66DE92BE996461D5E4DC878EF"+
            "9BCA030521E8351E4BAED2FD04F9467368C4AD6AC186D082"+
            "45B263A2666D1F6C5420F1599DFD9F438921C2F5A463938C"+
            "E0982265EEF70179BC553F339EB1A4C1AF5F6A547F");
         attrib.put(ARCFour.ARCFOUR_KEY_MATERIAL, kb);

         keystream.init(attrib);

         byte[] cct = new byte[pt.length];
         for (int i = 0; i < pt.length; i++) {
            cct[i] = (byte) (pt[i] ^ keystream.nextByte());
         }
         harness.check(Arrays.equals(cct, ct));
      } catch (Exception e) {
         harness.debug(e);
         harness.fail("TestOfARCFour.testVectorThree");
      }

      harness.checkPoint("TestOfARCFour.testCloneability");
      try {
         attrib.clear();
         keystream = PRNGFactory.getInstance(Registry.ARCFOUR_PRNG);

         attrib.put(ARCFour.ARCFOUR_KEY_MATERIAL, new byte[0]);
         byte[] b1 = new byte[16];
         byte[] b2 = new byte[16];
         IRandom r1 = PRNGFactory.getInstance(Registry.ARCFOUR_PRNG);
         r1.init(attrib);
         r1.nextBytes(b1, 0, b1.length);
         IRandom r2 = (IRandom) r1.clone();
         r1.nextBytes(b1, 0, b1.length);
         r2.nextBytes(b2, 0, b1.length);
         harness.check(Arrays.equals(b1, b2));
      } catch (Exception e) {
         harness.debug(e);
         harness.fail("TestOfARCFour.testCloneability");
      }
   }
}
