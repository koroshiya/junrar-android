package gnu.testlet.gnu.crypto.hash;

// ----------------------------------------------------------------------------
// $Id: TestOfSha512.java,v 1.2 2005/10/06 04:24:19 rsdio Exp $
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

import gnu.crypto.hash.IMessageDigest;
import gnu.crypto.hash.Sha512;
import gnu.crypto.util.Util;
import gnu.testlet.TestHarness;
import gnu.testlet.Testlet;

/**
 * <p>Conformance tests for the SHA-2-3 implementation.</p>
 *
 * @version $Revision: 1.2 $
 */
public class TestOfSha512 implements Testlet {

   // Constants and variables
   // -------------------------------------------------------------------------

   private IMessageDigest algorithm;

   // Constructor(s)
   // -------------------------------------------------------------------------

   // default 0-arguments constructor

   // Class methods
   // -------------------------------------------------------------------------

   // Instance methods
   // -------------------------------------------------------------------------

   public void test(TestHarness harness) {
      harness.checkPoint("TestOfSha512");
      try {
         algorithm = new Sha512();
         harness.check(algorithm.selfTest(), "selfTest");
      } catch (Exception x) {
         harness.debug(x);
         harness.fail("TestOfSha512.selfTest");
      }

      try {
         algorithm = new Sha512();
         algorithm.update(
               ("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
               +"ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu").getBytes(), 0, 112);
         byte[] md = algorithm.digest();
         String exp =
               "8E959B75DAE313DA8CF4F72814FC143F8F7779C6EB9F7FA17299AEADB6889018"+
               "501D289E4900F7E4331B99DEC4B5433AC7D329EEB6DD26545E96E55B874BE909";
         harness.check(exp.equals(Util.toString(md)), "testAlphabet");
      } catch (Exception x) {
         harness.debug(x);
         harness.fail("TestOfSha512.testAlphabet");
      }
   }
}
