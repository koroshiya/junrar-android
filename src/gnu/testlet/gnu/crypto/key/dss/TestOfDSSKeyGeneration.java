package gnu.testlet.gnu.crypto.key.dss;

// ----------------------------------------------------------------------------
// $Id: TestOfDSSKeyGeneration.java,v 1.3 2005/10/06 04:24:20 rsdio Exp $
//
// Copyright (C) 2001, 2002, Free Software Foundation, Inc.
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

import gnu.crypto.key.dss.DSSKeyPairGenerator;
import gnu.crypto.util.Prime;
import gnu.testlet.TestHarness;
import gnu.testlet.Testlet;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.util.HashMap;

/**
 * <p>Conformance tests for the DSS key-pair generation implementation.</p>
 *
 * @version $Revision: 1.3 $
 */
public class TestOfDSSKeyGeneration implements Testlet {

   // Constants and variables
   // -------------------------------------------------------------------------

   // Constructor(s)
   // -------------------------------------------------------------------------

   // default 0-arguments constructor

   // Class methods
   // -------------------------------------------------------------------------

   // Instance methods
   // -------------------------------------------------------------------------

   public void test(TestHarness harness) {
      harness.checkPoint("TestOfDSSKeyGeneration");
      DSSKeyPairGenerator kpg = new DSSKeyPairGenerator();
      HashMap map = new HashMap();
      map.put(DSSKeyPairGenerator.MODULUS_LENGTH, new Integer(530));

      try {
         kpg.setup(map);
         harness.fail("L should be <= 1024 and of the form 512 + 64n");
      } catch (IllegalArgumentException x) {
         harness.check(true, "L should be <= 1024 and of the form 512 + 64n");
      }

      map.put(DSSKeyPairGenerator.MODULUS_LENGTH, new Integer(512));
      map.put(DSSKeyPairGenerator.USE_DEFAULTS, new Boolean(false));
      kpg.setup(map);
      KeyPair kp = kpg.generate();

      BigInteger p1 = ((DSAPublicKey) kp.getPublic()).getParams().getP();
      BigInteger p2 = ((DSAPrivateKey) kp.getPrivate()).getParams().getP();
      harness.check(p1.equals(p2), "p1.equals(p2)");

      BigInteger q1 = ((DSAPublicKey) kp.getPublic()).getParams().getQ();
      BigInteger q2 = ((DSAPrivateKey) kp.getPrivate()).getParams().getQ();
      harness.check(q1.equals(q2), "q1.equals(q2)");

      BigInteger g1 = ((DSAPublicKey) kp.getPublic()).getParams().getG();
      BigInteger g2 = ((DSAPrivateKey) kp.getPrivate()).getParams().getG();
      harness.check(g1.equals(g2), "g1.equals(g2)");

      harness.check(Prime.isProbablePrime(q1), "q is probable prime");
      harness.check(Prime.isProbablePrime(p1), "p is probable prime");
   }
}
