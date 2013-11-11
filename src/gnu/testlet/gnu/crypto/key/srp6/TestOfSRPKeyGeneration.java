package gnu.testlet.gnu.crypto.key.srp6;

// ----------------------------------------------------------------------------
// $Id: TestOfSRPKeyGeneration.java,v 1.2 2005/10/06 04:24:20 rsdio Exp $
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

import gnu.crypto.key.srp6.SRPKeyPairGenerator;
import gnu.crypto.key.srp6.SRPPrivateKey;
import gnu.crypto.key.srp6.SRPPublicKey;
import gnu.crypto.util.Prime;
import gnu.testlet.TestHarness;
import gnu.testlet.Testlet;

import java.math.BigInteger;
import java.security.KeyPair;
import java.util.HashMap;

/**
 * <p>Conformance tests for the SRP key-pair generation implementation.</p>
 *
 * @version $Revision: 1.2 $
 */
public class TestOfSRPKeyGeneration implements Testlet {

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
      harness.checkPoint("TestOfSRPKeyGeneration");
      SRPKeyPairGenerator kpg = new SRPKeyPairGenerator();
      HashMap map = new HashMap();
      map.put(SRPKeyPairGenerator.MODULUS_LENGTH, new Integer(530));

      try {
         kpg.setup(map);
         harness.fail("L should be >= 512, <= 2048 and of the form 512 + 256n");
      } catch (IllegalArgumentException x) {
         harness.check(true, "L should be >= 512, <= 2048 and of the form 512 + 256n");
      }

      map.put(SRPKeyPairGenerator.MODULUS_LENGTH, new Integer(512));
      map.put(SRPKeyPairGenerator.USE_DEFAULTS, Boolean.FALSE);
      kpg.setup(map);
      KeyPair kp = kpg.generate();

      BigInteger N1 = ((SRPPublicKey) kp.getPublic()).getN();
      BigInteger N2 = ((SRPPrivateKey) kp.getPrivate()).getN();
      harness.check(N1.equals(N2), "N1.equals(N2)");

      BigInteger q = N1.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2L));

      BigInteger g1 = ((SRPPublicKey) kp.getPublic()).getG();
      BigInteger g2 = ((SRPPrivateKey) kp.getPrivate()).getG();
      harness.check(g1.equals(g2), "g1.equals(g2)");

      harness.check(Prime.isProbablePrime(N1), "N is probable prime");
      harness.check(Prime.isProbablePrime(q), "q is probable prime");
   }
}
