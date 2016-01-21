﻿using NUnit.Framework;


namespace SshKeys.Test
{
    [TestFixture]
    public class KeyPairRSATest : AssertionHelper
    {
        [Test]
        public void IvTest()
        {
            var rsa = new KeyPairRSA(2048);

            Expect(rsa.Iv.Length, Is.EqualTo(8));
        }

        [Test]
        public void KeyTest()
        {
            var rsa = new KeyPairRSA(2048, "StrengGeheim");

            Expect(rsa.Key.Length, Is.EqualTo(24));
        }

        [Test]
        public void AmoredTest()
        {
            var rsa = new KeyPairRSA(0x800); //, "StrengGeheim");

            var a = rsa.AmoredPrivateKey;
            var b = rsa.Base64PublicKey;
        }
    }
}