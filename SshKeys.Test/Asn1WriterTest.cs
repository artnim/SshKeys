using System.Security.Cryptography;
using NUnit.Framework;


namespace SshKeys.Test
{
    [TestFixture]
    public class Asn1WriterTest : AssertionHelper
    {
        [Test]
        public void Test()
        {
            var data = new byte[0x200];
            var rng = new RNGCryptoServiceProvider();

            rng.GetBytes(data);

            var writer = new Asn1Writer(0x240);

            writer.WriteInt(data);

            data = writer.GetSequence();

        }
    }
}