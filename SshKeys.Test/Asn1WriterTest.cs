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

            data[0] &= 0x7f;
            writer.WriteInt(data);

            Expect(writer.SequenceBytes[7], Is.EqualTo(0));

            writer = new Asn1Writer(0x240);
            data[0] |= 0x80;
            writer.WriteInt(data);

            Expect(writer.SequenceBytes[7], Is.EqualTo(1));
        }
    }
}