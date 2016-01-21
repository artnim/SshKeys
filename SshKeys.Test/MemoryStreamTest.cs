using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using NUnit;
using NUnit.Framework;

namespace SshKeys.Test
{
    [TestFixture]
    public class MemoryStreamTest : AssertionHelper
    {
        [Test]
        public void Test1()
        {
            using (var stream = new MemoryStream())
            using (var writer = new BinaryWriter(stream))
            {
                writer.Write(IPAddress.HostToNetworkOrder(42));

                Expect(stream.Position, Is.EqualTo(4));
                Expect(stream.Length, Is.EqualTo(4));
            }
        }

    }
}
