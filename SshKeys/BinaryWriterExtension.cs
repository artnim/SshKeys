using System.IO;


namespace SshKeys
{
    public static class BinaryWriterExtension
    {
        public static void WriteBytes(this BinaryWriter writer, byte[] data)
        {
            writer.Write(Asn1Writer.GetLength(data));

            if (data[0] > 0x7f)
            {
                writer.Write((byte)0x00);
            }

            writer.Write(data);
        }
    }
}