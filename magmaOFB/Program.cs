using System;
using System.Diagnostics;
using System.IO;

namespace MagmaCBC
{
    class Program
    {
        static void Main(string[] args)
        {

            int action = 0; //действие
            Console.WriteLine("Выберите режим");
            Console.WriteLine("Введите 1 - для шифрования в режиме ECB");
            Console.WriteLine("Введите 2 - для расшифрования в режиме ECB");
            Console.WriteLine("Введите 3 - для шифрования в режиме CBC");
            Console.WriteLine("Введите 4 - для расшифрования в режиме CBC");
            Console.WriteLine("Введите 5 - для ршифрования в режиме OFB");
            Console.WriteLine("Введите 6 - для расшифрования в режиме OFB");
            action = Convert.ToInt32(Console.ReadLine());

            Console.WriteLine("Введите название файла ключа");
            string KeyFileName = Console.ReadLine();
            FileStream KeyFile = File.OpenRead(KeyFileName); //поток для ключа (на чтение)
            byte[] KEY = new byte[32];
            KeyFile.Read(KEY, 0, 32); // считываем ключ
            KeyFile.Close();

            Console.WriteLine("Введите название файла");
            string FileName = Console.ReadLine();
            FileStream TextFile = File.OpenRead(FileName);
            byte[] Text = new byte[TextFile.Length];
            TextFile.Read(Text, 0, Text.Length); // считываем ОТ
            TextFile.Close();

            Console.WriteLine("Введите название получаемого файла");
            string resultFileName = Console.ReadLine();
            Magma test = new Magma(KEY);
            switch (action)
            {
                case 1:
                   byte[] ETECB = test.ECBenc(Text);
                    File.Delete(resultFileName);
                    FileStream EncFileECB = new FileStream(resultFileName, FileMode.OpenOrCreate);
                    EncFileECB.Seek(0, SeekOrigin.End);
                    EncFileECB.Write(ETECB);
                    EncFileECB.Close();
                    break;
                case 2:
                    byte[] DTECB = test.ECBdec(Text);
                    File.Delete(resultFileName);
                    FileStream DecFileECB = new FileStream(resultFileName, FileMode.OpenOrCreate);
                    DecFileECB.Seek(0, SeekOrigin.End);
                    DecFileECB.Write(DTECB);
                    DecFileECB.Close();
                    break;
                case 3:
                    byte[] ETCBC = test.CBCenc(Text);
                    File.Delete(resultFileName);
                    FileStream EncFile = new FileStream(resultFileName, FileMode.OpenOrCreate);
                    EncFile.Seek(0, SeekOrigin.End);
                    EncFile.Write(ETCBC);
                    EncFile.Close();
                    break;
                case 4:
                    byte[] DTCBC = test.CBCdec(Text);
                    File.Delete(resultFileName);
                    FileStream DecFile = new FileStream(resultFileName, FileMode.OpenOrCreate);
                    DecFile.Seek(0, SeekOrigin.End);
                    DecFile.Write(DTCBC);
                    DecFile.Close();
                    break;
                case 5:
                    byte[] ETOFB = test.OFBenc(Text);
                    File.Delete(resultFileName);
                    FileStream EncFileOFB = new FileStream(resultFileName, FileMode.OpenOrCreate);
                    EncFileOFB.Seek(0, SeekOrigin.End);
                    EncFileOFB.Write(ETOFB);
                    EncFileOFB.Close();
                    break;
                case 6:
                    byte[] DTOFB = test.OFBdec(Text);
                    File.Delete(resultFileName);
                    FileStream DecFileOFB = new FileStream(resultFileName, FileMode.OpenOrCreate);
                    DecFileOFB.Seek(0, SeekOrigin.End);
                    DecFileOFB.Write(DTOFB);
                    DecFileOFB.Close();
                    break;
            }
        }
    }

    public class Magma
    {
        private uint A;
        private uint B;
        private byte[] KEY = new byte[32];
        private uint[] RoundKeys = new uint[8];
        private static int[] keyMap = { 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 7, 6, 5, 4, 3, 2, 1, 0 };
        private byte[,] Sbox = new byte[8, 16]{
            {12,4,6,2,10,5,11,9,14,8,13,7,0,3,15,1},
            {6,8,2,3,9,10,5,12,1,14,4,7,11,13,0,15},
            {11,3,5,8,2,15,10,13,14,1,7,4,12,9,6,0},
            {12,8,2,1,13,4,15,6,7,0,10,5,3,14,9,11},
            {7,15,5,10,8,1,6,13,0,9,3,14,11,4,2,12},
            {5,13,15,6,9,2,12,10,11,7,8,1,4,3,14,0},
            {8,14,2,5,6,9,1,12,15,4,11,0,13,10,3,7},
            {1,7,14,13,0,5,8,3,4,15,10,6,9,12,11,2}
        };
        public byte bytesAdded;

        public Magma(byte[] key)
        {//конструктор класса
            this.KEY = key;
        }



        public byte[] genIV()
        {
            byte[] c = new byte[8];
            Random rnd = new Random();
            for (int i = 0; i < (c.Length); i++)
            {
                c[i] = (byte)(rnd.Next());
            }
            return c;
        }
        private void encryptblock() //шифрование блока
        {
                uint temp = 0;
                for (int Round = 0; Round < 32; Round++)
                {
                    temp = A;
                    this.A = Module32(A, RoundKeys[keyMap[Round]]);
                    this.A = Substitute(A, Sbox);
                    this.A = (A << 11) | (A >> 21);
                    this.A = B ^ A;
                    this.B = temp;
                };
        }


        private void decryptblock() //дешифрование блока
        {
                uint temp = 0;
                for (int Round = 0; Round < 32; Round++)
                {
                    temp = A;
                    this.A = Module32(A, RoundKeys[keyMap[31 - Round]]);
                    this.A = Substitute(A, Sbox);
                    this.A = (A << 11) | (A >> 21);
                    this.A = B ^ A;
                    this.B = temp;
                }
        }
//---------------------------------------------------------------------------------------------------------------------------------------------------------------
        public byte[] CBCenc(byte[] OpenText) //шифрование в режиме CBC
        {
            byte[] IV = new byte[8];
            IV = genIV();
            byte[] ExOpenText = AddingBytes(OpenText);
            byte[] OpenTextBlock = new byte[8];
            Array.Copy(ExOpenText, 0, OpenTextBlock, 0, OpenTextBlock.Length);
            byte[] PreviousBlock = new byte[8];
            Array.Copy(IV, 0, PreviousBlock, 0, PreviousBlock.Length);

            KeyDivide(this.KEY);
            for (int index = 0; index < ExOpenText.Length - 2; index = index + 8)
            {
                Array.Copy(ExOpenText, index, OpenTextBlock, 0, OpenTextBlock.Length);
                for (int i = 0; i < 8; i++)
                {
                    OpenTextBlock[i] ^= PreviousBlock[i];
                }
                this.A = BitConverter.ToUInt32(OpenTextBlock, 0);
                this.B = BitConverter.ToUInt32(OpenTextBlock, 4);
                encryptblock();
                byte[] AA = BitConverter.GetBytes(A);
                byte[] BB = BitConverter.GetBytes(B);
                Array.Copy(BB, 0, ExOpenText, index, BB.Length);
                Array.Copy(AA, 0, ExOpenText, index + 4, AA.Length);
                Array.Copy(ExOpenText, index, PreviousBlock, 0, PreviousBlock.Length);
            }
            byte[] ExOpenTextWIV = new byte[ExOpenText.Length+8];
            Array.Copy(IV,0, ExOpenTextWIV,0,IV.Length);
            Array.Copy(ExOpenText, 0, ExOpenTextWIV, 8, ExOpenText.Length);
            return ExOpenTextWIV;
        }
        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        public byte[] CBCdec(byte[] EncryptedText)
        {
            byte[] IV = new byte[8];
            uint tempA;
            uint tempB;
            KeyDivide(this.KEY);
            for (int index = 8; index < EncryptedText.Length-2; index = index + 8)
            {
                this.A = BitConverter.ToUInt32(EncryptedText, index);
                tempA = A;
                this.B = BitConverter.ToUInt32(EncryptedText, index + 4);
                tempB = B;
                Array.Copy(EncryptedText, 0, IV, 0, IV.Length);
                decryptblock();
                byte[] AA = BitConverter.GetBytes(A);
                byte[] BB = BitConverter.GetBytes(B);
                for(int i = 0; i < 4 ; i++)
                {
                    BB[i] ^= IV[i];
                    AA[i] ^= IV[i + 4];
                }
                byte[] tempAA = BitConverter.GetBytes(tempA);
                byte[] tempBB = BitConverter.GetBytes(tempB);
                Array.Copy(tempAA, 0, EncryptedText, 0, AA.Length);
                Array.Copy(tempBB, 0, EncryptedText, 4, BB.Length);
                Array.Copy(BB, 0, EncryptedText, index, BB.Length);
                Array.Copy(AA, 0, EncryptedText, index+4, AA.Length); 
            }
            byte[] TextWithoutIV = new byte[EncryptedText.Length - IV.Length];
            Array.Copy(EncryptedText, 8, TextWithoutIV, 0, TextWithoutIV.Length);
            byte[] CuttedText = CutBytes(TextWithoutIV);
            return CuttedText;
        }
        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        public byte[] OFBenc(byte[] OpenText)
        {
            byte[] IV = new byte[8];
            IV = genIV();
            byte[] PreviousBlock = new byte[8];
            Array.Copy(IV, 0, PreviousBlock, 0, IV.Length);
            byte[] ExOpenText = AddingBytes(OpenText);
            byte[] OpenTextBlock = new byte[8];
            KeyDivide(this.KEY);
            for (int index = 0; index < ExOpenText.Length - 1; index = index + 8)
            {  
                this.A = BitConverter.ToUInt32(PreviousBlock, 0);
                this.B = BitConverter.ToUInt32(PreviousBlock, 4);
                encryptblock();
                byte[] AA = BitConverter.GetBytes(A);
                byte[] BB = BitConverter.GetBytes(B);
                Array.Copy(BB, 0, PreviousBlock, 0, BB.Length);
                Array.Copy(AA, 0, PreviousBlock, 4, AA.Length);
                Array.Copy(ExOpenText, index, OpenTextBlock, 0, OpenTextBlock.Length);
                for (int i = 0; i < 8; i++)
                {
                    OpenTextBlock[i] ^= PreviousBlock[i];
                }
                Array.Copy(OpenTextBlock, 0, ExOpenText, index, OpenTextBlock.Length);
            }
            byte[] ExOpenTextWIV = new byte[ExOpenText.Length + 8];
            Array.Copy(IV, 0, ExOpenTextWIV, 0, IV.Length);
            Array.Copy(ExOpenText, 0, ExOpenTextWIV, 8, ExOpenText.Length);
            return ExOpenTextWIV;
        }
        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        public byte[] OFBdec(byte[] EncryptedText)
        {
            byte[] IV = new byte[8];
            byte[] EncryptedTextBlock = new byte[8];
            Array.Copy(EncryptedText, 0, IV, 0, IV.Length);
            KeyDivide(this.KEY);
            for (int index = 8; index < EncryptedText.Length - 2; index = index + 8)
            {
                this.A = BitConverter.ToUInt32(IV, 0);
                this.B = BitConverter.ToUInt32(IV, 4);
                encryptblock();
                byte[] AA = BitConverter.GetBytes(A);
                byte[] BB = BitConverter.GetBytes(B);
                Array.Copy(BB, 0, IV, 0, BB.Length);
                Array.Copy(AA, 0, IV, 4, AA.Length);
                Array.Copy(EncryptedText, index, EncryptedTextBlock, 0, EncryptedTextBlock.Length);
                for (int i = 0; i < 8; i++)
                {
                    EncryptedTextBlock[i] ^= IV[i];
                }
                Array.Copy(EncryptedTextBlock, 0, EncryptedText, index, EncryptedTextBlock.Length);
            }
            byte[] TextWithoutIV = new byte[EncryptedText.Length - IV.Length];
            Array.Copy(EncryptedText, 8, TextWithoutIV, 0, TextWithoutIV.Length);
            byte[] CuttedText = CutBytes(TextWithoutIV);
            return CuttedText;
        }
        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        public byte[] ECBenc(byte[] OpenText)
        {
            KeyDivide(this.KEY);
            byte[] ExOpenText = AddingBytes(OpenText);
            for (int index = 0; index < ExOpenText.Length - 1; index = index + 8)
            {
                this.A = BitConverter.ToUInt32(ExOpenText, index);
                this.B = BitConverter.ToUInt32(ExOpenText, index + 4);
                encryptblock();
                byte[] AA = BitConverter.GetBytes(A);
                byte[] BB = BitConverter.GetBytes(B);
                Array.Copy(BB, 0, ExOpenText, index, BB.Length);
                Array.Copy(AA, 0, ExOpenText, index + 4, AA.Length);
            }
            return ExOpenText;
        }
        //---------------------------------------------------------------------------------------------------------------------------------------------------------------

        public byte[] ECBdec(byte[] EncryptedText)
        {
            KeyDivide(this.KEY);
            for (int index = 0; index < EncryptedText.Length - 2; index = index + 8)
            {
                this.A = BitConverter.ToUInt32(EncryptedText, index);
                this.B = BitConverter.ToUInt32(EncryptedText, index + 4);
                decryptblock();
                byte[] AA = BitConverter.GetBytes(A);
                byte[] BB = BitConverter.GetBytes(B);
                Array.Copy(BB, 0, EncryptedText, index, BB.Length);
                Array.Copy(AA, 0, EncryptedText, index + 4, AA.Length);
            }
            byte[] CuttedText = CutBytes(EncryptedText);
            return CuttedText;
        }
//---------------------------------------------------------------------------------------------------------------------------------------------------------------
        private byte[] AddingBytes(byte[] Text)
        {
            int LastBlockLength = 8 - (Text.Length % 8);
            if (Text.Length % 8 != 0)
            {
                byte[] NewText = new byte[(Text.Length + LastBlockLength+1)];
                Array.Copy(Text, NewText, Text.Length);
                this.bytesAdded = (byte)LastBlockLength;
                NewText[Text.Length + LastBlockLength] = (byte)LastBlockLength;
                return NewText;

            }
            else
            {
                byte[] NewText = new byte[(Text.Length + 1)];
                Array.Copy(Text, NewText, Text.Length);
                NewText[Text.Length] = 0;
                return NewText;
            }
        }

        private byte[] CutBytes(byte[] Text)
        {

            byte LastBlockLength = Text[Text.Length-1];
            this.bytesAdded = LastBlockLength;
            if (LastBlockLength != 0)
            {
                byte[] NewText = new byte[Text.Length - LastBlockLength - 1];
                Array.Copy(Text, NewText, NewText.Length);
                return NewText;
            }
            else
            {
                byte[] NewText = new byte[Text.Length - 1];
                Array.Copy(Text, NewText, NewText.Length);
                return NewText;
            }
        }

        private uint Module32(uint PartOfText, uint RoundKey) //A = A + RoundKey;
        {
            uint result = (PartOfText + RoundKey) % uint.MaxValue;
            return result;
        }

        private uint Substitute(uint AfterModule, byte[,] sBox) //S-box
        {
            uint result = 0;
            for (int i = 0; i < 8; i++)
            {
                byte index, sBlock;
                index = (byte)(AfterModule >> (4 * i) & 0x0f);
                sBlock = sBox[i, index];
                result |= (uint)sBlock << (4 * i);
            }
            return result;
        }

        private void WriteIntoFile(byte[] Text, string FileName)
        {
            FileStream File = new FileStream(FileName, FileMode.Append);
            File.Seek(0, SeekOrigin.End);
            File.Write(Text);
            File.Close();
        }

        private void KeyDivide(byte[] KEY) // Разделяем ключ
        {
            int k = 0;
            for (int i = 0; i < 8; i++)
            {
                this.RoundKeys[i] = BitConverter.ToUInt32(KEY, k);
                k += 4;
            }
        }
    }
}

