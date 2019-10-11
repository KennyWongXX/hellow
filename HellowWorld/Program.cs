using System;

namespace HellowWorld
{
    class Program
    {
        static void Main(string[] args)
        {
            string doubleForwardSlash = new string((char)47, 2); // /
            string doubleBackSlash = new string((char)92, 2); // \

            string hellow = "Hellow TEST";

            Console.WriteLine(hellow);
            Console.WriteLine();
        }
    }
}
