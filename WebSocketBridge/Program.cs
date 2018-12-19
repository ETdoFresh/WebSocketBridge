﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace WebSocketBridge
{
    class Program
    {
        private static TcpListener server;
        private static TcpClient client;
        private static NetworkStream stream;

        private static IPAddress iPAddress = IPAddress.Parse("192.168.254.194");
        private static int port = 9080;

        static void Main(string[] args)
        {
            server = new TcpListener(IPAddress.Parse("127.0.0.1"), 9081);
            server.Start();
            Console.WriteLine("Server started... awaiting connection...");
            client = server.AcceptTcpClient();
            Console.WriteLine("A client connected! " + client.Client.RemoteEndPoint);
            stream = client.GetStream();

            while (!stream.DataAvailable) ;
            var bytes = new byte[client.Available];
            stream.Read(bytes, 0, bytes.Length);
            for (int i = 0; i < bytes.Length; i++)
                Console.Write((i == 0 ? "" : " ") + bytes[i].ToString());
            Console.WriteLine();
            var message = Encoding.UTF8.GetString(bytes);
            Console.WriteLine("Read: " + message);

            const string EOL = "\r\n";
            var keyLabel = "Sec-WebSocket-Key: ";
            var startIndex = message.IndexOf(keyLabel) + keyLabel.Length;
            var endIndex = message.IndexOf(EOL, startIndex);
            string key = message.Substring(startIndex, endIndex - startIndex);
            key += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
            key = Convert.ToBase64String(SHA1.Create().ComputeHash(Encoding.UTF8.GetBytes(key)));
            var response = Encoding.UTF8.GetBytes(
                "HTTP/1.1 101 Switching Protocols" + EOL
                + "Connection: upgrade" + EOL
                + "Upgrade: websocket" + EOL
                + "Sec-WebSocket-Accept: " + key + EOL
                + EOL);
            stream.Write(response, 0, response.Length);

            Send("Welcome to WebSocketBridge.");
            Send("This will relay commands from this websocket to a tcp socket");
            Send("Please send the server ip and port in the following format:");
            Send("TcpSocket Server: " + iPAddress.ToString());
            Send("Port: " + port);
            Send("Note: The above are the default settings.");

            while (true)
            {
                while (!stream.DataAvailable || !client.Connected) ;
                if (!client.Connected) break;
                bytes = new byte[client.Available];
                stream.Read(bytes, 0, bytes.Length);
                for (int i = 0; i < bytes.Length; i++)
                    Console.Write((i == 0 ? "" : " ") + bytes[i].ToString());

                var byte1 = bytes[0];
                var byte2 = bytes[1];
                var mask = new[] { bytes[2], bytes[3], bytes[4], bytes[5] };
                var decoded = new byte[bytes.Length - 6];
                Array.Copy(bytes, 6, decoded, 0, decoded.Length);

                for (int i = 0; i < decoded.Length; i++)
                    decoded[i] = (byte)(bytes[i + 6] ^ mask[i % 4]);
                Console.WriteLine();

                var clientDisconnected = decoded.Length == 2 && decoded[0] == 3 && decoded[1] == 233;
                if (clientDisconnected)
                    break;

                message = Encoding.UTF8.GetString(decoded);
                Console.WriteLine("From WebSocketClient: " + message);

                Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                socket.Connect(iPAddress, port);
                if (socket.Connected)
                {
                    socket.Send(Encoding.UTF8.GetBytes(message));
                    Console.WriteLine("To TcpSocket: " + message);
                    byte[] buffer = new byte[64 * 1024];
                    var bytesRead = socket.Receive(buffer);
                    var output = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                    Console.WriteLine("From TcpSocket: " + output);
                    Send(output);
                }
                else
                    Send("Could not connect to socket!");
            }
        }

        private static void Send(string message)
        {
            List<byte> bytes = new List<byte>();
            bytes.Add(129);
            if (message.Length < 126)
                bytes.Add((byte)message.Length);
            else if (message.Length < 65536)
            {
                bytes.Add(126);
                bytes.AddRange(BitConverter.GetBytes((ushort)message.Length).Reverse());
            }
            else if ((ulong)message.Length <= 18446744073709551615)
            {
                bytes.Add(127);
                bytes.AddRange(BitConverter.GetBytes((ulong)message.Length).Reverse());
            }
            bytes.AddRange(Encoding.UTF8.GetBytes(message));
            stream.Write(bytes.ToArray(), 0, bytes.Count);
        }
    }
}