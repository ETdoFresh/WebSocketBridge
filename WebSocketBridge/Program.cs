using System;
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
        private const string EOL = "\r\n";
        private static TcpListener server;
        private static TcpClient client;
        private static NetworkStream stream;

        private static IPAddress iPAddress = IPAddress.Parse("192.168.254.194");
        private static int port = 9080;

        static void Main(string[] args)
        {
            StartServer();

            client = server.AcceptTcpClient();
            Console.WriteLine("A client connected! " + client.Client.RemoteEndPoint);
            stream = client.GetStream();

            HandleWebSocketHandshake();
            SendWebSocketClientInstructions();

            while (true)
            {
                while (!stream.DataAvailable || !client.Connected) ;
                if (!client.Connected) break;
                byte[] bytes = ReceiveWebSocketBytes();
                byte[] decoded = DecodeWebSocketBytes(bytes);
                var message = Encoding.UTF8.GetString(decoded);
                Console.WriteLine("From WebSocketClient: " + message);

                Socket socket = ConnectTcpSocket();
                if (socket.Connected)
                {
                    SentToTcpClient(message, socket);
                    bytes = ReceiveTcpClientBytes(socket);
                    var output = Encoding.UTF8.GetString(bytes);
                    Console.WriteLine("From TcpSocket: " + output);
                    SendToWebSocket(output);
                    socket.Close();
                }
                else
                    SendToWebSocket("Could not connect to socket!");
            }
        }

        private static byte[] ReceiveTcpClientBytes(Socket socket)
        {
            var buffer = new byte[64 * 1024];
            var bytesRead = socket.Receive(buffer);
            var bytes = new byte[bytesRead];
            Array.Copy(buffer, 0, bytes, 0, bytesRead);
            return bytes;
        }

        private static void SentToTcpClient(string message, Socket socket)
        {
            socket.Send(Encoding.UTF8.GetBytes(message));
            Console.WriteLine("To TcpSocket: " + message);
        }

        private static Socket ConnectTcpSocket()
        {
            Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            socket.Connect(iPAddress, port);
            return socket;
        }

        private static byte[] DecodeWebSocketBytes(byte[] bytes)
        {
            var byte1 = bytes[0];
            var byte2 = bytes[1];
            var mask = new[] { bytes[2], bytes[3], bytes[4], bytes[5] };
            var decoded = new byte[bytes.Length - 6];
            Array.Copy(bytes, 6, decoded, 0, decoded.Length);

            for (int i = 0; i < decoded.Length; i++)
                decoded[i] = (byte)(bytes[i + 6] ^ mask[i % 4]);
            return decoded;
        }

        private static byte[] ReceiveWebSocketBytes()
        {
            var bytes = new byte[client.Available];
            stream.Read(bytes, 0, bytes.Length);
            return bytes;
        }

        private static void HandleWebSocketHandshake()
        {
            var message = ReceiveHandshakeMessage();
            var key = GetKey(message);
            SendHandshakeResponse(key);
        }

        private static void SendWebSocketClientInstructions()
        {
            SendToWebSocket("Welcome to WebSocketBridge.");
            SendToWebSocket("This will relay commands from this websocket to a tcp socket");
            SendToWebSocket("Please send the server ip and port in the following format:");
            SendToWebSocket("TcpSocket Server: " + iPAddress.ToString());
            SendToWebSocket("Port: " + port);
            SendToWebSocket("Note: The above are the default settings.");
        }

        private static void SendHandshakeResponse(string key)
        {
            var response = Encoding.UTF8.GetBytes(
                            "HTTP/1.1 101 Switching Protocols" + EOL
                            + "Connection: upgrade" + EOL
                            + "Upgrade: websocket" + EOL
                            + "Sec-WebSocket-Accept: " + key + EOL
                            + EOL);
            stream.Write(response, 0, response.Length);
        }

        private static string GetKey(string message)
        {
            var keyLabel = "Sec-WebSocket-Key: ";
            var startIndex = message.IndexOf(keyLabel) + keyLabel.Length;
            var endIndex = message.IndexOf(EOL, startIndex);
            var key = message.Substring(startIndex, endIndex - startIndex);
            key += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
            key = Convert.ToBase64String(SHA1.Create().ComputeHash(Encoding.UTF8.GetBytes(key)));
            return key;
        }

        private static void StartServer()
        {
            server = new TcpListener(IPAddress.Parse("127.0.0.1"), 9081);
            server.Start();
            Console.WriteLine("Server started... awaiting connection...");
        }

        private static string ReceiveHandshakeMessage()
        {
            string message;
            while (!stream.DataAvailable) ;
            var bytes = new byte[client.Available];
            stream.Read(bytes, 0, bytes.Length);
            message = Encoding.UTF8.GetString(bytes);
            Console.WriteLine("Read: " + message);
            return message;
        }

        private static void OnAcceptTcpClient(IAsyncResult ar)
        {
            throw new NotImplementedException();
        }

        private static void SendToWebSocket(string message)
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
