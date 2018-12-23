using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

// TODO : Handle errors in sending and receiving

namespace WebSocketBridge
{
    class Program
    {
        private const string EOL = "\r\n";

        private static IPAddress iPAddress = IPAddress.Parse("127.0.0.1");
        private static int port = 9080;

        public static List<TcpClient> clients = new List<TcpClient>();

        private static void Main(string[] args)
        {
            StartServer();
            while (true) ;
        }

        private static void StartServer()
        {
            var server = new TcpListener(IPAddress.Parse("127.0.0.1"), 9081);
            server.Start();
            BeginAcceptConnection(server);
        }

        private static void BeginAcceptConnection(TcpListener listener)
        {
            Console.WriteLine("Server: Waiting for a connection...");
            listener.BeginAcceptTcpClient(OnAcceptedConnection, listener);
        }

        private static void OnAcceptedConnection(IAsyncResult ar)
        {
            TcpListener listener = (TcpListener)ar.AsyncState;
            TcpClient client = listener.EndAcceptTcpClient(ar);
            clients.Add(client);
            var clientIndex = clients.Count - 1;
            Console.WriteLine("Client " + clientIndex + ": Connected from " + client.Client.RemoteEndPoint);
            BeginReceiveHandshake(client);
            BeginAcceptConnection(listener);
        }

        private static void BeginReceiveHandshake(TcpClient client)
        {
            var buffer = new byte[64 * 1024];
            var stream = client.GetStream();
            stream.BeginRead(buffer, 0, buffer.Length, OnReceivedHandshake, new ClientBuffer(client, stream, buffer));
        }

        private static void OnReceivedHandshake(IAsyncResult ar)
        {
            var clientBuffer = (ClientBuffer)ar.AsyncState;
            var client = clientBuffer.client;
            var stream = clientBuffer.stream;
            var clientIndex = clients.IndexOf(client);
            var bytesRead = stream.EndRead(ar);
            var message = Encoding.UTF8.GetString(clientBuffer.bytes, 0, bytesRead);
            Console.WriteLine("Client " + clientIndex + ": Received **Handshake**");

            BeginSendHandshake(client, stream, message);
        }

        private static void BeginSendHandshake(TcpClient client, NetworkStream stream, string message)
        {
            var key = GetKey(message);
            var response = Encoding.UTF8.GetBytes(
                           "HTTP/1.1 101 Switching Protocols" + EOL
                           + "Connection: upgrade" + EOL
                           + "Upgrade: websocket" + EOL
                           + "Sec-WebSocket-Accept: " + key + EOL
                           + EOL);
            stream.BeginWrite(response, 0, response.Length, OnSentHandshake, new ClientBuffer(client, stream, response));
        }

        private static void OnSentHandshake(IAsyncResult ar)
        {
            var clientBuffer = (ClientBuffer)ar.AsyncState;
            var client = clientBuffer.client;
            var stream = clientBuffer.stream;
            var clientIndex = clients.IndexOf(client);

            stream.EndWrite(ar);
            Console.WriteLine("Client " + clientIndex + ": Sent **Handshake**");

            SendWebSocketClientInstructions(stream);
            Console.WriteLine("Client " + clientIndex + ": Sent **Instructions**");

            BeginReceiveMessage(client, stream);
        }

        private static void BeginReceiveMessage(TcpClient client, NetworkStream stream)
        {
            var buffer = new byte[64 * 1024];
            stream.BeginRead(buffer, 0, buffer.Length, OnReceivedMessage, new ClientBuffer(client, stream, buffer));
        }

        private static void OnReceivedMessage(IAsyncResult ar)
        {
            var clientBuffer = (ClientBuffer)ar.AsyncState;
            var client = clientBuffer.client;
            var stream = clientBuffer.stream;
            var bytes = clientBuffer.bytes;
            var clientIndex = clients.IndexOf(client);
            var bytesRead = stream.EndRead(ar);

            var trimmed = new byte[bytesRead];
            Array.Copy(bytes, trimmed, trimmed.Length);

            var opcode = trimmed[0] & 0x0F;
            var closeConnectionRequested = opcode == 0x08;
            var decoded = DecodeWebSocketBytes(trimmed);

            if (closeConnectionRequested)
            {
                CloseConnection(client, clientIndex, decoded);
                return;
            }

            var message = Encoding.UTF8.GetString(decoded);
            Console.WriteLine("Client " + clientIndex + ": Received " + message);

            if (IsChangeIPAddressMessage(message))
            {
                if (ChangeIPAddress(message)) BeginSendToWebSocket(stream, "IPAddress: " + iPAddress);
                else BeginSendToWebSocket(stream, "Error setting IP Address");
            }
            else if (IsChangePortMessage(message))
            {
                if (ChangePort(message)) BeginSendToWebSocket(stream, "Port: " + port);
                else BeginSendToWebSocket(stream, "Error setting Port");
            }
            else
            {
                try
                {
                    var socket = ConnectTcpSocket();
                    socket.Send(Encoding.UTF8.GetBytes(message));
                    Console.WriteLine("Client " + clientIndex + ": tcp://" + iPAddress + ":" + port + ": Sent " + message);
                    bytes = ReceiveTcpClientBytes(socket);
                    socket.Close();

                    var response = Encoding.UTF8.GetString(bytes);
                    Console.WriteLine("Client " + clientIndex + ": tcp://" + iPAddress + ":" + port + ": Received " + response);
                    BeginSendToWebSocket(stream, response);
                    Console.WriteLine("Client " + clientIndex + ": Sent " + response);
                }
                catch
                {
                    var response = "Error connecting/communicating to tcp://" + iPAddress + ":" + port;
                    BeginSendToWebSocket(stream, response);
                    Console.WriteLine("Client " + clientIndex + ": Sent " + response);
                }
            }
            BeginReceiveMessage(client, stream);
        }

        private static bool ChangePort(string message)
        {
            message = message.Replace("Port: ", "");
            return int.TryParse(message, out port);
        }

        private static bool ChangeIPAddress(string message)
        {
            message = message.Replace("IPAddress: ", "");
            return IPAddress.TryParse(message, out iPAddress);
        }

        private static bool IsChangeIPAddressMessage(string message)
        {
            return message.StartsWith("IPAddress: ");
        }

        private static bool IsChangePortMessage(string message)
        {
            return message.StartsWith("Port: ");
        }

        private static byte[] DecodeWebSocketBytes(byte[] bytes)
        {
            var mask = new[] { bytes[2], bytes[3], bytes[4], bytes[5] };
            var decoded = new byte[bytes.Length - 6];
            Array.Copy(bytes, 6, decoded, 0, decoded.Length);

            for (int i = 0; i < decoded.Length; i++)
                decoded[i] = (byte)(bytes[i + 6] ^ mask[i % 4]);
            return decoded;
        }

        private static void CloseConnection(TcpClient client, int clientIndex, byte[] decoded)
        {
            var closeCode = 0;
            var closeText = "No Code";
            if (decoded.Length == 2)
            {
                closeCode = BitConverter.ToUInt16(decoded.Reverse().ToArray(), 0);
                if (closeCode == 1000) closeText = "Normal";
                if (closeCode == 1001) closeText = "Going Away";
                if (closeCode == 1002) closeText = "Protocol Error";
                if (closeCode == 1003) closeText = "Received Data Type Error (binary/text)";
                if (closeCode == 1004) closeText = "Reserved";
                if (closeCode == 1005) closeText = "No Status";
                if (closeCode == 1006) closeText = "Abnormal Closure";
                if (closeCode == 1007) closeText = "Received Data Type Error (non-UTF8?)";
                if (closeCode == 1008) closeText = "Policy Violated";
                if (closeCode == 1009) closeText = "Message Too Big";
                if (closeCode == 1010) closeText = "Server Close Handshake Wrong";
                if (closeCode == 1011) closeText = "Unexpected Condition";
                if (closeCode == 1015) closeText = "TLS handshake failure";
            }
            Console.WriteLine("Client " + clientIndex + ": Close Connection (" + closeCode + ": " + closeText + ")");
            client.Close();
            clients.Remove(client);
        }

        private static Socket ConnectTcpSocket()
        {
            Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            socket.Connect(iPAddress, port);
            return socket;
        }

        private static byte[] ReceiveTcpClientBytes(Socket socket)
        {
            var buffer = new byte[64 * 1024];
            var bytesRead = socket.Receive(buffer);
            var bytes = new byte[bytesRead];
            Array.Copy(buffer, 0, bytes, 0, bytesRead);
            return bytes;
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

        private static void SendWebSocketClientInstructions(NetworkStream stream)
        {
            BeginSendToWebSocket(stream, "Welcome to WebSocketBridge." + EOL
                + "This will relay commands from this websocket to a tcp socket" + EOL
                + "Please send the server ip and port of tcp socket server in the following format:" + EOL
                + EOL
                + "IPAddress: " + iPAddress.ToString() + EOL
                + "Port: " + port + EOL
                + EOL
                + "Note: The above are the default settings.");
        }

        private static void BeginSendToWebSocket(NetworkStream stream, string message)
        {
            List<byte> bytes = MessageToUnmaskedBytes(message);
            stream.BeginWrite(bytes.ToArray(), 0, bytes.Count, OnSentToWebSocket, stream);
        }

        private static List<byte> MessageToUnmaskedBytes(string message)
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
            return bytes;
        }

        private static void OnSentToWebSocket(IAsyncResult ar)
        {
            var stream = (NetworkStream)ar.AsyncState;
            stream.EndWrite(ar);
        }

        private class ClientBuffer
        {
            public TcpClient client;
            public NetworkStream stream;
            public byte[] bytes;

            public ClientBuffer(TcpClient client, NetworkStream stream, byte[] bytes)
            {
                this.client = client;
                this.stream = stream;
                this.bytes = bytes;
            }
        }
    }
}
