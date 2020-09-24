using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SslStreamBugCore3
{
	class Program
	{
		public const byte SocksVersion = 0x05;
		private enum AddressType : byte
		{
			IpV4 = 0x01,
			DomainName = 0x03,
			IpV6 = 0x04
		}
		private enum ReplyType : byte
		{
			Succeeded = 0x00,
			GeneralSocksServerFailure = 0x01,
			ConnectionNotAllowedByRuleset = 0x02,
			NetworkUnreachable = 0x03,
			HostUnreachable = 0x04,
			ConnectionRefused = 0x05,
			TtlExpired = 0x06,
			CommandNotSupport = 0x07,
			AddressTypeNotSupported = 0x08,
			Unassigned = 0x09
		}

		static void Main(string[] args)
		{
			// Before running the software make sure Tor is running: https://www.torproject.org/download/download.html.en

			var uri = new Uri("https://httpbin.org/");
			// If you run Tor Browser, not Tor directly then your port is 9150
			var endPoint = new IPEndPoint(IPAddress.Parse("127.0.0.1"), 9050);

			Console.WriteLine("Connecting socket...");
			Socket socket = ConnectToSocket(endPoint);
			Console.WriteLine("Handshaking Tor...");
			HandshakeTor(socket);

			Console.WriteLine("Connecting to destination...");
			ConnectToDestination(uri, socket);

			Console.WriteLine("Ssl authenticating as client...");
			using (var stream = new NetworkStream(socket, ownsSocket: false))
			using (SslStream httpsStream = new SslStream(stream, leaveInnerStreamOpen: true))
			{
				httpsStream
					.AuthenticateAsClientAsync(
						uri.DnsSafeHost,
						new X509CertificateCollection(),
						SslProtocols.Tls | SslProtocols.Tls11 | SslProtocols.Tls12,
						checkCertificateRevocation: true)
						.Wait();

				Console.WriteLine("Success! Press a key to exit...");
				Console.ReadKey();
			}
		}

		private static void ConnectToDestination(Uri uri, Socket socket)
		{
			var sendBuffer = new ArraySegment<byte>(BuildConnectToUri(uri).Array);
			socket.Send(sendBuffer.Array, SocketFlags.None);
			var recBuffer = new byte[socket.ReceiveBufferSize];
			var recCnt = socket.Receive(recBuffer, SocketFlags.None);
			ValidateConnectToDestinationResponse(recBuffer, recCnt);
		}

		private static void ValidateConnectToDestinationResponse(byte[] receiveBuffer, int receiveCount)
		{
			if (receiveCount < 7)
			{
				throw new Exception($"The SOCKS5 proxy responded with {receiveCount} bytes to the connect request. At least 7 bytes are expected.");
			}

			byte version = receiveBuffer[0];
			if (version != SocksVersion)
			{
				throw new Exception($"The SOCKS5 proxy responded with 0x{version:x2}, instead of 0x{SocksVersion:x2}, for the SOCKS version number.");
			}
			if (receiveBuffer[1] != (byte)ReplyType.Succeeded)
			{
				throw new Exception($"The SOCKS5 proxy responded with a unsuccessful reply type '{(receiveBuffer[1] >= (byte)ReplyType.Unassigned ? ReplyType.Unassigned : (ReplyType)receiveBuffer[1])}' (0x{receiveBuffer[1]:x2}).");
			}
			if (receiveBuffer[2] != 0x00)
			{
				throw new Exception($"The SOCKS5 proxy responded with an unexpected reserved field value 0x{receiveBuffer[2]:x2}. 0x00 was expected.");
			}
			if (!Enum.GetValues(typeof(AddressType)).Cast<byte>().Contains(receiveBuffer[3]))
			{
				throw new Exception($"The SOCKS5 proxy responded with an unexpected {nameof(AddressType)} 0x{receiveBuffer[3]:x2}.");
			}

			var bindAddressType = (AddressType)receiveBuffer[3];
			if (bindAddressType == AddressType.IpV4)
			{
				if (receiveCount != 10)
				{
					throw new Exception($"The SOCKS5 proxy responded with an unexpected number of bytes ({receiveCount} bytes) when the address is an IPv4 address. 10 bytes were expected.");
				}

				IPAddress.NetworkToHostOrder(BitConverter.ToInt16(receiveBuffer, 8));
			}
			else if (bindAddressType == AddressType.DomainName)
			{
				byte bindAddressLength = receiveBuffer[4];
				Encoding.ASCII.GetString(receiveBuffer, 5, bindAddressLength);
				IPAddress.NetworkToHostOrder(BitConverter.ToInt16(receiveBuffer, 5 + bindAddressLength));
			}
			else if (bindAddressType == AddressType.IpV6)
			{
				if (receiveCount != 22)
				{
					throw new Exception($"The SOCKS5 proxy responded with an unexpected number of bytes ({receiveCount} bytes) when the address is an IPv6 address. 22 bytes were expected.");
				}

				IPAddress.NetworkToHostOrder(BitConverter.ToInt16(receiveBuffer, 20));
			}
			else
			{
				var addressTypeNotSupportedMessage = $"The provided address type '{bindAddressType}' is not supported.";
				throw new NotSupportedException(addressTypeNotSupportedMessage);
			}
		}

		private static ArraySegment<byte> BuildConnectToUri(Uri uri)
		{
			ArraySegment<byte> sendBuffer;
			int port = uri.Port;
			byte[] nameBytes = Encoding.ASCII.GetBytes(uri.DnsSafeHost);

			var addressBytes =
				Enumerable.Empty<byte>()
				.Concat(new[] { (byte)nameBytes.Length })
				.Concat(nameBytes).ToArray();

			sendBuffer =
				new ArraySegment<byte>(
					Enumerable.Empty<byte>()
					.Concat(
						new[]
						{
							SocksVersion, (byte) 0x01, (byte) 0x00, (byte) AddressType.DomainName
						})
						.Concat(addressBytes)
						.Concat(BitConverter.GetBytes(IPAddress.HostToNetworkOrder((short)port))).ToArray());
			return sendBuffer;
		}

		private static void HandshakeTor(Socket socket)
		{
			var sendBuffer = new byte[] { 5, 1, 0 };
			socket.Send(sendBuffer, SocketFlags.None);
			var recBuffer = new byte[socket.ReceiveBufferSize];
			var recCnt = socket.Receive(recBuffer, SocketFlags.None);
			ValidateHandshakeResponse(recBuffer, recCnt);
		}

		private static Socket ConnectToSocket(IPEndPoint endPoint)
		{
			var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
			{
				Blocking = true
			};
			socket.Connect(endPoint);
			return socket;
		}

		private static void ValidateHandshakeResponse(byte[] receiveBuffer, int receiveCount)
		{
			if (receiveCount != 2)
			{
				throw new Exception($"The SOCKS5 proxy responded with {receiveCount} bytes, instead of 2, during the handshake.");
			}

			byte version = receiveBuffer[0];
			if (version != SocksVersion)
			{
				throw new Exception($"The SOCKS5 proxy responded with 0x{version:x2}, instead of 0x{SocksVersion:x2}, for the SOCKS version number.");
			}

			if (receiveBuffer[1] == 0xFF)
			{
				throw new Exception("The SOCKS5 proxy does not support any of the client's authentication methods.");
			}
		}
	}
}