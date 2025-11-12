using ARSoft.Tools.Net.Dns;
using McMaster.Extensions.CommandLineUtils;
using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Runtime.Versioning;
using DeepCloner.Core;

[assembly: RequiresPreviewFeatures]
namespace ArashiDNS.QC2
{
    internal class Program
    {
        public static IPEndPoint ListenerEndPoint = new(IPAddress.Loopback, 25353);
        public static DnsEndPoint ServerEndPoint = new("dns.alidns.com", 853);
        public static bool UseLog;

        static void Main(string[] args)
        {
            var cmd = new CommandLineApplication
            {
                Name = "ArashiDNS.QC2",
                Description = "ArashiDNS.QC2 - DNS over QUIC Client" +
                              Environment.NewLine +
                              $"Copyright (c) {DateTime.Now.Year} Milkey Tan. Code released under the MIT License"
            };
            cmd.HelpOption("-?|-h|--help");
            var isZh = Thread.CurrentThread.CurrentCulture.Name.Contains("zh");
            var serverArgument = cmd.Argument("target",
                isZh ? "目标 DNS over QUIC 端点" : "Target DNS over QUIC service endpoint");
            var ipOption = cmd.Option<string>("-l|--listen <IPEndPoint>",
                isZh ? "监听的地址与端口" : "Set server listening address and port", CommandOptionType.SingleValue);
            var logOption = cmd.Option("--log", isZh ? "打印查询与响应日志" : "Print query and response logs",
                CommandOptionType.NoValue);

            cmd.OnExecute(async () =>
            {
                if (serverArgument.HasValue)
                {
                    var uri = new Uri(serverArgument.Value!);
                    ServerEndPoint = new DnsEndPoint(uri.Host, uri.Port == 0 ? 853 : uri.Port);
                }

                if (ipOption.HasValue()) ListenerEndPoint = IPEndPoint.Parse(ipOption.Value()!);
                if (logOption.HasValue()) UseLog = true;

                var dnsServer = new DnsServer(new UdpServerTransport(ListenerEndPoint),
                    new TcpServerTransport(ListenerEndPoint));
                dnsServer.QueryReceived += DnsServerOnQueryReceived;
                dnsServer.Start();

                Console.WriteLine("ArashiDNS.QC2 - DNS over QUIC Client");
                Console.WriteLine("Now listening on: " + ListenerEndPoint);
                Console.WriteLine("The server is: " + ServerEndPoint);
                Console.WriteLine("Application started. Press Ctrl+C / q to shut down.");

                if (!Console.IsInputRedirected)
                    while (true)
                        if (Console.ReadKey(true).KeyChar == 'q')
                            Environment.Exit(0);

                EventWaitHandle wait = new AutoResetEvent(false);
                while (true) wait.WaitOne();
            });

            cmd.Execute(args);
        }

        private static async Task DnsServerOnQueryReceived(object sender, QueryReceivedEventArgs e)
        {
            try
            {
                if (e.Query is not DnsMessage query) return;
                var id = query.TransactionID.DeepClone();

                using var client = new DoQClient.DoQClient(ServerEndPoint.Host, ServerEndPoint.Port);
                var answer = await client.QueryAsync(query);
                if (answer != null)
                {
                    answer.TransactionID = id;
                    e.Response = answer;
                    if (UseLog) await Task.Run(() => PrintDnsMessage(answer));
                }
            }
            catch (QuicException qex)
            {
                Console.WriteLine($"QUIC error: {qex.Message}");
            }
            catch (Exception exception)
            {
                Console.WriteLine($"General error: {exception}");
            }
        }

        public static void PrintDnsMessage(DnsMessage message)
        {
            Console.Write($"Q: {message.Questions.FirstOrDefault()} ");
            Console.Write($"R: {message.ReturnCode} ");
            foreach (var item in message.AnswerRecords) Console.Write($"A:{item} ");
            Console.Write(Environment.NewLine);
        }
    }

    namespace DoQClient
    {
        public class DoQClient : IDisposable
        {
            private QuicConnection? connection;

            private readonly IPEndPoint serverEndPoint;
            private readonly SslClientAuthenticationOptions sslOptions;
            private static IPAddress[]? serverAddresses;

            public DoQClient(string serverHost, int serverPort = 853)
            {
                serverHost = serverHost ?? throw new ArgumentNullException(nameof(serverHost));

                serverAddresses ??= Dns.GetHostAddresses(serverHost);
                if (serverAddresses.Length == 0)
                    throw new ArgumentException($"Unable to resolve host: {serverHost}");

                serverEndPoint = new IPEndPoint(serverAddresses[0], serverPort);

                sslOptions = new SslClientAuthenticationOptions
                {
                    ApplicationProtocols = [new SslApplicationProtocol("doq")],
                    TargetHost = serverHost,
                    //RemoteCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) =>
                    //{
                    //    return true; // 暂时接受所有证书
                    //}
                };
            }

            public async Task<DnsMessage?> QueryAsync(DnsMessage query, CancellationToken cancellationToken = default)
            {
                await EnsureConnectedAsync(cancellationToken);

                if (connection == null)
                    throw new InvalidOperationException("QUIC Connection not established");

                query.TransactionID = 0;

                await using var stream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional, cancellationToken);
                var queryData = SerializeDnsMessageWithLength(query);

                await stream.WriteAsync(queryData, cancellationToken);
                stream.CompleteWrites();

                var responseData = await ReadDnsMessageFromStream(stream, cancellationToken);

                return responseData != null ? DnsMessage.Parse(responseData) : null;
            }

            private async Task EnsureConnectedAsync(CancellationToken cancellationToken)
            {
                try
                {
                    if (connection != null)
                    {
                        await connection.DisposeAsync();
                        connection = null;
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }

                connection ??= await QuicConnection.ConnectAsync(new QuicClientConnectionOptions
                {
                    DefaultStreamErrorCode = 0x2, // DOQ_PROTOCOL_ERROR
                    DefaultCloseErrorCode = 0x2,
                    RemoteEndPoint = serverEndPoint,
                    ClientAuthenticationOptions = sslOptions
                }, cancellationToken);
            }

            private byte[] SerializeDnsMessageWithLength(DnsMessage message)
            {
                var messageData = message.Encode().ToArraySegment(false).ToArray();
                var result = new byte[messageData.Length + 2];

                result[0] = (byte)(messageData.Length >> 8);
                result[1] = (byte)messageData.Length;
                Buffer.BlockCopy(messageData, 0, result, 2, messageData.Length);

                return result;
            }

            private async Task<byte[]?> ReadDnsMessageFromStream(QuicStream stream, CancellationToken cancellationToken)
            {
                var lengthBuffer = new byte[2];
                var bytesRead = await stream.ReadAsync(lengthBuffer, 0, 2, cancellationToken);

                if (bytesRead != 2) return null;

                var messageLength = (ushort)((lengthBuffer[0] << 8) | lengthBuffer[1]);

                if (messageLength == 0) return null;

                var messageBuffer = new byte[messageLength];
                bytesRead = 0;

                while (bytesRead < messageLength)
                {
                    var chunk = await stream.ReadAsync(messageBuffer, bytesRead, messageLength - bytesRead, cancellationToken);
                    if (chunk == 0) break;

                    bytesRead += chunk;
                }

                return bytesRead != messageLength ? null : messageBuffer;
            }

            public void Dispose()
            {
                connection?.DisposeAsync();
            }
        }
    }
}