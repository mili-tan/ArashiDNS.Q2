using System.Buffers;
using System.IO.Pipelines;
using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using ARSoft.Tools.Net.Dns;
using McMaster.Extensions.CommandLineUtils;

namespace ArashiDNS.QC2
{
    internal class Program
    {
        public static IPEndPoint ListenerEndPoint = new(IPAddress.Loopback, 25353);
        public static DnsEndPoint ServerEndPoint = new("example.com", 853);
        public static bool UseLog;

        static void Main(string[] args)
        {
            var cmd = new CommandLineApplication
            {
                Name = "ArashiDNS.QC2",
                Description = "ArashiDNS.QC2 - DNS over QUIC Client" +
                              Environment.NewLine +
                              $"Copyright (c) {DateTime.Now.Year} Milkey Tan. Code released under the MPL License"
            };
            cmd.HelpOption("-?|-h|--help");
            var isZh = Thread.CurrentThread.CurrentCulture.Name.Contains("zh");
            var serverArgument = cmd.Argument("target",
                isZh ? "目标 DNS over QUIC 端点" : "Target DNS over QUIC service endpoint");
            var ipOption = cmd.Option<string>("-l|--listen <IPEndPoint>",
                isZh ? "监听的地址与端口" : "Set server listening address and port", CommandOptionType.SingleValue);
            var logOption = cmd.Option("--log", isZh ? "打印查询与响应日志。" : "Print query and response logs",
                CommandOptionType.NoValue);

            cmd.OnExecute(() =>
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
                Console.WriteLine("\ud83d\udea7 Not working yet. Under Debugging. \ud83d\udea7");
                Console.WriteLine("ArashiDNS.QC2 - DNS over QUIC Client");
                Console.WriteLine("Now listening on: " + ListenerEndPoint);
                Console.WriteLine("The server is: " + ServerEndPoint);
                Console.WriteLine("Application started. Press Ctrl+C / q to shut down.");

                if (!Console.IsInputRedirected && Console.KeyAvailable)
                {
                    while (true)
                        if (Console.ReadKey().KeyChar == 'q')
                            Environment.Exit(0);
                }

                EventWaitHandle wait = new AutoResetEvent(false);
                while (true) wait.WaitOne();
            });

            cmd.Execute(args);
        }

        private static async Task DnsServerOnQueryReceived(object sender, QueryReceivedEventArgs e)
        {
            try
            {
                // 🚧 Not working yet. Under Debugging. 🚧
                if (e.Query is not DnsMessage query) return;
                var dnsBytes = query.Encode().ToArraySegment(false).ToArray();

                var connection = await QuicConnection.ConnectAsync(new QuicClientConnectionOptions
                {
                    DefaultCloseErrorCode = 0,
                    DefaultStreamErrorCode = 5,
                    RemoteEndPoint = ServerEndPoint,

                    ClientAuthenticationOptions = new SslClientAuthenticationOptions
                    {
                        ApplicationProtocols = new List<SslApplicationProtocol> {new SslApplicationProtocol("doq")},
                        CertificateRevocationCheckMode = X509RevocationMode.NoCheck, TargetHost = ServerEndPoint.Host,
                        //RemoteCertificateValidationCallback = (sender, certificate, chain, errors) => true
                    }
                });

                var stream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
                var writer = PipeWriter.Create(stream);
                var reader = PipeReader.Create(stream);
                writer.WriteAsync(dnsBytes);
                var result = await reader.ReadAsync();

                var answer = query.CreateResponseInstance();

                //foreach (var i in result.Buffer)
                //{
                //    Console.WriteLine(i.Length);
                //}
                //answer = DnsMessage.Parse(result.Buffer.First.ToArray());

                await reader.CompleteAsync();
                await writer.CompleteAsync();
                await connection.CloseAsync(0);
                e.Response = answer;

                if (UseLog) await Task.Run(() => PrintDnsMessage(answer));
            }
            catch (Exception exception)
            {
                Console.WriteLine(exception);
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
}
