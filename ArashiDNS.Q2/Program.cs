﻿using ARSoft.Tools.Net.Dns;
using System.Net.Quic;
using System.Net.Security;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using McMaster.Extensions.CommandLineUtils;

namespace ArashiDNS.Q2
{
    internal class Program
    {
        public static IPEndPoint ListenerEndPoint = new(IPAddress.Any, 853);
        public static IPAddress UpStream = IPAddress.Parse("8.8.8.8");
        public static int Timeout = 1000;
        public static X509Certificate2Collection Certificate2Collection = new();

        private static readonly List<SslApplicationProtocol> QuicApplicationProtocols =
        [
            new SslApplicationProtocol("doq") //new SslApplicationProtocol("dq"),
            //new SslApplicationProtocol("dq-i02"), new SslApplicationProtocol("dq-i00")
        ];

        static async Task Main(string[] args)
        {
            var cmd = new CommandLineApplication
            {
                Name = "ArashiDNS.KS",
                Description = "ArashiDNS.KS - DNS over KCP Server" +
                              Environment.NewLine +
                              $"Copyright (c) {DateTime.Now.Year} Milkey Tan. Code released under the MPL License"
            };
            cmd.HelpOption("-?|-h|--help");
            var isZh = Thread.CurrentThread.CurrentCulture.Name.Contains("zh");
            var upArgument = cmd.Argument("target",
                isZh ? "目标上游 DNS 端点" : "Target upstream DNS service endpoint");
            var ipOption = cmd.Option<string>("-l|--listen <IPEndPoint>",
                isZh ? "监听的地址与端口" : "Set server listening address and port", CommandOptionType.SingleValue);
            var pemOption = cmd.Option<string>("-p|--pem <Path>",
                isZh ? "PEM 证书文件路径" : "PEM certificate file path", CommandOptionType.SingleValue);
            var keyOption = cmd.Option<string>("-k|--key <Path>",
                isZh ? "私钥文件路径" : "Private key file path", CommandOptionType.SingleValue);
            var wOption = cmd.Option<int>("-w <timeout>",
                isZh ? "等待回复的超时时间(毫秒)。" : "Timeout time to wait for reply", CommandOptionType.SingleValue);

            if (args.Any(x => x.StartsWith("--crts")))
            {
                foreach (var item in args.FirstOrDefault(x => x.StartsWith("--crts="))?.Split("=").LastOrDefault()?.Split(',')!)
                {
                    Certificate2Collection.Add(X509Certificate2.CreateFromPem(new HttpClient()
                        .GetStringAsync(item).Result));
                }
            }

            cmd.OnExecute(async () =>
            {
                if (upArgument.HasValue) UpStream = IPEndPoint.Parse(upArgument.Value!).Address;
                if (ipOption.HasValue()) ListenerEndPoint = IPEndPoint.Parse(ipOption.Value()!);
                if (wOption.HasValue()) Timeout = int.Parse(wOption.Value()!);

                var pem = await File.ReadAllTextAsync(pemOption.Value() ?? "crt.pem");
                var key = await File.ReadAllTextAsync(keyOption.Value() ?? "key.key");
                var cert = X509Certificate2.CreateFromPem(pem, key);

                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    cert = new X509Certificate2(cert.Export(X509ContentType.Pfx), (string?)null, X509KeyStorageFlags.Exportable);

                var sslOptions = new SslServerAuthenticationOptions()
                {
                    ApplicationProtocols = QuicApplicationProtocols,
                    ServerCertificateContext = SslStreamCertificateContext.Create(cert, Certificate2Collection),
                    ClientCertificateRequired = false,
                };
                var listenerOptions = new QuicListenerOptions()
                {
                    ListenEndPoint = ListenerEndPoint,
                    ListenBacklog = 100,
                    ApplicationProtocols = QuicApplicationProtocols,
                    ConnectionOptionsCallback = delegate
                    {
                        var serverConnectionOptions = new QuicServerConnectionOptions()
                        {
                            DefaultCloseErrorCode = 0,
                            DefaultStreamErrorCode = 5,
                            MaxInboundUnidirectionalStreams = 0,
                            MaxInboundBidirectionalStreams = 100,
                            IdleTimeout = TimeSpan.FromMilliseconds(1000),
                            ServerAuthenticationOptions = sslOptions
                        };
                        return ValueTask.FromResult(serverConnectionOptions);
                    }
                };

                var listener = await QuicListener.ListenAsync(listenerOptions);
                for (var i = 0; i < 4; i++) await Task.Factory.StartNew(() => AcceptQuicConnection(listener));
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

        static async Task AcceptQuicConnection(QuicListener quicListener)
        {
            try
            {
                while (true)
                {
                    try
                    {
                        var connection = await quicListener.AcceptConnectionAsync();
                        _ = Task.Run(async () =>
                        {
                            while (true)
                            {
                                var stream = await connection.AcceptInboundStreamAsync();
                                _ = HandleQuicStreamRequest(stream);
                            }
                        });
                    }
                    catch (QuicException ex)
                    {
                        switch (ex.QuicError)
                        {
                            case QuicError.ConnectionIdle:
                            case QuicError.InternalError:
                            case QuicError.ConnectionAborted:
                            case QuicError.ConnectionTimeout:
                                break;

                            default:
                                Console.WriteLine(ex);
                                break;
                        }
                    }
                    catch (ObjectDisposedException)
                    {
                        // ignore
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
        }

        private static async Task HandleQuicStreamRequest(QuicStream stream)
        {
            var qBytes = new byte[512];
            byte additional = 0;
            try
            {
                stream.ReadTimeout = 500;

                var len = await stream.ReadAsync(qBytes);
                if (len == 0) return;

                var qListBytes = qBytes.Take(len).ToList();
                if (qListBytes[1] != 0)
                {
                    additional = qListBytes[1];
                    qListBytes.RemoveRange(0, 2);
                }

                qBytes = qListBytes.ToArray();
                var query = DnsMessage.Parse(qBytes);

                //Console.WriteLine(BitConverter.ToString(qBytes));
                //Console.WriteLine(host + ":" + query.Questions.First());

                if (query.IsEDnsEnabled)
                    query.EDnsOptions?.Options.RemoveAll(x => x.Type != EDnsOptionType.ClientSubnet);

                stream.WriteTimeout = 500;
                var response = await new DnsClient(UpStream, Timeout).SendMessageAsync(query);

                if (response != null)
                {
                    response.IsRecursionAllowed = true;
                    response.IsRecursionDesired = true;
                    response.IsTruncated = false;
                    response.IsQuery = false;
                    response.IsEDnsEnabled = false;
                    response.EDnsOptions?.Options.Clear();
                    response.AdditionalRecords.Clear();
                    response.TransactionID = query.TransactionID;
                }
                else
                {
                    response = query.CreateResponseInstance();
                    response.ReturnCode = ReturnCode.ServerFailure;
                }

                var bytes = response.Encode().ToArraySegment(false).ToList();
                if (additional != 0) bytes.InsertRange(0, new byte[] { 0x00, additional });
                await stream.WriteAsync(bytes.ToArray());
            }
            catch (IOException)
            {
                //ignore
            }
            catch (Exception ex)
            {
                Console.WriteLine(Convert.ToBase64String(qBytes));
                Console.WriteLine(ex);
            }
            finally
            {
                //quicStream.Close();
                await stream.DisposeAsync();
            }
        }
    }
}