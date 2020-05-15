﻿using RotMG_Net_Lib.Crypto;
using RotMG_Net_Lib.Data;
using RotMG_Net_Lib.Networking.Packets;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using NLog;

namespace RotMG_Net_Lib.Networking
{
    public class NetClient
    {
        public static Logger Log = LogManager.GetCurrentClassLogger();

        private const int HeadSize = 5;

        public const string IncomingKey = "c79332b197f92ba85ed281a023";
        public const string OutgoingKey = "6a39570cc9de4ec71d64821894";

        private Socket _socket;
        private Thread _listener;
        private RC4 _incomingEncryption;
        private RC4 _outgoingEncryption;
        private Dictionary<PacketType, List<Action<IncomingPacket>>> _hooks = new Dictionary<PacketType, List<Action<IncomingPacket>>>();

        private List<Action<IncomingPacket>> _anyPacketHook = new List<Action<IncomingPacket>>();

        private Action _onConnect;
        private Action<DisconnectReason> _onDisconnect;

        public bool Disconnected = true;
        private readonly bool DebugPackets = false;

        public bool OnDisconnectHasBeenCalled;

        public void Connect(Reconnect reconnect)
        {
            OnDisconnectHasBeenCalled = false;

            _incomingEncryption = new RC4(IncomingKey);
            _outgoingEncryption = new RC4(OutgoingKey);

            try
            {
                Log.Info("Connecting no using proxy!");
                _socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
                _socket.Connect(new IPEndPoint(IPAddress.Parse(reconnect.Host), reconnect.Port));

                _socket.NoDelay = true;
                _socket.ReceiveTimeout = 5000;
                _socket.SendTimeout = 5000;
                Disconnected = false;
                Start();
                _onConnect?.Invoke();
            }
            catch (Exception e)
            {
                Log.Error("Disconnecting due to error : " + e.Message);
                Disconnect(DisconnectReason.ExceptionOnConnection.SetDetails(e.Message));
            }
        }

        public void AddConnectionListener(Action onConnect)
        {
            this._onConnect += onConnect;
        }

        public void AddDisconnectListener(Action<DisconnectReason> onDisconnect)
        {
            this._onDisconnect += onDisconnect;
        }

        public void HookAnyPacket(Action<IncomingPacket> action)
        {
            _anyPacketHook.Add(action);
        }

        public void Hook(PacketType type, Action<IncomingPacket> action)
        {
            if (!_hooks.ContainsKey(type))
            {
                _hooks[type] = new List<Action<IncomingPacket>>();
            }

            _hooks[type].Add(action);
        }

        private void Start()
        {
            try
            {
                (_listener = new Thread(Listen)).IsBackground = true;
                _listener.Start();
            }
            catch (Exception e)
            {
                Log.Error(e);
                Disconnect(DisconnectReason.ExceptionOnListenerStart.SetDetails(e.Message));
            }
        }

        private void Listen()
        {
            try
            {
                while (!Disconnected)
                {
                    byte[] head = new byte[HeadSize];

                    int received = 0;
                    while (received < head.Length)
                    {
                        int read = _socket.Receive(head, received, head.Length - received, SocketFlags.None);
                        if (read == 0)
                        {
                            // eof
                            Disconnect(DisconnectReason.EofHead.SetDetails("Read was 0."));
                            return;
                        }

                        received += read;
                    }

                    int size = IPAddress.NetworkToHostOrder(BitConverter.ToInt32(head, 0));
                    byte type = head[4];
                    ProcessPacket(type, size - 5);
                }
            }
            catch (Exception e)
            {
                Log.Debug(e);
                Disconnect(DisconnectReason.ExceptionOnListener.SetDetails(e.Message));
            }
        }

        private void ProcessPacket(byte type, int size)
        {
            try
            {
                byte[] buffer = new byte[size];
                int received = 0;
                while (received < size)
                {
                    int read = _socket.Receive(buffer, received, size - received, SocketFlags.None);
                    if (read == 0)
                    {
                        // eof
                        Disconnect(DisconnectReason.EofBody.SetDetails("Read was 0."));
                        return;
                    }

                    received += read;
                }

                _incomingEncryption.Cipher(buffer, 0);
                PacketType packetType = type.ToPacketType();

                if (packetType == PacketType.UNKNOWN)
                {
                    return;
                }

                IncomingPacket packet = IncomingPacket.Create(packetType);
                if (packet != null)
                {
                    MemoryStream ms = new MemoryStream(buffer);
                    using (PacketInput pi = new PacketInput(ms))
                    {
                        packet.Read(pi);

                        if (DebugPackets) Log.Info("Received " + packet.GetPacketType());
                    }

                    foreach (Action<IncomingPacket> action in _anyPacketHook)
                    {
                        action.Invoke(packet);
                    }

                    if (_hooks.ContainsKey(packetType))
                    {
                        foreach (var hook in _hooks[packetType].ToArray())
                        {
                            try
                            {
                                hook(packet);
                            }
                            catch (Exception e)
                            {
                                Log.Info(e);
                            }
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Disconnect(DisconnectReason.ExceptionOnProcessPacket.SetDetails(e.Message));
            }
        }

        public void SendPacket(OutgoingPacket packet)
        {
            if (_socket == null)
            {
                //Log.Error("Socket is null...");
                return;
            }

            if (!_socket.Connected)
            {
                //Log.Error("Socket is not connected.");
                return;
            }

            MemoryStream ms = new MemoryStream();
            using (PacketOutput output = new PacketOutput(ms))
            {
                output.Write(0);
                output.Write(packet.GetPacketType().ToId());
                packet.Write(output);

                if (DebugPackets) Log.Info("Sent " + packet.GetPacketType());
            }

            byte[] buffer = ms.ToArray();
            _outgoingEncryption.Cipher(buffer, 5);
            int size = buffer.Length;
            byte[] a = BitConverter.GetBytes(IPAddress.NetworkToHostOrder(size));
            buffer[0] = a[0];
            buffer[1] = a[1];
            buffer[2] = a[2];
            buffer[3] = a[3];
            _socket?.Send(buffer);
        }


        public void Disconnect(DisconnectReason reason)
        {
            if (!OnDisconnectHasBeenCalled)
            {
                OnDisconnectHasBeenCalled = true;
                _onDisconnect?.Invoke(reason);
            }

            if (!Disconnected)
            {
                Disconnected = true;
                _socket?.Close();
            }
        }

        public int GetTimer()
        {
            return (int) Environment.TickCount;
        }
    }
}