﻿namespace RotMG_Net_Lib.Networking.Packets.Outgoing
{
    public class UsePortalPacket : OutgoingPacket
    {
        public int ObjectId;

        public override PacketType GetPacketType() => PacketType.USEPORTAL;

        public override void Write(PacketOutput output)
        {
            output.Write(ObjectId);
        }
    }
}