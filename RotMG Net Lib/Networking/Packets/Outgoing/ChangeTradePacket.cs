﻿namespace RotMG_Net_Lib.Networking.Packets.Outgoing
{
    public class ChangeTradePacket : OutgoingPacket
    {
        public bool[] Offer;

        public override PacketType GetPacketType() => PacketType.CHANGETRADE;

        public override void Write(PacketOutput output)
        {
            output.Write((short) Offer.Length);
            foreach (var slot in Offer)
                output.Write(slot);
        }
    }
}