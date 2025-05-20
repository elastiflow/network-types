/// IPv6 extension header types.
/// <https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml>
/// <https://www.rfc-editor.org/rfc/rfc9740.html>
#[repr(u8)]
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub enum Ipv6ExtHdrType {
    /// Destination Options for IPv6
    /// Note: Shares the same structure as HopOpt, can use the HopOpt struct
    Dst = 60,
    /// IPv6 Hop-by-Hop Options
    HopOpt = 0,
    /// No Next Header for IPv6
    NoNxt = 59,
    /// Unknown extension or transport header
    /// Note: Using 255 (Reserved) as a placeholder value
    Unk = 255,
    /// Fragment header
    /// Note: Both first and non-first fragments use the same protocol number (44)
    /// but are treated differently in RFC9740
    Fragment = 44,
    /// Routing header
    Ipv6Route = 43,
    /// Mobility Header
    MobilityHdr = 135,
    /// Encapsulating Security Payload
    Esp = 50,
    /// Authentication Header
    AuthHdr = 51,
    /// Host Identity Protocol
    HipHdr = 139,
    /// Shim6 Protocol
    Shim6Hdr = 140,
}

// Existing implementations:
// - hop_opt.rs: Hop-by-Hop Options (HopOpt)
// - fragment.rs: Fragment header (Fragment) - handles both first and non-first fragments
// - ipv6_route.rs: Routing header (Ipv6Route)
// - mobility.rs: Mobility Header (MobilityHdr)
// - esp.rs: Encapsulating Security Payload (Esp)
// - ah.rs: Authentication Header (AuthHdr)
// - shim6.rs: Shim6 Protocol (Shim6Hdr)
// - hip.rs: HIP Protocol (HipHdr)
