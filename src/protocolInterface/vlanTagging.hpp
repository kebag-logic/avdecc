/*
* Copyright (C) 2016-2026, L-Acoustics and its contributors

* This file is part of LA_avdecc.

* LA_avdecc is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.

* LA_avdecc is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU Lesser General Public License for more details.

* You should have received a copy of the GNU Lesser General Public License
* along with LA_avdecc.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
* @file vlanTagging.hpp
* @author Christophe Calmejane
* @brief IEEE 802.1Q / 802.1ad (Q-in-Q) tag stack codec for AVDECC control frames.
* @details AVDECC control traffic (EtherType 0x22f0) may reach the controller either untagged,
*          single tagged (802.1Q C-TAG) or double tagged (802.1ad S-TAG + C-TAG) depending on
*          how the switch port is configured and on whether the capture path preserved the tag.
*          This header provides the bounds-checked parsing and building primitives used by the
*          transport implementations so the Ethernet header length is computed instead of assumed.
*/

#pragma once

#include "la/avdecc/internals/protocolAvtpdu.hpp"
#include "la/avdecc/internals/protocolDefines.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace la
{
namespace avdecc
{
namespace protocol
{
namespace vlan
{
/** IEEE 802.1Q Customer VLAN tag TPID */
static constexpr std::uint16_t Tpid_CTag{ 0x8100 };
/** IEEE 802.1ad Service VLAN tag TPID */
static constexpr std::uint16_t Tpid_STag{ 0x88a8 };
/** Legacy (pre-802.1ad) vendor Service VLAN tag TPID, still emitted by some switches */
static constexpr std::uint16_t Tpid_Legacy{ 0x9100 };
/** Maximum supported tag stack depth (802.1ad Q-in-Q == 2) */
static constexpr std::size_t MaxTags{ 2u };
/** Length of a single VLAN tag (TPID + TCI) */
static constexpr std::size_t TagLength{ 4u };
/** Length of an untagged Ethernet II header, same value as EtherLayer2::HeaderLength */
static constexpr std::size_t UntaggedHeaderLength{ 14u };

static_assert(UntaggedHeaderLength == EtherLayer2::HeaderLength, "Untagged header length must track EtherLayer2::HeaderLength");

/** Returns true if the given halfword is a VLAN tag protocol identifier */
constexpr bool isTpid(std::uint16_t const value) noexcept
{
	return value == Tpid_CTag || value == Tpid_STag || value == Tpid_Legacy;
}

/** A single VLAN tag */
struct Tag
{
	std::uint16_t tpid{ Tpid_CTag };
	std::uint8_t pcp{ 0u }; /**< Priority Code Point [0..7] */
	bool dei{ false }; /**< Drop Eligible Indicator */
	std::uint16_t vid{ 0u }; /**< VLAN Identifier [0..4095] */

	/** Packs the Tag Control Information halfword */
	constexpr std::uint16_t tci() const noexcept
	{
		return static_cast<std::uint16_t>((static_cast<std::uint16_t>(pcp & 0x07u) << 13) | (dei ? 0x1000u : 0x0000u) | (vid & 0x0fffu));
	}
};

/** Result of parsing the Ethernet header of a received frame */
struct RxHeader
{
	std::size_t headerLength{ 0u }; /**< 14, 18 or 22 depending on the tag stack depth */
	std::uint16_t etherType{ 0u }; /**< The true (innermost) EtherType, never a TPID */
	std::uint8_t tagCount{ 0u };
	std::array<Tag, MaxTags> tags{};
};

/** Bounds-checked big-endian halfword read. Replaces unaligned type-punned loads. */
inline bool readUint16(std::uint8_t const* const data, std::size_t const size, std::size_t const offset, std::uint16_t& out) noexcept
{
	if (data == nullptr || offset + 2u > size)
	{
		return false;
	}
	out = static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[offset]) << 8) | data[offset + 1u]);
	return true;
}

/**
* @brief Parses DestAddress + SrcAddress + an optional VLAN tag stack + EtherType.
* @return true if a complete header followed by at least one payload byte was found.
* @details Returns false for runt frames, tag stacks deeper than MaxTags, truncated tags,
*          and frames carrying no payload. On success, headerLength is strictly lower than
*          size, which guarantees the caller's (size - headerLength) cannot underflow.
*/
inline bool parseHeader(std::uint8_t const* const data, std::size_t const size, RxHeader& out) noexcept
{
	if (data == nullptr || size < UntaggedHeaderLength)
	{
		return false;
	}

	auto offset = std::size_t{ 12u }; // Right after DestAddress + SrcAddress
	auto value = std::uint16_t{ 0u };

	out.tagCount = 0u;

	while (readUint16(data, size, offset, value) && isTpid(value))
	{
		if (out.tagCount >= MaxTags)
		{
			return false; // Tag stack deeper than 802.1ad Q-in-Q, not supported
		}
		auto tci = std::uint16_t{ 0u };
		if (!readUint16(data, size, offset + 2u, tci))
		{
			return false; // Truncated tag
		}
		out.tags[out.tagCount] = Tag{ value, static_cast<std::uint8_t>((tci >> 13) & 0x07u), (tci & 0x1000u) != 0u, static_cast<std::uint16_t>(tci & 0x0fffu) };
		++out.tagCount;
		offset += TagLength;
	}

	if (!readUint16(data, size, offset, out.etherType))
	{
		return false;
	}
	out.headerLength = offset + 2u;

	return size > out.headerLength;
}

/** Fills an EtherLayer2 from a parsed frame. DestAddress/SrcAddress live at offsets 0..11 whatever the tagging. */
inline void fillEtherLayer2(std::uint8_t const* const data, RxHeader const& header, EtherLayer2& etherLayer2) noexcept
{
	auto destAddress = networkInterface::MacAddress{};
	auto srcAddress = networkInterface::MacAddress{};

	std::memcpy(destAddress.data(), data, destAddress.size());
	std::memcpy(srcAddress.data(), data + destAddress.size(), srcAddress.size());

	etherLayer2.setDestAddress(destAddress);
	etherLayer2.setSrcAddress(srcAddress);
	etherLayer2.setEtherType(header.etherType); // The true EtherType, never a TPID
}

/**
* @brief Returns the pcap capture filter accepting AVDECC control frames, tagged or not.
* @details The untagged branch is intentionally identical to the historical filter so the
*          untagged code path keeps its exact previous behaviour. The tagged branches
*          additionally test the AVTP 'cd' bit (bit 7 of the first AVTPDU octet) so tagged
*          AVTP *media streams*, which share EtherType 0x22f0 and are the bulk of the traffic
*          on an AVB VLAN, are rejected in-kernel rather than copied and queued to be dropped
*          in userspace.
*
*          Do NOT express this with libpcap's 'vlan' keyword: it mutates a compile-global
*          offset that leaks rightward across 'or', so "A or (vlan and A) or (vlan and vlan
*          and A)" tests offsets 12/16/20 then 16/20/24, i.e. its last disjunct matches a
*          *triple* tagged frame and real Q-in-Q frames are silently dropped.
*
*          The parentheses around the '&' tests are required: pcap-filter operator precedence
*          does not bind '&' tighter than '!=', so "ether[18] & 0x80 != 0" does not parse as
*          intended.
*/
inline char const* captureFilter() noexcept
{
	static_assert(AvtpEtherType == 0x22f0, "Hardcoded EtherType literals below must track AvtpEtherType");
	static_assert(Tpid_CTag == 0x8100 && Tpid_STag == 0x88a8 && Tpid_Legacy == 0x9100, "Hardcoded TPID literals below must track the Tpid_* constants");
	static_assert(MaxTags == 2u, "Filter only covers a tag stack depth of at most 2");

	return "ether proto 0x22f0"
				 " or (ether[12:2]=0x8100 and ether[16:2]=0x22f0 and (ether[18] & 0x80) != 0)"
				 " or (ether[12:2]=0x88a8 and ether[16:2]=0x22f0 and (ether[18] & 0x80) != 0)"
				 " or (ether[12:2]=0x9100 and ether[16:2]=0x22f0 and (ether[18] & 0x80) != 0)"
				 " or ((ether[12:2]=0x8100 or ether[12:2]=0x88a8 or ether[12:2]=0x9100)"
				 " and (ether[16:2]=0x8100 or ether[16:2]=0x88a8 or ether[16:2]=0x9100)"
				 " and ether[20:2]=0x22f0 and (ether[22] & 0x80) != 0)";
}

/** The historical untagged-only capture filter, kept as a fallback for libpcap versions that cannot compile the above. */
inline char const* legacyCaptureFilter() noexcept
{
	static_assert(AvtpEtherType == 0x22f0, "Hardcoded EtherType literal below must track AvtpEtherType");

	return "ether proto 0x22f0";
}

} // namespace vlan
} // namespace protocol
} // namespace avdecc
} // namespace la
