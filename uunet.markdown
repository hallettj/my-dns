A secure decentralized domain name system
=========================================

There have been numerous attempts to design a decentralized domain
system.  The central problem that each design attempts to address is
that of determining the authoritative owner of a name without a central
authority.  This system addresses that problem by including a
universally unique string as a component in each domain name combined
with a cryptographic signature on each name record.


Rationale
---------

In 2011 the United States Congress came close to passing the [Stop Online
Piracy ACT][SOPA], a bill that presented dramatic implications for
online censorship.  SOPA included provisions for effectively taking web
sites offline by targeting two pieces if internet infrastructure: search
engines and the Domain Name System.  Unlike TCP/IP, web servers, email
and so forth, these two systems rely on central control - which makes
them relatively easy to manipulate.

[SOPA]: http://en.wikipedia.org/wiki/SOPA

In some parts of the world government interference in the domain name
system is not just a hypothetical problem.  China maintains [an
extensive DNS injection system][Internet Censorship by DNS Injection]
that affects virtually every internet user in the country.  YouTube has
been [blocked by over a dozen countries][Censorship of YouTube] at
different times.  At least some of those countries (e.g. Turkey) used
DNS manipulation to block the site.

[Internet Censorship by DNS Injection]: http://conferences.sigcomm.org/sigcomm/2012/paper/ccr-paper266.pdf
[Censorship of YouTube]: http://en.wikipedia.org/wiki/Censorship_of_YouTube

The Domain Name System does a fantastic job powering the internet; as it
has done for the last 30 years.  But its centralized nature makes the
system a weak link when faced with censorship.  An alternative,
decentralized option could provide additional protection for freedom of
expression.

What scares me the most is that, if I understand correctly and if SOPA
had passed it would not be legal for me to publish this document.  It
would have become a felony to distribute any information on how to
bypass blocks placed by SOPA provisions.  Working on a decentralized
domain name system is a way for me to affirm my right to do so, to get
the system ready while it is legal to do so in case it is ever needed in
the US, and to try to provide better tools to people currently living
with censorship.


Overview
--------

To achieve decentralization domain name records can be placed in a
distributed hash table (DHT), such as [Kademlia][].  To resolve the
address associated with a name a client computes a hash of the name and
uses that hash as a key to retrieve a name record from the DHT.

[Kademlia]: http://en.wikipedia.org/wiki/Kademlia

BitTorrent and some other filesharing protocols use a DHT to distribute
metadata on shared files via [magnet links][].  These and other use
cases demonstrate that DHTs work in the real world.

[magnet links]: http://en.wikipedia.org/wiki/Magnet_URI_scheme

Publishing information about domain names is the easy part.  The hard
part is verifying that the client has received an authentic name record.
My proposal is that every name record be cryptographically signed by a
private key owned by the owner of the domain names described by that
record.  To verify that the key used to sign a record is valid, the
fingerpint of the matching pubic key is included as a component in each
domain name.

Consider an example of a traditional domain name: `example.com.`  An
analogous name in this decentralized system would be of the form
`example.gtd57g70hq521uyrd5w6qzcn9tkafpz.uu.`  The second-to-last
component of that name is a Base36 encoding of a SHA1 hash of a public
key.  The TLD indicates that the name should be resolved by this
decentralized system

The corresponding name record includes the full public key, information
about addresses associated with the domain name, and a cryptographic
signature of the record content that can be verified using the given
key.

To resolve an address given a domain name, a client looks up a name
record from the DHT using a hash of the name.  The client takes a hash
of the public key in the record to verify that it matches the
fingerprint in the domain name.  The client also verifies the
cryptographic signature in the record.  Finally, the client inspects the
record content for the desired information.

This scheme is intended to maximize compatibility with existing DNS
implementations.  Base36 is a case-insensitive encoding for binary data.
Since domain names are not supposed to be case sensitive, according to
[RFC-1035][], this encoding works well for a string that appears in a
domain name.  The encoding also produces characters that are safe to use
in a domain name, again according to RFC-1035.  A traditional domain
name is limited to 255 bytes, including dots.  A decentralized address
constructed with the same limit would use about 32 characters/bytes for
the key fingerprint, leaving about 223 bytes for the name proper.

[RFC-1035]: https://www.ietf.org/rfc/rfc1035.txt

A domain name with a 30 character hash in it may seem unwieldly.  It is
unlikely that anyone would memorize such a name.  And it would be
awkward to communicate an address with a name like this in print or over
the phone.  But consider that these days many URLs are exchanged purely
digitally.  It is no more difficult to copy and paste a 30 character
hash than any other string.  And we have QR codes for exchanging lengthy
URLs in the physical world.  It seems silly to use a QR code to
communicate a URL like [`www.bbc.co.uk`][BBC QR].  If you want to
communicate a URL that contains a 30 character hash you would actually
have a good excuse.

[BBC QR]: http://2d-code.co.uk/bbc-logo-in-qr-code/

Updating a large number of clients to support a new decentralized domain
name system would be a long and painful process.  Bridge servers can be
deployed to accomodate existing client applications and operating
systems.  Bridge servers accept traditional DNS queries, look up the
appropriate response in the DHT, and send that response in a traditional
DNS format.  Bridge servers should perform traditional DNS lookups for
queries regarding domain names that do not use the decentralized TLD.


Specification
-------------

The details of this specification are mostly speculative at this point.
There will be changes based on feedback and based on lessons learned
while creating reference implementations.

Until such time as a proper name for this specification is selected, it
will be referred to here as "DDNS".


### format for domain names

A DDNS domain name is based on the specification in [RFC-1035][], with
the added requirements that the TLD of the name must be "uu" and that
the second-to-last component of the name must be a fingerprint of a
public key.

For example:

    www.example.gtd57g70hq521uyrd5w6qzcn9tkafpz.uu.
    \-/ \-----/ \-----------------------------/ \/
     |     |                   |                |
     |   domain            fingerprint         TLD
     |
    subdomain


The fingerprint is computed as follows:

1. take the binary representation of a public key belonging to the owner
of the name
2. compute the SHA1 hash of the key
3. produce the Base36 representation of the hash value

_TODO: Is SHA1 the right hash function to use?  Would SHA256 be better?
Should the system support a selection of hash functions?  If so, how is
the chosen hash function expressed?  That information could be included
as part of the name record - it does not have to be expressed in the
domain name itself._

_TODO: In some cases Base36 encoding will result in a digit rather than
an alphabetical character as the first character in the encoded string.
RFC-1035 specifies that digits are allowed in domain names, but that the
first character in each component should be an alphabetical character.
What to do about this?_

When constructing a domain name, a truncated version of the public key
hash may be used.  In this case the fingerprint is computed by following
the above three steps and then removing any number of characters from
the end of the Base36-encoded string.  A fingerprint must contain at
least one character.  Domain name publishers should be aware that the
shorter the fingerprint, the easier it is for a malicious party to forge
an apparently valid record for the domain name.

Example of a domain name with a truncated fingerprint:

    www.example.gtd57g70hq.uu.
    \-/ \-----/ \--------/ \/
     |     |        |      |
     |   domain     |     TLD
     |              |
    subdomain   fingerprint

_TODO: Establish a reccomendation for the minimum number of characters to
use in a fingerprint_


### resolving an address

To resolve an address given a DDNS domain name the client follows these
steps:

1. Compute a hash of the last three components of the name, including
dots between them.  For example, given the name
`www.example.gtd57g70hq.uu` the client computes a hash of the string
`"example.gtd57g70hq.uu"`.
2. Use the resulting hash to perform a DHT lookup.
3. If a record is found, verify it according to the *verifying a domain
name record* section below.
4. Parse the domain name information in the record and pull out the
value given for the desired name, record class, and record type.  E.g.,
`www.example.gtd57g70hq.uu`, `IN`, `A`


### format for domain name records

A domain name record is a piece of data that is stored in the DHT.  When
resolving a DDNS domain name a client will compute a hash of the name
and will use that hash as a key in a DHT lookup.  The data that is
returned should be a name record with details on the given domain name.

A name record is a [BSON][] data structure.  Each record must contain
the following fields:

- `"k"`, a byte array representing a public key
- `"m"`, a byte array containing domain name information
- `"s"`, a byte array containing a cryptographic signature of `"m"` that
  can be verified with `"k"`

[BSON]: http://bsonspec.org/

_TODO: The following fields may be desirable:_

- _`"a"`, string indicating the encryption algorithm that the public key
  is based on (e.g., `"rsa"` or `"dsa"`)_
- _`"t"`, string representing the document type (if the DHT is allowed to
  store documents other than domain name records)_
- _`"h"`, string indicating the hash algorithm used to compute the public
  key fingerprint (e.g. `"sha1"` or `"sha256"`)_

_TODO: BSON may or may not be the best choice of format.  Further study
is warranted_

_TODO: BSON uses little-endian encoding, but DNS uses big-endian.  That
could become confusing really fast._

`"m"` should be a message, as specified by [RFC-1035][].  Information
about domain names should be expressed as entries in the answer section
of the message.

_TODO: Using the RFC-1035 message format may waste about 80 bits of
space.  We might be able to get away with using just the ANCOUNT field
of the message header._

A name record is stored in the DHT under one or more keys such that a
client can retrieve the record given only a domain name.  More than one
key may be required if the record provides information on more than one
domain name.

Since lookups are based on the last three components of a domain name,
the publisher of a domain name should take the last three components of
each domain name mentioned in the record, take hashes of each unique
value, and store the record under each resulting hash.

_TODO: Allow subdomains to be delegated to distinct records?_

_TODO: Should separate name records be required for each type and class
pairing?  For example, should A, MX, and TXT information be stored in
separate records?  If so DHT keys would be computed as a hash of a
concatenation of domain name, class, and type instead of just a hash of
a domain name._


### verifying a domain name record

Assuming that a client is in the process of resolving a given domain
name, upon retrieving a corresponding name record from the DHT the
client should verify the authenticity of the record by following these
steps:

1. Parse the top-level fields of the record to extract the public key,
the binary content, and the cryptographic signature of the binary
content.
2. Compute a fingerprint of the public key provided by the name record.
For this verification step the fingerprint must not be truncated.
3. Compare the computed fingerprint to the fingerprint parsed from the
given domain name using a string prefix match.  If the parsed
fingerprint is a prefix of the computed fingerprint then the
fingerprints match.  If the fingerprints do not match then the record
should be rejected as not authentic.
4. Compute a hash of the record content.
5. Decrypt the given cryptographic signature using the public key
provided by the record.
6. Compare the decrypted signature to the computed content hash.  If
these values match, and the fingerprints matched, then the record should
be considered authentic.  Otherwise the record should be rejected as not
authentic.

_TODO: Reference the appropriate specification for computing a
cryptographic signature._

The client may present a warning to the user if the fingerprint in the
given domain name is truncated to a value below a threshold determined
by the client.  This is to make the user aware that the resolved address
of a name should not be trusted if the fingerprint is too short.

DDNS clients that the user interacts with directly, such as web
browsers, are advised to apply a trust on first use (TOFU) policy.  Upon
visiting a resource via a DDNS host the client may present a warning to
the user if the user has not visited that host before.  If the user has
not visited that host but has visited a host with a similar name, for
example if the name is the same except for the fingerprint, then a
stronger warning is advised.

_TODO: Talk about visualizations for fingerprints that could help users
to notice when visiting a site with the wrong fingerprint._


### distributed hash table protocol

The distributed hash table used with this specification is based on
[Kademlia][].  There is [a nice description][BitTorrent DHT] of
BitTorrent's implementation of a Kademlia-based on the BitTorrent blog.

[BitTorrent DHT]: http://www.bittorrent.org/beps/bep_0005.html

The specification for the DDNS DHT protocol needs to be worked out in
detail.  For now it should roughly match the BitTorrent DHT with the
additional requirements:

1. Before storing a record a peer should verify that the cryptographic
signature provided by the record is valid.
2. Before storing a record a peer should verify that the fingerprints in
domain names described in the record match the public key in the record.

_TODO: If the DHT is allowed to store multiple types of documents then
the peer will have to check the document type before performing the
second verification step._

The implication of verification step 2 is that if a domain name record
provides information on multiple domain names, every name in the record
must have matching fingerprints.

A bridge server, a server that provides information from the DHT in
response to traditional DNS queries, should operate as a DHT node
itself.  That is, clients wishing to join the DHT should be able to do
so by sending a `get_peers` message to the bridge server.

_TODO: Should bridge servers accept DHT messages on a canonical port?  If
so, what port should that be?_


Outstanding questions
---------------------

Can DHT requests and responses be encrypted?  Without encryption the
system will be vulnerable to deep packet inspection (DPI).  Iran notably
uses DPI to filter traffic and other countries have used similar
techniques.  In the US Comcast has used DPI to block BitTorrent traffic
on its networks.

The go-to encryption solution, TLS, requires TCP connections.  But DHT
messages are generally handled with UDP to keep latency low.  DHT nodes
could be required to support TCP connections in addition to UDP
messages.  Another option might be to devise some scheme to disguise DHT
messages as something innocuous.  A secondary measure might be to allow
the DHT to be replicated for transportation on a USB stick, or to
operate redundantly within an isolated network.

It might be a good idea to support signing chains.  In that case the
fingerprint in a domain name would correspond to an ultimately trusted
key.  The content of the name record may be signed by a different key,
that is itself signed by the ultimately trusted key or that is in a
signing chain with the ultimately trusted key at the root of the chain.
There must be some mechanism to allow the client to access all of the
keys in the chain.
