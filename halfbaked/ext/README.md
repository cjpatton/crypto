# Extensible protocols

Whenever a feature is added to TLS, it is specified as an RFC provide an [extension](https://tlswg.github.io/tls13-spec/draft-ietf-tls-tls13.html#rfc.section.4.2) to the handshake protocol. Extensions may add (trusted) third parties to the protocol.
  * The [visibility](https://tools.ietf.org/html/draft-rhrd-tls-tls13-visibility-00) extension, if adopted, will allow a third party access to the session ticket and thereby the ability to passively decrypt all traffic sent betwewen client and server. 
  * Cloudflare is working on an extension that would allow the server to _delegate credentials_ to a Cloudflare's edge. This would improve the latency of their [Keyless SSL service](https://www.cloudflare.com/ssl/keyless-ssl/) -- which costs a round trip between Cf and the server for signing -- but requires a stronger trust model. (The idea here is that the delegated credentials would only be valid for ~2 minutes at a time.)
  * The TLS 1.3 standard specifies a number of extensions. These impact things like forward secrecy.
  
The goal of this work is to provide a framework for analyzing extensible protocols. The steps are, roughly, as follows:
  1. Syntax of _extensible protocols_. The partially-specified protocol framework is a good place to start.
  2. Formalize the security goal of the _base protocol_. That is, what security should it provide on its own, no matter what extensions are provided?
  3. Formalize the security goal of the _extended protocool_.
  4. (Partially) specify the extension. Does the composition of the base protocol and the extension achieve the security goal of the extended protocol?
  5. An equally important question: does the extended protocol still meet the security goal of the base protocol?
