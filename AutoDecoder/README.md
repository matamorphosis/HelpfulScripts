# Auto Decoder
This tool allows users to decode strings automatically. In the event you have a string with several layers of encoding, this tool can easily decode it as many times as necessary until it gets a cleartext string.

Supported Encoding Types Include:
- Base64
- Hex
- HTML
- URL
- Decimal
- Binary

Auto Decoder even handles events where a string is encoded in one method and re-encoded in another. As each time a layer is peeled off, the decoded text is re-checked against all encoding types again.
