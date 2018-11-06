# JA3

JA3 is a technique developed by Salesforce, to fingerprint TLS Client Hellos.
the official python implementation can be found here: https://github.com/salesforce/ja3

This package provides a pure golang implementation.

JA3 gathers the decimal values of the bytes for the following fields; SSL Version, Accepted Ciphers, List of Extensions, Elliptic Curves, and Elliptic Curve Formats.

It then concatenates those values together in order, using a “,” to delimit each field and a “-” to delimit each value in each field.

**The field order is as follows:**

SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats

**Example:**

    769,47–53–5–10–49161–49162–49171–49172–50–56–19–4,0–10–11,23–24–25,0

If there are no SSL Extensions in the Client Hello, the fields are left empty.

**Example:**

    769,4–5–10–9–100–98–3–6–19–18–99,,,

These strings are then MD5 hashed to produce an easily consumable and shareable 32 character fingerprint. This is the JA3 SSL Client Fingerprint.