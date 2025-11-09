# Protobuf Viewer -- Python GUI

A standalone, schema-less Protobuf decoding tool with a graphical
interface built using **PySide6**.\
Designed for forensic analysis, reverse engineering, education, and
debugging of Protobuf binary payloads --- even when no `.proto` schema
is available.

------------------------------------------------------------------------

## Authors

Marc Brandt\ mb4n6

------------------------------------------------------------------------

## Features

**Load raw binary files** or **paste hex input**\
Fully decode Protobuf wire format **without `.proto` definitions**\
Supports: - Varint (uint, sint via ZigZag decoding) - Fixed32
(uint32, float) - Fixed64 (uint64, double) - Length-delimited (string,
bytes, embedded message, packed repeated fields)

**Nested message detection** (recursive parsing)\
**Concatenated frame parsing** (optional)\
**Full ASCII view** for every field (no truncation)\
**Structured "Content" view** with interpreted values\
**Deep hex inspection** (offsets, full hex dump with ASCII)\
**Quick Hex View** for the whole input\
Built-in **Protobuf Primer** window --- ideal for teaching /
explaining Protobuf concepts\
Cross-platform: macOS, Linux, Windows

------------------------------------------------------------------------

## Installation

``` bash
pip install PySide6
```

------------------------------------------------------------------------

## Usage

``` bash
python protobuf_viewer_gui_v2.py
```

1.  Click **Open File...** or paste hex into the input pane\
2.  Click **Decode**\
3.  Inspect:
    -   Field numbers
    -   Wire types
    -   Byte ranges
    -   Full hex payload
    -   Full ASCII representation
    -   Interpreted values (uint, sint, float, double, UTF-8 string)
    -   Nested messages

------------------------------------------------------------------------

## Protobuf Primer (Integrated in the GUI)

The viewer includes an expandable built-in Protobuf explanation window
covering: - Protobuf wire format - Field key encoding
(`field_number << 3 | wire_type`) - Varint structure - ZigZag decoding -
Length-delimited payloads - Embedded messages - Packed repeated fields -
Frame concatenation - Forensic considerations & safety notes

------------------------------------------------------------------------

## License

MIT License.
