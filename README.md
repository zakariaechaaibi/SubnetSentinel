# SubnetSentinel — IPv4 Subnet Analyzer

An interactive, cybersecurity-themed IPv4 subnetting tool that runs entirely in the browser.
No frameworks, no dependencies, no data leaves your machine.

## Features

- **Flexible input:** `192.168.1.10/24`, `10.0.0.1/255.255.0.0` or `10.0.0.1 255.255.0.0`
- **Full network breakdown:** network, broadcast, mask, wildcard, first/last host, usable hosts, class
- **Binary view:** network bits and host bits colour-coded so the maths is visible
- **Threat intel panel:** classifies the range (RFC 1918, CGNAT, loopback, link-local, TEST-NET, multicast, public), explains its security relevance, and suggests `nmap` commands with a sweep-time estimate
- **Subnet splitter:** divide any network into smaller subnets with full host ranges
- **Edge cases handled:** `/31` point-to-point links (RFC 3021) and `/32` single hosts
- **Click-to-copy** on every value, with input validation and clear error messages

## Run it

No install or build step:

```bash
# Option 1: just open the file
open index.html            # macOS  (Linux: xdg-open, Windows: start)

# Option 2: serve locally
python3 -m http.server 8000   # then visit http://localhost:8000
```

## Usage

1. Type an address with a prefix or mask and press **Enter** (or click **ANALYZE**), or pick an example chip.
2. Click any result card to copy its value.
3. In **Subnet Splitter**, change the prefix (e.g. `/26`) to see every resulting subnet.

## Project structure

```
subnet-sentinel/
├── index.html        # page markup
├── css/
│   └── style.css     # dark SOC-terminal theme (colours are CSS variables)
├── js/
│   ├── subnet.js     # pure IPv4 maths engine (no DOM, easy to test)
│   └── ui.js         # input handling and rendering
└── README.md
```

The engine and UI are deliberately separated: `subnet.js` has no DOM access, so it can be tested
in Node or the browser console, e.g. `Subnet.calc(Subnet.parse('10.1.2.3/20').ip, 20)`.

## How the maths works

All addresses are treated as unsigned 32-bit integers and manipulated with bitwise operators:

| Value | Formula |
|-------|---------|
| Mask | `(0xFFFFFFFF << (32 - prefix)) >>> 0` |
| Wildcard | `~mask` |
| Network | `ip AND mask` |
| Broadcast | `network OR wildcard` |
| Usable hosts | `2^(32 - prefix) - 2` (special cases for `/31`, `/32`) |

Mask validation rejects non-contiguous masks such as `255.0.255.0`.

## Security note

The `nmap` suggestions and sweep estimates are for **authorized testing only**. Scanning networks you
do not own or have written permission to test may be illegal. Use the documentation ranges
(`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) for examples and reports.

## Roadmap

- [ ] VLSM planner (allocate subnets from host requirements)
- [ ] IPv6 support
- [ ] Supernetting / route summarisation
- [ ] Export results to CSV / JSON



## License

MIT

