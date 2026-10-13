# Protocol Verification — Plugin vs. native SDK decompilation

This integration's protocol was originally reverse-engineered from live traffic
(Frida SSL hooks + HTTP replay). It has since been **cross-checked against a full
decompilation** of the two native libraries shipped in the Balter EVO 2 Android
app (`de.balter.evo.two` v1.8):

- `libqv-p2p-v2.so` — Quvii/`tdkcloud` P2P SDK (`p2p_sdk_app_3.2.5`)
- `liblive_player.so` — media/transparent-command layer

Decompiler: Ghidra 12.1.4 (headless), 52 009 functions, 0 failures.

## Verified matches

| Element | Plugin | Native evidence | Result |
|---|---|---|---|
| Discovery envelope | `_mst_query` → `<flag>tdkcloud</flag><command>query-hlrv2</command>…<version>4456</version>` | `tdkcloud::ServerResource::BuildHlr` builds the identical string, same field order, literal `4456` | byte-exact ✅ |
| LOGIN payload | `adminapp&&<pw>\0<oem>\0clientid=<id>\0` | `&&%s` and `clientid=` literals in `liblive_player.so` | ✅ |
| OPENDOOR payload | `[door,00,lock,01,12×00,sha256]` (`build_open_payload`) | `DeviceOrderHelper.SendUnlockData(ch,i4,true,pwd)` = `[ch,00,i4,1,12×00,str]` | byte-exact ✅ |
| Transparent opcode | `0xFE`, `msg13=4` | transparent RPC inner cmd `4 = VIDEO_CHANNEL_ORDER_UNLOCK` | ✅ |
| PIN hashing | `sha256(pin)` hex, empty-PIN handled | `QvEncrypt.EncodeDevicePassword = (len<64)? sha256(str) : str` | ✅ |
| MQTT credential KDF (`qv_kdf.py`) | AES-256-CBC, IV `b"0"*16`, dynamic box/sbox + key-schedule | symbols present: `MstEncrypt`, `AESSecret`, `GenerateKey`, `GenerateSeedKeyAndBox`, `GenerateExpansionKey`, `GenerateSourceData`; 4096-byte tables; `box[0]=B[0xF1]` (= `data2[data1[1]]`); IV matches | ✅ grounded |
| Transport stack | KCP/UDP, MQTT `p2pconnect`, natcheck, mTLS | `ikcp`, `MqttConnect`, `NatCheck*`, BoringSSL all present | ✅ |

The device command set is a video **door intercom** (`VIDEO_CHANNEL_ORDER_*`:
HANG_UP, INDOOR_ANSWER, UNLOCK, HOLD_OPEN, ON_OTHER_DOORBELL_CALL,
SET_INDOOR_CALL_NAME, …).

## Divergences found

### 1. NAT-check server was hardcoded (fixed)

`NATCHECK_SERVER = ("8.211.5.8", 8300)` was a captured constant. The real SDK
resolves the NAT-check address **dynamically** from the discovery response
(server-type `natcheck`; in the binary `MqttConnect` resolves `NatCheckUrl` from
the mst server). The plugin already *requested* `natcheck` in its server-type
list but ignored the returned address.

**Confirmed dynamic — the hardcode would break.** Two captured `mst/query`
responses from this account carry **different** natcheck servers:

| capture | `natcheck` `<url>` |
|---|---|
| `bootstrap_full.txt` | `udp://8.211.5.8:8300` |
| `mqtt_live.txt` (18 Aug 2026) | `udp://8.209.66.224:8300` |

The vendor rotated the NAT-check server (`8.211.5.8` → `8.209.66.224`). Every
`.pcap` still shows `8.211.5.8` only because all of them predate the rotation;
a client hardcoded to `8.211.5.8` fails once the account is steered to the new
one. The native `createP2PClient` call (from `native_trace.txt`) confirms the
address is discovered, not fixed — it is passed in as the `ustTestAddress`
argument (`… | udp://8.211.5.8:8300 | …`).

**Fixed:** `_natcheck_server()` takes the address from the (already cached)
discovery answer — format `udp://host:port`, parsed and verified against both
real values above — and falls back to the constant on a cold start or any parse
failure, so critical-path timing and cold-start behaviour are unchanged.

### 2. Minor notes (no action required)

- `<regionid>0</regionid>` in the discovery envelope vs. `IP_REGION_ID="1"` used
  for the REST login — works live; worth a one-line comment on why 0 here.
- The requested server-type list is a subset (no `p2pust`/`p2pdev`) — fine
  because the plugin runs its own P2P/relay, but it diverges from the app's
  full bitmask.
- `door`/`locknumber` byte positions: the app calls
  `SendUnlockData(i4, i3, …)` from `unlock(i3, i4, …)`. For the default EVO-2
  station (`door=1`, `lock=1`) the mapping is irrelevant; re-check on a real
  multi-door station.
