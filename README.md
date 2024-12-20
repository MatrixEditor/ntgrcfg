# Netgear Switch Configuration Parser

Rust crate to parse and build Netgear Switch binary configuration files (`.cfg`).

## Usage

```rust
use std::fs;
use ntgrcfg; // import

fn main() -> Result<(), ntgrcfg::Error> {
    // 1. read the file
    let contents = fs::read("/path/to/file.cfg").unwrap();

    // 2. parse the file
    let config = ntgrcfg::NetgearConfig::parse(&contents)?;

    // usage: get specific entry
    if let Some(NetgearConfigEntry::PlusUtility(enabled))
        = config.get_entry("plusutility") {
        // ...
    }

    // add entry
    config.put_entry("plusutility", NetgearConfigEntry::PlusUtility(false));

    // 3. build the file
    let updated_contents = config.build()?;
    fs::write("/path/to/file.cfg", updated_contents).unwrap();
    Ok(())
}
```

## Implementation Status

- [ ] pvid
- [ ] mirror
- [x] qos
- [ ] misc
- [ ] vlan
- [x] mcast
- [x] plusutilitytftp
- [x] registration
- [ ] igmpsnoop
- [x] rate
- [x] storm
- [x] loopdetect
- [ ] ethconfig
- [ ] password
- [ ] name
- [x] plusutility

## License

Distributed under the GNU General Public License (V3). See [License](LICENSE) for more information.