// Documentation taken from:
// https://www.downloads.netgear.com/files/GDC/GS105EV2/WebManagedSwitches_UM_EN.pdf
use std::collections::HashMap;

// --- QUALITY OF SERVICE ---
/// Quality of Service attribute
const ATTR_QOS: &str = "qos";

/// Port-based QoS mode: Lets you manually set the priority level for individual ports.
/// For example, you can select Low Priority (P0). Data with a higher priority is
/// transmitted faster. If packets arrive at several ports at the same time, the ports
/// configured as higher priority transmit their packets first
#[derive(Debug)]
pub enum QoSPortPriority {
    /// Low priority (0x01)
    Low,
    /// Normal priority (0x03)
    Normal,
    /// Medium priority (0x05)
    Medium,
    /// High priority (0x07)
    High,
    /// Not set
    None,
}

impl TryFrom<u8> for QoSPortPriority {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(QoSPortPriority::Low),
            0x03 => Ok(QoSPortPriority::Normal),
            0x05 => Ok(QoSPortPriority::Medium),
            0x07 => Ok(QoSPortPriority::High),
            _ => Ok(QoSPortPriority::None),
        }
    }
}

impl QoSPortPriority {
    fn to_number(&self) -> u8 {
        match self {
            QoSPortPriority::Low => 0x01,
            QoSPortPriority::Normal => 0x03,
            QoSPortPriority::Medium => 0x05,
            QoSPortPriority::High => 0x07,
            QoSPortPriority::None => 0x00,
        }
    }
}

/// Quality of Service configuration
#[derive(Debug)]
pub enum QoSConfig {
    /// Automatically applies pass-through prioritization for
    /// traffic (for example, voice or video) that is based on tagged packets. This QoS mode
    /// applies to all ports but only for traffic for connected devices that support 802.1p
    /// tagging or Differentiated Services Code Point (DSCP) tagging. For connected devices
    /// that do not support 802.1p or DSCP tagging, traffic is not prioritized.
    ByDSCP,
    /// manually set the priority level for individual ports. Note that the value here
    /// is a vector as the config file may be applied to other switch models.
    ByPort(Vec<QoSPortPriority>),
}

// -- IGMP SNOOPING ---
// const ATTR_IGMPSNOOP: &str = "igmpsnoop";
// struct IGMPSnoop {
//     enabled: bool,
//     vlanid: u16, <-- not verified
//     validate_header: bool,
// }

// -- BROADCAST FILTERING ---
const ATTR_STORM: &str = "storm";

/// Configure blocking of massive transmission of broadcast packets forwarded to
/// every port on the same VLAN
#[derive(Debug)]
pub enum BroadcastFiltering {
    Disabled,
    // transmission rate as bits per second for each port
    Enabled(Vec<u32>),
}

// --- RATE LIMITING ---
const ATTR_RATE: &str = "rate";

/// tuple of (egress_rate, ingress_rate)
type RateControl = (u32, u32);

#[derive(Debug)]
pub enum NetgearConfigEntry<'a> {
    /// default entry
    Unknown(&'a [u8]),

    /// Configuration for Plus Utility and Web Management
    PlusUtility(bool),

    /// Configuration for Plus Utility via TFTP
    PlusUtilityTFTP(bool),

    /// Configuration for Loop Detection
    LoopDetect(bool),

    /// Configuration for Multicast blocking
    Multicast(bool),

    /// Configuration for device Registration
    Registration(bool),

    /// Configuration for Quality of Service
    QoS(QoSConfig),

    /// Rate limiting
    Rate(Vec<RateControl>),

    /// Broadcast filtering
    Storm(BroadcastFiltering),
}

const ATTR_PLUS_UTILITY: &str = "plusutility";
const ATTR_PLUS_UTILITY_TFTP: &str = "plusutilitytftp";
const ATTR_LOOPDETECT: &str = "loopdetect";
const ATTR_MCAST: &str = "mcast";
const ATTR_REGISTRATION: &str = "registration";

// PARSING
impl NetgearConfigEntry<'_> {
    /// Returns a NetgearConfigEntry based on the given attribute identifier and
    /// configuration bytes.
    ///
    /// This method assumes the correct amount of bytes has been provided.
    pub fn from_name_and_bytes<'a>(name: &str, bytes: &'a [u8]) -> NetgearConfigEntry<'a> {
        match name {
            ATTR_PLUS_UTILITY => NetgearConfigEntry::PlusUtility(bytes[0] == 1),
            ATTR_PLUS_UTILITY_TFTP => NetgearConfigEntry::PlusUtilityTFTP(bytes[0] == 1),
            ATTR_LOOPDETECT => NetgearConfigEntry::LoopDetect(bytes[0] == 1),
            ATTR_MCAST => NetgearConfigEntry::Multicast(bytes[0] == 1),
            ATTR_REGISTRATION => NetgearConfigEntry::Registration(bytes[0] == 1),
            ATTR_RATE => NetgearConfigEntry::Rate(
                (0..8)
                    .map(|b| {
                        (
                            u32::from_be_bytes(bytes[b * 4..b * 4 + 4].try_into().unwrap()),
                            u32::from_be_bytes(bytes[b * 4 + 8..b * 4 + 12].try_into().unwrap()),
                        )
                    })
                    .collect::<Vec<RateControl>>(),
            ),
            ATTR_STORM => {
                if bytes[0] == 0xFF {
                    NetgearConfigEntry::Storm(BroadcastFiltering::Disabled)
                } else {
                    NetgearConfigEntry::Storm(BroadcastFiltering::Enabled(
                        (0..8)
                            .map(|b| {
                                u32::from_be_bytes(
                                    bytes[4 + b * 4..4 + b * 4 + 4].try_into().unwrap(),
                                )
                            })
                            .collect::<Vec<u32>>(),
                    ))
                }
            }
            ATTR_QOS => {
                if bytes[1..].iter().all(|&b| b == 0) {
                    NetgearConfigEntry::QoS(QoSConfig::ByDSCP)
                } else {
                    NetgearConfigEntry::QoS(QoSConfig::ByPort(
                        bytes[1..9]
                            .iter()
                            .map(|&b| QoSPortPriority::try_from(b).unwrap())
                            .collect::<Vec<QoSPortPriority>>(),
                    ))
                }
            }
            _ => NetgearConfigEntry::Unknown(bytes),
        }
    }
}

// BUILDING
impl NetgearConfigEntry<'_> {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            NetgearConfigEntry::Unknown(bytes) => bytes.to_vec(),
            NetgearConfigEntry::PlusUtility(enabled)
            | NetgearConfigEntry::PlusUtilityTFTP(enabled)
            | NetgearConfigEntry::LoopDetect(enabled)
            | NetgearConfigEntry::Multicast(enabled)
            | NetgearConfigEntry::Registration(enabled) => vec![if *enabled { 1 } else { 0 }],
            NetgearConfigEntry::QoS(config) => match config {
                QoSConfig::ByDSCP => [0x00].repeat(9), // only for 8port switches
                QoSConfig::ByPort(priorities) => {
                    let mut data = Vec::new();
                    data.push(0x01);
                    data.extend(priorities.iter().map(|p| p.to_number()));
                    data
                }
            },
            NetgearConfigEntry::Rate(rates) => {
                let mut data = Vec::new();
                for (egress, ingress) in rates {
                    data.extend(egress.to_be_bytes());
                    data.extend(ingress.to_be_bytes());
                }
                data
            }
            NetgearConfigEntry::Storm(config) => match config {
                BroadcastFiltering::Disabled => {
                    let mut data = [0x00].repeat(36);
                    data[0] = 0xFF;
                    data
                }
                BroadcastFiltering::Enabled(rates) => {
                    let mut data = Vec::new();
                    rates.iter().for_each(|r| data.extend(r.to_be_bytes()));
                    data
                }
            },
        }
    }
}

/// Common errors
#[derive(Debug)]
pub enum Error {
    /// Invalid magic bytes
    InvalidMagic,
    /// Invalid length value that does not conform to the file length
    InvalidLength(String),
    /// Invalid checksum value
    InvalidChecksum(String),
    /// Entry is missing a null terminator
    InvalidEntry(String),
    /// Invalid configuration file
    InvalidConfig(String),
}

// -- CHECKSUM --
/// Calculates the checksum for the given data.
///
/// The algorithm used here is straightforward and not optimized. It is
/// a simple folded HashSum of the entry data within a configuration file.
pub fn calc_checksum(data: &[u8]) -> u16 {
    let mut sum: u64 = 0u64;
    let mut progress: u16 = 0u16;
    data.iter().for_each(|&b| {
        sum += (b as u64) << (progress * 8);
        progress += 1;
        progress %= 2
    });

    let mut folded_sum: u64 = sum;
    while folded_sum > 65535 {
        let mut partial_sum: u64 = 0;
        (0..8)
            .step_by(2)
            .for_each(|i| partial_sum += (folded_sum & (0xffff << (i * 8))) >> (i * 8));
        folded_sum = partial_sum;
    }
    (folded_sum as u16) >> 8 | (folded_sum as u16 & 0xFF) << 8
}

// -- NETGEAR CONFIGURATION --
const FILE_MAGIC: &str = "FMv2";

/// Netgear configuration
///
/// This struct is used to represent a Netgear configuration file. It contains a
/// checksum and a map of entries where the key is the attribute name.
#[derive(Debug)]
pub struct NetgearConfig<'a> {
    /// file checksum
    pub chksum: u16,
    /// configuration entries
    entries: HashMap<String, NetgearConfigEntry<'a>>,
}

// METHODS
impl<'a> NetgearConfig<'a> {
    /// Returns the entry with the given name
    pub fn get_entry(&self, name: &str) -> Option<&NetgearConfigEntry<'_>> {
        self.entries.get(name)
    }

    /// Returns the entry with the given name
    pub fn get_entry_mut(&mut self, name: &String) -> Option<&mut NetgearConfigEntry<'a>> {
        self.entries.get_mut(name)
    }

    /// Returns the number of entries in the configuration
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if the configuration contains an entry with the given name
    pub fn contains_entry(&self, name: &String) -> bool {
        self.entries.contains_key(name)
    }

    /// inserts a new entry into the configuration
    pub fn put_entry(&mut self, name: &str, entry: NetgearConfigEntry<'a>) {
        self.entries.insert(name.to_string(), entry);
    }

    /// removes an entry from the configuration
    pub fn remove_entry(&mut self, name: &String) {
        self.entries.remove(name);
    }

    /// Returns a list of all entry names
    pub fn entry_names(&self) -> Vec<String> {
        self.entries.keys().cloned().collect()
    }

    /// Checks if the given data is a valid Netgear configuration file
    pub fn is_valid(blob: &[u8]) -> bool {
        if blob.len() < 4 {
            return false;
        }
        let magic = String::from_utf8_lossy(&blob[0..4]);
        magic == FILE_MAGIC
    }

    /// Creates a new empty configuration
    pub fn new() -> NetgearConfig<'a> {
        NetgearConfig {
            chksum: 0,
            entries: HashMap::new(),
        }
    }
}



// PARSING
impl NetgearConfig<'_> {
    /// Parses and verifies a Netgear configuration file
    pub fn parse(blob: &[u8]) -> Result<NetgearConfig<'_>, Error> {
        if blob.len() < 8 {
            return Err(Error::InvalidConfig(format!(
                "The file is only {} bytes long (minimum of 8 bytes)",
                blob.len()
            )));
        }
        if !NetgearConfig::is_valid(blob) {
            return Err(Error::InvalidMagic);
        }

        let config_length = u16::from_be_bytes(blob[4..6].try_into().unwrap());
        let mut config = NetgearConfig {
            chksum: u16::from_be_bytes(blob[6..8].try_into().unwrap()),
            entries: HashMap::new(),
        };
        if config_length != (blob.len() as u16 - 8) {
            return Err(Error::InvalidLength(format!(
                "The length is {} but the file is {} bytes long",
                config_length,
                blob.len() - 8
            )));
        }

        let length = blob.len() as u16;
        let mut index: u16 = 8;
        let chksum = calc_checksum(&blob[8..]);
        if chksum != config.chksum {
            return Err(Error::InvalidChecksum(format!(
                "The checksum is {:#04x} but should be {:#04x}",
                chksum, config.chksum
            )));
        }

        while index < length {
            // REVISIT: The first two bytes are always 0x01
            index += 2;
            if index >= length {
                return Err(Error::InvalidLength(format!(
                    "The start of the entry {} is outside of the file's bounds ({})",
                    config.entries.len(),
                    length
                )));
            }
            // guranteed to succeed due to previous index check
            let entry_size: u16 = u16::from_be_bytes(
                blob[(index as usize)..(index as usize) + 2]
                    .try_into()
                    .unwrap(),
            );
            index += 2;
            if index + entry_size > length {
                return Err(Error::InvalidLength(format!(
                    "The end of the entry {} (pos={}, len={:04x}) is outside of the file's bounds ({})",
                    config.entries.len(),
                    index + entry_size,
                    entry_size,
                    length
                )));
            }

            let entry_slice = &blob[(index as usize)..(index as usize + entry_size as usize)];
            let entry_data_start: u16 = match entry_slice.iter().position(|&x| x == 0u8) {
                Some(x) => x as u16,
                None => {
                    return Err(Error::InvalidEntry(format!(
                        "The entry {} is missing a null terminator",
                        config.entries.len()
                    )))
                }
            };

            let name =
                String::from_utf8_lossy(&entry_slice[0..entry_data_start as usize]).to_string();
            let entry_data = &entry_slice[entry_data_start as usize + 1..];
            let entry = NetgearConfigEntry::from_name_and_bytes(&name, entry_data);
            config.entries.insert(name, entry);

            index += entry_size;
        }

        Ok(config)
    }
}

/// BUILDING
impl NetgearConfig<'_> {
    /// Builds a Netgear configuration file (ordering is not guaranteed)
    pub fn build(&self) -> Vec<u8> {
        let mut config_data: Vec<u8> = Vec::new();
        for (key, value) in &self.entries {
            config_data.extend_from_slice(&[0x00u8, 0x01u8]); // always 1

            let mut entry_data = value.to_bytes();
            config_data.extend((key.len() as u16 + entry_data.len() as u16 + 1).to_be_bytes());
            config_data.extend(key.as_bytes());
            config_data.push(0x00);
            config_data.append(&mut entry_data);
        }

        let chksum = calc_checksum(&config_data);
        let mut data = Vec::new();
        data.extend(FILE_MAGIC.as_bytes());
        data.extend(&(config_data.len() as u16).to_be_bytes());
        data.extend(&chksum.to_be_bytes());
        data.append(&mut config_data);
        data
    }
}
