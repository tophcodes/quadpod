//! Web Access Control: resolve the applicable ACL (`prp`), decide from it
//! (`pdp`), and enforce that decision at the HTTP edge (`guard`).

pub mod pdp;
pub mod prp;
pub mod provision;

/// A single WAC access mode, as requested by a handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Read,
    Write,
    Append,
    Control,
}

/// The set of modes an agent holds on one resource.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AccessModes {
    pub read: bool,
    pub write: bool,
    pub append: bool,
    pub control: bool,
}

impl AccessModes {
    /// `Write` subsumes `Append` (a writer may also append); no other mode
    /// implies another. In particular `Control` grants only ACL access, and
    /// neither `Read` nor `Write` implies it.
    pub fn allows(self, mode: Mode) -> bool {
        match mode {
            Mode::Read => self.read,
            Mode::Write => self.write,
            Mode::Append => self.append || self.write,
            Mode::Control => self.control,
        }
    }
}
