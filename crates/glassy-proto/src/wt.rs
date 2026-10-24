//! WebTransport request path codec (spec §6.2): `/glassy?t=<base64url server ticket>`.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::Error;
use crate::server_ticket::{SERVER_TICKET_BROWSER_MAX, SERVER_TICKET_MIN};

pub const WT_PATH_PREFIX: &str = "/glassy?t=";

/// `ceil(394 * 4 / 3)` base64url characters for the largest browser ticket.
pub const WT_TICKET_B64_MAX: usize = 526;
/// Longest accepted path: the prefix plus [`WT_TICKET_B64_MAX`] characters.
pub const WT_PATH_MAX: usize = WT_PATH_PREFIX.len() + WT_TICKET_B64_MAX;

fn check_ticket_len(len: usize) -> Result<(), Error> {
    if (SERVER_TICKET_MIN..=SERVER_TICKET_BROWSER_MAX).contains(&len) {
        Ok(())
    } else {
        Err(Error::BadLength)
    }
}

/// Builds the request path for `server_ticket`.
pub fn wt_path(server_ticket: &[u8]) -> Result<String, Error> {
    check_ticket_len(server_ticket.len())?;
    Ok(format!(
        "{WT_PATH_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(server_ticket)
    ))
}

/// Extracts and validates the server ticket from a request path.
pub fn parse_wt_path(path: &str) -> Result<Vec<u8>, Error> {
    if path.len() > WT_PATH_MAX {
        return Err(Error::TooLarge);
    }
    let b64 = path
        .strip_prefix(WT_PATH_PREFIX)
        .filter(|rest| !rest.contains(['&', '#']))
        .ok_or(Error::BadEncoding)?;
    let ticket = URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(|_| Error::BadEncoding)?;
    check_ticket_len(ticket.len())?;
    Ok(ticket)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wt_path_max_len_536() {
        let p = wt_path(&[7; 394]).unwrap();
        assert_eq!(p.len(), 536);
        assert_eq!(WT_PATH_MAX, 536);
        assert_eq!(parse_wt_path(&p), Ok(vec![7; 394]));
        assert_eq!(wt_path(&[7; 395]), Err(Error::BadLength));
        assert_eq!(wt_path(&[7; 74]), Err(Error::BadLength));
    }

    #[test]
    fn parse_check_order() {
        let long = format!("{WT_PATH_PREFIX}{}", "A".repeat(527));
        assert_eq!(parse_wt_path(&long), Err(Error::TooLarge));
        assert_eq!(parse_wt_path("/glassy?t"), Err(Error::BadEncoding));
        assert_eq!(parse_wt_path("/glassy?t=AA&x=1"), Err(Error::BadEncoding));
        assert_eq!(parse_wt_path("/glassy?t=AA#f"), Err(Error::BadEncoding));
        assert_eq!(parse_wt_path("/glassy?t=AA=="), Err(Error::BadEncoding));
        assert_eq!(parse_wt_path("/glassy?t=AAAA"), Err(Error::BadLength));
    }
}
