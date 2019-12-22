extern crate p8n_types as ty;
extern crate p8n_amd64 as amd64;

use std::path::Path;

use crate::ty::Architecture;
use crate::amd64::Mode;

#[test]
fn all_bins() {
    let c = ty::Image::load(Path::new("/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/Current/Google Chrome Framework")).unwrap();

    eprintln!("{:?}", c.regions);
    for r in c.regions.iter() {
        if r.name() == "__TEXT" {
            let mut matches = vec![];

            let _ = amd64::Amd64::decode(
                &r, 0x2d00, &Mode::Long, &mut matches);
        }
    }
}
